package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/miekg/dns"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// TODO: add caching

const (
	// hostname can resolve different ips closest to location so need a bootstrap

	DOH_HOSTNAME  = "dns.quad9.net"
	BOOTSTRAP_DNS = "9.9.9.9:53"

	// would use but response time can sometimes vary
	// DOH_HOSTNAME  = "doh.dns.sb"
	// BOOTSTRAP_DNS = "185.222.222.222:53"

	// project honeypot
	// DOH_HOSTNAME  = "cloudflare-dns.com"
	// BOOTSTRAP_DNS = "1.1.1.1:53"

	BLOCKED_HOSTS_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
	// use expire so if machine has slept, will update if expired
	BLOCKED_HOSTS_EXPIRE = time.Hour * 24
)

func envOrDefault(key string, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if exists {
		return value
	} else {
		return defaultValue
	}
}

var (
	_, DEBUG = os.LookupEnv("DEBUG")
	PORT     = envOrDefault("PORT", "53")

	LISTEN_ADDR = "127.0.0.1:" + PORT

	// https://quic-go.net/docs/http3/client

	// http3 doesnt make enough of a different to justify using it

	// quicTransport  *quic.Transport
	// http3Transport = &http3.Transport{
	// 	TLSClientConfig: &tls.Config{
	// 		ClientSessionCache: tls.NewLRUClientSessionCache(100),
	// 	},
	// 	QUICConfig: &quic.Config{
	// 		EnableDatagrams: true,
	// 		// this is set to 30 seconds by default
	// 		// changing this doesnt work though
	// 		MaxIdleTimeout: time.Minute * 5,
	// 	},
	// 	EnableDatagrams:    true,
	// 	DisableCompression: true,
	// }

	// leave max idle timeout as is. requesting a new ip is usually a good idea

	httpClient = http.Client{
		// Transport: &http.Transport{
		// 	DialContext: func(
		// 		ctx context.Context, network, addr string,
		// 	) (net.Conn, error) {
		// 		d := net.Dialer{}
		// 		if strings.Contains(addr, DOH_HOSTNAME) {
		// 			return d.DialContext(ctx, network, "")
		// 		}
		// 		return d.DialContext(ctx, network, addr)
		// 	},
		// },
	}

	blockedHosts       map[string]struct{}
	blockedHostsMutex  = sync.Mutex{}
	blockedHostsExpire time.Time

	blockedHostRegexp = regexp.MustCompile(`^0\.0\.0\.0 (.+?)$`)
)

func _updateBlockedHosts() error {
	// TODO: will use bootstrap dns. shouldnt. idk maybe im too schizo

	res, err := httpClient.Get(BLOCKED_HOSTS_URL)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	newBlockedHosts := map[string]struct{}{}

	for line := range strings.SplitSeq(string(data), "\n") {
		matches := blockedHostRegexp.FindStringSubmatch(strings.TrimSpace(line))
		if len(matches) == 0 {
			continue
		}
		newBlockedHosts[matches[1]] = struct{}{}
	}

	blockedHostsMutex.Lock()
	blockedHosts = newBlockedHosts
	blockedHostsMutex.Unlock()

	p := message.NewPrinter(language.English)
	log.Println(p.Sprintf(
		"got %d blocked hosts. expires in %s", len(blockedHosts),
		formatDuration(BLOCKED_HOSTS_EXPIRE),
	))

	return nil
}

func ensureBlockList() bool {
	if time.Now().Before(blockedHostsExpire) {
		return true
	}

	// immediate update expire
	blockedHostsExpire = time.Now().Add(BLOCKED_HOSTS_EXPIRE)

	return retryNoFailNoOutput(
		10, time.Second*2, _updateBlockedHosts,
		"getting blocked hosts",
	)
}

func filterDNS(req *dns.Msg) *dns.Msg {
	// multiple questions are barely supported. answer null if any are blocked
	// note: we're blocking everything, not just A and AAAA

	blockedHostsMutex.Lock()
	defer blockedHostsMutex.Unlock()

	var blockedQuestion *dns.Question

	for _, question := range req.Question {
		hostname := question.Name
		if strings.HasSuffix(hostname, ".") {
			hostname = hostname[:len(hostname)-1]
		}

		_, blocked := blockedHosts[hostname]
		if blocked {
			blockedQuestion = &question
			break
		}
	}

	if blockedQuestion == nil {
		return nil
	}

	// https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/dnsforward/msg.go

	m := &dns.Msg{}
	m = m.SetRcode(m, dns.RcodeSuccess)
	m.RecursionAvailable = true
	m.Compress = true
	m.Id = req.Id

	hdr := dns.RR_Header{
		Name:  blockedQuestion.Name,
		Ttl:   3600,
		Class: dns.ClassINET,
	}

	switch blockedQuestion.Qtype {
	case dns.TypeA:
		hdr.Rrtype = dns.TypeA
		m.Answer = []dns.RR{
			&dns.A{Hdr: hdr, A: netip.IPv4Unspecified().AsSlice()},
		}
	case dns.TypeAAAA:
		hdr.Rrtype = dns.TypeAAAA
		m.Answer = []dns.RR{
			&dns.AAAA{Hdr: hdr, AAAA: netip.IPv6Unspecified().AsSlice()},
		}
	default:
		// keep empty
	}

	return m
}

type dnsHandler struct{}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	go ensureBlockList() // dont block

	blockedAnswer := filterDNS(req)
	if blockedAnswer != nil {
		w.WriteMsg(blockedAnswer)
		return
	}

	httpReq, err := doh.NewRequest(http.MethodGet, "https://"+DOH_HOSTNAME, req)
	if err != nil {
		log.Println("failed to create doh request: " + err.Error())
		return
	}

	if DEBUG {
		trace := &httptrace.ClientTrace{
			DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
				log.Printf("dns done: %+v\n", dnsInfo)
			},
			GotConn: func(connInfo httptrace.GotConnInfo) {
				log.Printf("got conn: %+v\n", connInfo)
			},
		}
		httpReq = httpReq.WithContext(
			httptrace.WithClientTrace(httpReq.Context(), trace),
		)
	}

	httpRes, err := httpClient.Do(httpReq)
	// httpReq.Method = http3.MethodGet0RTT
	// httpRes, err := http3Transport.RoundTrip(httpReq)
	if err != nil {
		log.Println("failed doh request: " + err.Error())
		return
	}
	defer httpRes.Body.Close()

	res, err := doh.ResponseToMsg(httpRes)
	if err != nil {
		log.Println("failed to convert doh response: " + err.Error())
		return
	}

	w.WriteMsg(res)
}

func main() {
	log.Println("doh hostname: " + DOH_HOSTNAME)
	log.Println("bootstrap dns: " + BOOTSTRAP_DNS)

	var bootstrapDNSDialer net.Dialer

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// var address is system dns
			if DEBUG {
				log.Println("using bootstrap dns")
			}
			return bootstrapDNSDialer.DialContext(
				ctx, network, BOOTSTRAP_DNS,
			)
		},
	}

	ok := ensureBlockList()
	if !ok {
		// definitely dont want to start dns server without blocked hosts
		os.Exit(1)
	}

	handler := new(dnsHandler)
	server := &dns.Server{
		Addr:      LISTEN_ADDR,
		Net:       "udp",
		Handler:   handler,
		UDPSize:   65535,
		ReusePort: true,
	}

	log.Println("dns server listening: " + LISTEN_ADDR)
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
