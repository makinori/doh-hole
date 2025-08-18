package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/fxamacker/cbor/v2"
	"github.com/miekg/dns"
	"github.com/robfig/cron/v3"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

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

	ADDR = envOrDefault("ADDR", "127.0.0.1")
	PORT = envOrDefault("PORT", "53")

	LISTEN_ADDR = ADDR + ":" + PORT

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

	// httpClient = http.Client{
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
	// }

	// we're replacing map when updating so no need to use sync.Map
	blockedHosts      map[string]struct{}
	blockedHostsMutex = sync.RWMutex{}

	blockedHostsExpire time.Time

	blockedHostRegexp = regexp.MustCompile(`^0\.0\.0\.0\s(.+?)(?:$|[\s#])`)

	dnsCache sync.Map
)

func init() {
	// reap dns cache every 5 minutes
	// map could be huge although this is threaded
	c := cron.New()
	c.AddFunc("0/5 * * * *", func() {
		dnsCache.Range(func(key, cacheEntryAny any) bool {
			if DEBUG {
				log.Println("reaping dns cache...")
			}
			cacheEntry, ok := cacheEntryAny.(CacheEntry)
			if !ok {
				return true
			}
			if cacheEntry.Expires.Before(time.Now()) {
				log.Println("deleting", key)
				dnsCache.Delete(key)
			}
			return true
		})
	})
	c.Start()
}

func rawUpdateBlockedHosts() error {
	// TODO: will use bootstrap dns. shouldnt. idk maybe im too schizo

	res, err := http.DefaultClient.Get(BLOCKED_HOSTS_URL)
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
		"got %d blocked hosts. expires in %s", len(newBlockedHosts),
		formatDuration(BLOCKED_HOSTS_EXPIRE),
	))

	return nil
}

var blockListMutex atomic.Bool

func ensureBlockList() bool {
	if time.Now().Before(blockedHostsExpire) {
		return true
	}

	if blockListMutex.Load() {
		return false
	}

	blockListMutex.Store(true)
	defer blockListMutex.Store(false)

	// immediate update expire
	blockedHostsExpire = time.Now().Add(BLOCKED_HOSTS_EXPIRE)

	// try forever
	return retryNoFailNoOutput(
		-1, time.Second*2, rawUpdateBlockedHosts,
		"getting blocked hosts",
	)
}

func handleTestDNS(req *dns.Msg) *dns.Msg {
	if len(req.Question) == 0 {
		return nil
	}

	if req.Question[0].Name != "doh.hole." {
		return nil
	}

	hostname, _ := os.Hostname()

	lines := []string{
		// "gawr gura best shork",
		"sameko saba best fish",
		"hostname: " + hostname,
		"time: " + time.Now().Format("15:04:05"),
		runtime.Version(),
	}

	records := make([]dns.RR, len(lines))

	for i, line := range lines {
		records[i] = &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   "doh.hole.",
				Ttl:    0,
				Class:  dns.ClassINET,
				Rrtype: dns.TypeTXT,
			},
			Txt: []string{line},
		}
	}

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionAvailable: true,
		},
		Compress: true,
		Answer:   records,
	}

	m.SetReply(req) // sets dns.RcodeSuccess

	return m
}

func filterDNS(req *dns.Msg) *dns.Msg {
	// multiple questions are barely supported. answer null if any are blocked
	// note: we're blocking everything, not just A and AAAA

	blockedHostsMutex.RLock()
	defer blockedHostsMutex.RUnlock()

	var blockedQuestion *dns.Question

	for _, question := range req.Question {
		hostname := strings.TrimSuffix(question.Name, ".")

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

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionAvailable: true,
		},
		Compress: true,
	}

	m.SetReply(req) // sets dns.RcodeSuccess

	hdr := dns.RR_Header{
		Name:  blockedQuestion.Name,
		Ttl:   3600, // 1 hour
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

type CacheEntry struct {
	Expires  time.Time
	Response dns.Msg
}

func getCacheKey(req *dns.Msg) uint64 {
	cacheKeyData, err := cbor.Marshal(req.Question[0])
	if err != nil {
		log.Println("failed to get cache key data: " + err.Error())
		return 0
	}
	return xxhash.Sum64(cacheKeyData)
}

func getCached(req *dns.Msg) *dns.Msg {
	cacheKey := getCacheKey(req)
	if cacheKey == 0 {
		return nil
	}

	cacheEntryAny, ok := dnsCache.Load(cacheKey)
	if !ok {
		return nil
	}

	cacheEntry, ok := cacheEntryAny.(CacheEntry)
	if !ok {
		if DEBUG {
			log.Printf("failed to cast cache entry")
		}
		return nil
	}

	if cacheEntry.Expires.Before(time.Now()) {
		return nil
	}

	res := cacheEntry.Response // copy

	res.SetReply(req)

	return &res
}

func getFreshDoH(req *dns.Msg) (*dns.Msg, error) {
	httpReq, err := doh.NewRequest(http.MethodGet, "https://"+DOH_HOSTNAME, req)
	if err != nil {
		return nil, errors.New("failed to create doh request: " + err.Error())
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

	httpRes, err := http.DefaultClient.Do(httpReq)
	// httpReq.Method = http3.MethodGet0RTT
	// httpRes, err := http3Transport.RoundTrip(httpReq)
	if err != nil {
		return nil, errors.New("failed doh request: " + err.Error())
	}
	defer httpRes.Body.Close()

	res, err := doh.ResponseToMsg(httpRes)
	if err != nil {
		return nil, errors.New("failed to convert doh response: " + err.Error())
	}

	// cache response. dont block

	go func() {
		cacheKey := getCacheKey(req)
		if cacheKey == 0 {
			return
		}

		var lowestTTL uint32
		for i, answer := range res.Answer {
			ttl := answer.Header().Ttl
			if i == 0 {
				lowestTTL = ttl
			} else if ttl < lowestTTL {
				lowestTTL = ttl
			}
		}

		dnsCache.Store(cacheKey, CacheEntry{
			Expires:  time.Now().Add(time.Second * time.Duration(lowestTTL)),
			Response: *res, // copy response
		})
	}()

	return res, nil
}

type dnsHandler struct{}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	go ensureBlockList() // dont block

	testAnswer := handleTestDNS(req)
	if testAnswer != nil {
		w.WriteMsg(testAnswer)
		log.Println("test from: " + w.RemoteAddr().String())
		return
	}

	blockedAnswer := filterDNS(req)
	if blockedAnswer != nil {
		w.WriteMsg(blockedAnswer)
		return
	}

	cachedAnswer := getCached(req)
	if cachedAnswer != nil {
		w.WriteMsg(cachedAnswer)
		// still fetch and cache just incase it changed
		// i think the extra bandwidth is ok. cached dns sucks
		go getFreshDoH(req)
		return
	}

	res, err := getFreshDoH(req)
	if err != nil {
		if DEBUG {
			log.Println(err)
		}
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

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		log.Println("failed to cast default http transport")
		os.Exit(1)
	}

	transport.IdleConnTimeout = time.Hour // default is 1m30s

	ok = ensureBlockList()
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
