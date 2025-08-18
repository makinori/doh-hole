package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/miekg/dns"
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

	// official european
	// DOH_HOSTNAME  = "unfiltered.joindns4.eu"
	// BOOTSTRAP_DNS = "86.54.11.100:53"
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
)

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
