package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/miekg/dns"
)

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
