package main

import (
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	testDNSSillyIndex = 0
	testDNSSillyMutex = sync.Mutex{}
	testDNSSillyLines = []string{
		"kiriko kamori my wife",
		"sameko saba best fish",
		"gawr gura best shork",
	}
)

func handleTestDNS(req *dns.Msg) *dns.Msg {
	if len(req.Question) == 0 {
		return nil
	}

	if req.Question[0].Name != "doh.hole." {
		return nil
	}

	hostname, _ := os.Hostname()

	testDNSSillyMutex.Lock()
	testDNSSillyIndex = (testDNSSillyIndex + 1) % len(testDNSSillyLines)
	testDNSSilly := testDNSSillyLines[testDNSSillyIndex]
	testDNSSillyMutex.Unlock()

	lines := []string{
		testDNSSilly,
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
