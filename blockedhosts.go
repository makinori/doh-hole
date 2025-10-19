package main

import (
	"io"
	"log"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var (
	blockedHostRegexp = regexp.MustCompile(`^0\.0\.0\.0\s(.+?)(?:$|[\s#])`)

	// we're replacing map when updating so no need to use sync.Map
	blockedHosts      map[string]struct{}
	blockedHostsMutex = sync.RWMutex{}

	blockedHostsExpireTime time.Time

	ensuringBlockList atomic.Bool
)

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

func ensureBlockList() bool {
	if time.Now().Before(blockedHostsExpireTime) {
		return true
	}

	if ensuringBlockList.Load() {
		return false
	}

	ensuringBlockList.Store(true)
	defer ensuringBlockList.Store(false)

	// immediate update expire
	blockedHostsExpireTime = time.Now().Add(BLOCKED_HOSTS_EXPIRE)

	// try forever
	return retryNoFailNoOutput(
		-1, time.Second*2, rawUpdateBlockedHosts,
		"getting blocked hosts",
	)
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
