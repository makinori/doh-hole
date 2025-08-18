package main

import (
	"log"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/fxamacker/cbor/v2"
	"github.com/miekg/dns"
	"github.com/robfig/cron/v3"
)

type CacheEntry struct {
	Expires  time.Time
	Response dns.Msg
}

var (
	dnsCache sync.Map
)

func reapDNSCache() {
	dnsCache.Range(func(key, cacheEntryAny any) bool {
		if DEBUG {
			log.Println("reaping dns cache...")
		}

		cacheEntry, ok := cacheEntryAny.(CacheEntry)
		if !ok {
			return true
		}

		if cacheEntry.Expires.After(time.Now()) {
			return true
		}

		if DEBUG {
			log.Println("deleting", key)
		}

		dnsCache.Delete(key)

		return true
	})
}

func init() {
	// reap dns cache every 5 minutes
	// map could be huge although this is threaded
	// c := cron.New(cron.WithSeconds())
	c := cron.New()
	c.AddFunc("*/5 * * * *", reapDNSCache)
	c.Start()
}

func getCacheKey(req *dns.Msg) uint64 {
	if len(req.Question) == 0 {
		return 0
	}

	cacheKeyData, err := cbor.Marshal(req.Question[0])
	if err != nil {
		log.Println("failed to get cache key data: " + err.Error())
		return 0
	}

	return xxhash.Sum64(cacheKeyData)
}

func setCache(req *dns.Msg, res *dns.Msg) {
	cacheKey := getCacheKey(req)
	if cacheKey == 0 {
		return
	}

	var lowestTTL uint32
	for i, answer := range res.Answer {
		ttl := answer.Header().Ttl
		if i == 0 || ttl < lowestTTL {
			lowestTTL = ttl
		}
	}

	dnsCache.Store(cacheKey, CacheEntry{
		Expires:  time.Now().Add(time.Second * time.Duration(lowestTTL)),
		Response: *res, // copy response
	})
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
