package main

import (
	"os"
	"time"
)

const (
	// hostname can resolve different ips closest to location so need a bootstrap

	// quad9 no malware blocking and no dnssec validation
	// when we do dnssec validation ourselves, we can switch to this
	// DOH_HOSTNAME  = "dns10.quad9.net"
	// BOOTSTRAP_DNS = "9.9.9.10:53"

	// quad9 malware blocking and dnssec validation
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
)
