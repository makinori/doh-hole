package main

import (
	"errors"
	"log"
	"net/http"
	"net/http/httptrace"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/miekg/dns"
)

var (
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

//	httpClient = http.Client{
//		Transport: &http.Transport{
//			DialContext: func(
//				ctx context.Context, network, addr string,
//			) (net.Conn, error) {
//				d := net.Dialer{}
//				if strings.Contains(addr, DOH_HOSTNAME) {
//					return d.DialContext(ctx, network, "")
//				}
//				return d.DialContext(ctx, network, addr)
//			},
//		},
//	}
)

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

	go setCache(req, res) // dont block

	return res, nil
}
