package middleware

import (
	"fmt"
	"net"
	"net/http"

	"github.com/gorilla/handlers"
)

// DefaultTrustedProxies is the list of proxies whose X-Forwarded-For,
// X-Real-IP and Forwarded headers are trusted when no explicit list is
// configured. Only loopback addresses are trusted by default, which supports
// the common case of a reverse proxy (nginx, Caddy, ...) running on the same
// host.
var DefaultTrustedProxies = []string{
	"127.0.0.0/8",
	"::1/128",
}

// ParseTrustedProxies parses a list of IP addresses or CIDR ranges. The
// special value "*" trusts every client (the legacy Gophish behavior).
func ParseTrustedProxies(proxies []string) (nets []*net.IPNet, trustAll bool, err error) {
	for _, p := range proxies {
		if p == "*" {
			return nil, true, nil
		}
		if ip := net.ParseIP(p); ip != nil {
			if ip.To4() != nil {
				p += "/32"
			} else {
				p += "/128"
			}
		}
		_, parsed, err := net.ParseCIDR(p)
		if err != nil {
			return nil, false, fmt.Errorf("invalid trusted proxy %q: %v", p, err)
		}
		nets = append(nets, parsed)
	}
	return nets, false, nil
}

// TrustedProxyHeaders only honors the proxy headers handled by
// handlers.ProxyHeaders when the direct peer is one of the trusted proxies.
// Without this check, any client could spoof its IP address by sending an
// X-Forwarded-For header, bypassing IP based rate limiting and falsifying the
// IP addresses recorded for campaign events.
//
// If proxies is empty, DefaultTrustedProxies is used.
func TrustedProxyHeaders(proxies []string, next http.Handler) (http.Handler, error) {
	if len(proxies) == 0 {
		proxies = DefaultTrustedProxies
	}
	trusted, trustAll, err := ParseTrustedProxies(proxies)
	if err != nil {
		return nil, err
	}
	proxied := handlers.ProxyHeaders(next)
	if trustAll {
		return proxied, nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip != nil {
			for _, n := range trusted {
				if n.Contains(ip) {
					proxied.ServeHTTP(w, r)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	}), nil
}
