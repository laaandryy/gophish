package middleware

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	log "github.com/gophish/gophish/logger"
	"github.com/gorilla/csrf"
	"github.com/sirupsen/logrus"
)

// isTLSRequest reports whether the client reached Gophish over HTTPS, either
// directly or through a reverse proxy terminating TLS.
//
// The X-Forwarded-Proto header is read even when the proxy isn't trusted:
// it can only make the CSRF checks stricter (HTTPS requires a valid Origin or
// Referer), never looser, and browsers don't let a third party set it.
func isTLSRequest(r *http.Request) bool {
	return r.TLS != nil ||
		strings.EqualFold(r.URL.Scheme, "https") ||
		strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// CSRFPlaintextHTTP tells the CSRF middleware when a request was served over
// plain HTTP. gorilla/csrf assumes HTTPS by default and would otherwise reject
// every form submitted to an admin server running without TLS.
func CSRFPlaintextHTTP(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isTLSRequest(r) {
			r = csrf.PlaintextHTTPRequest(r)
		}
		next.ServeHTTP(w, r)
	}
}

// CSRFFailureHandler logs why a request failed the CSRF checks before
// returning a 403 error, so that a misconfigured reverse proxy is easy to
// diagnose.
var CSRFFailureHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	log.WithFields(logrus.Fields{
		"reason":  csrf.FailureReason(r),
		"origin":  r.Header.Get("Origin"),
		"referer": r.Referer(),
		"host":    r.Host,
		"path":    r.URL.Path,
	}).Warn("CSRF check failed. If Gophish runs behind a reverse proxy, make " +
		"sure it forwards the Host header or add the public host name to " +
		"admin_server.trusted_origins")
	http.Error(w, http.StatusText(http.StatusForbidden)+" - CSRF token invalid", http.StatusForbidden)
})

// trustedOrigin is an origin, other than the admin server's own, from which
// state changing requests are accepted. An empty scheme means the origin must
// use the same scheme as the request.
type trustedOrigin struct {
	scheme string
	host   string
}

// parseTrustedOrigins parses the admin_server.trusted_origins setting. Each
// entry is either a host ("admin.example.com" or "admin.example.com:3333"),
// which is trusted over the same scheme as the request, or a full origin
// ("https://admin.example.com").
func parseTrustedOrigins(origins []string) ([]trustedOrigin, error) {
	parsed := make([]trustedOrigin, 0, len(origins))
	for _, o := range origins {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		if !strings.Contains(o, "://") {
			parsed = append(parsed, trustedOrigin{host: strings.ToLower(o)})
			continue
		}
		u, err := url.Parse(o)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid trusted origin %q", o)
		}
		parsed = append(parsed, trustedOrigin{scheme: u.Scheme, host: strings.ToLower(u.Host)})
	}
	return parsed, nil
}

func isTrustedOrigin(trusted []trustedOrigin, requestScheme string, u *url.URL) bool {
	if u.Scheme != requestScheme {
		// A trusted host reached over another scheme isn't trusted: over
		// HTTPS, an HTTP origin could be injected by a network attacker.
		return false
	}
	for _, t := range trusted {
		if (t.scheme == "" || t.scheme == u.Scheme) && t.host == strings.ToLower(u.Host) {
			return true
		}
	}
	return false
}

// CSRFTrustedOrigins accepts state changing requests coming from one of the
// trusted origins. gorilla/csrf's own TrustedOrigins option only compares the
// host and ignores the scheme (GO-2025-3884), so this middleware checks both
// and, for a trusted origin, presents the request to gorilla/csrf as a same
// origin one. The CSRF token is still required.
func CSRFTrustedOrigins(origins []string) (func(http.Handler) http.HandlerFunc, error) {
	trusted, err := parseTrustedOrigins(origins)
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if len(trusted) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
				next.ServeHTTP(w, r)
				return
			}
			scheme := "http"
			if isTLSRequest(r) {
				scheme = "https"
			}
			self := scheme + "://" + r.Host
			var header http.Header
			if origin := r.Header.Get("Origin"); origin != "" {
				if u, err := url.Parse(origin); err == nil && isTrustedOrigin(trusted, scheme, u) {
					header = r.Header.Clone()
					header.Set("Origin", self)
				}
			} else if referer := r.Referer(); referer != "" {
				if u, err := url.Parse(referer); err == nil && u.Host != r.Host && isTrustedOrigin(trusted, scheme, u) {
					header = r.Header.Clone()
					header.Set("Referer", self+u.RequestURI())
				}
			}
			if header != nil {
				r = r.WithContext(r.Context())
				r.Header = header
			}
			next.ServeHTTP(w, r)
		}
	}, nil
}
