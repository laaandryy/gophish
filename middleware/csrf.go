package middleware

import (
	"net/http"
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
