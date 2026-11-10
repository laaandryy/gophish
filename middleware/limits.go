package middleware

import (
	"net/http"
)

const (
	// DefaultAdminMaxRequestSize is the default maximum size of a request body
	// sent to the admin server (50 MB). It leaves room for large email
	// attachments, which are sent base64 encoded in JSON.
	DefaultAdminMaxRequestSize int64 = 50 << 20

	// DefaultPhishMaxRequestSize is the default maximum size of a request body
	// sent to the phishing server (2 MB), which only receives landing page
	// form submissions.
	DefaultPhishMaxRequestSize int64 = 2 << 20
)

// LimitRequestSize rejects requests whose body is larger than maxBytes. A
// request announcing a larger Content-Length is rejected right away with a
// 413 error; otherwise reading past the limit fails, so a client can't
// exhaust the server memory by streaming a huge body.
//
// A maxBytes value of 0 or less uses defaultBytes.
func LimitRequestSize(maxBytes, defaultBytes int64, next http.Handler) http.Handler {
	if maxBytes <= 0 {
		maxBytes = defaultBytes
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxBytes {
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}
