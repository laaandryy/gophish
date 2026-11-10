package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/csrf"
)

// csrfTestServer returns a server protected like the admin server, with
// admin.example.com trusted over the request's own scheme and
// https://secure.example.com trusted over HTTPS only.
func csrfTestServer(t *testing.T) *httptest.Server {
	trusted, err := CSRFTrustedOrigins([]string{"admin.example.com", "https://secure.example.com"})
	if err != nil {
		t.Fatalf("error parsing trusted origins: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(csrf.Token(r)))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	protect := csrf.Protect([]byte(strings.Repeat("k", 32)),
		csrf.FieldName("csrf_token"), csrf.Secure(false))
	return httptest.NewServer(Use(protect(mux).ServeHTTP, trusted, CSRFPlaintextHTTP))
}

func csrfPost(t *testing.T, srv *httptest.Server, headers map[string]string) int {
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("error requesting token: %v", err)
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("error reading token: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(url.Values{"csrf_token": {buf.String()}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", resp.Header.Get("Set-Cookie"))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("error posting form: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestCSRFTrustedOrigins(t *testing.T) {
	srv := csrfTestServer(t)
	defer srv.Close()
	tests := []struct {
		name     string
		headers  map[string]string
		expected int
	}{
		{"trusted host over HTTP", map[string]string{"Origin": "http://admin.example.com"}, http.StatusNoContent},
		{"trusted host over HTTPS", map[string]string{"Origin": "https://admin.example.com", "X-Forwarded-Proto": "https"}, http.StatusNoContent},
		{"trusted host with another scheme", map[string]string{"Origin": "http://admin.example.com", "X-Forwarded-Proto": "https"}, http.StatusForbidden},
		{"trusted HTTPS origin", map[string]string{"Origin": "https://secure.example.com", "X-Forwarded-Proto": "https"}, http.StatusNoContent},
		{"trusted HTTPS origin over HTTP", map[string]string{"Origin": "http://secure.example.com"}, http.StatusForbidden},
		{"untrusted origin", map[string]string{"Origin": "http://evil.example.com"}, http.StatusForbidden},
		{"trusted referer over HTTPS", map[string]string{"Referer": "https://admin.example.com/login", "X-Forwarded-Proto": "https"}, http.StatusNoContent},
		{"trusted host HTTP referer over HTTPS", map[string]string{"Referer": "http://admin.example.com/login", "X-Forwarded-Proto": "https"}, http.StatusForbidden},
		{"untrusted referer over HTTPS", map[string]string{"Referer": "https://evil.example.com/login", "X-Forwarded-Proto": "https"}, http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := csrfPost(t, srv, tc.headers); got != tc.expected {
				t.Fatalf("unexpected status code. expected %d got %d", tc.expected, got)
			}
		})
	}
}

func TestCSRFTrustedOriginsInvalid(t *testing.T) {
	if _, err := CSRFTrustedOrigins([]string{"ftp://admin.example.com"}); err == nil {
		t.Fatal("expected an error for an invalid trusted origin")
	}
}
