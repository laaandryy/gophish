package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLimitRequestSize(t *testing.T) {
	var readErr error
	h := LimitRequestSize(0, 10, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	}))

	// A body within the limit is read normally
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("0123456789"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || readErr != nil {
		t.Fatalf("expected the request to succeed, got status %d and error %v", rec.Code, readErr)
	}

	// A Content-Length over the limit is rejected before the handler runs
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("0123456789A"))
	rec = httptest.NewRecorder()
	readErr = nil
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status %d got %d", http.StatusRequestEntityTooLarge, rec.Code)
	}

	// A streamed body (unknown length) fails once it exceeds the limit
	req = httptest.NewRequest(http.MethodPost, "/", io.NopCloser(strings.NewReader("0123456789A")))
	req.ContentLength = -1
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if readErr == nil {
		t.Fatal("expected reading a body over the limit to fail")
	}
}
