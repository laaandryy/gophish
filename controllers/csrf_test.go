package controllers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
)

// loginWithHeaders submits the login form with the provided extra headers and
// returns the response status code. Redirects are not followed.
func loginWithHeaders(t *testing.T, ctx *testContext, headers map[string]string) int {
	resp, err := http.Get(fmt.Sprintf("%s/login", ctx.adminServer.URL))
	if err != nil {
		t.Fatalf("error requesting the /login endpoint: %v", err)
	}
	doc, err := goquery.NewDocumentFromResponse(resp)
	if err != nil {
		t.Fatalf("error parsing /login response body: %v", err)
	}
	token, ok := doc.Find("input[name='csrf_token']").First().Attr("value")
	if !ok {
		t.Fatal("unable to find csrf_token value in login response")
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/login", ctx.adminServer.URL), strings.NewReader(url.Values{
		"username":   {"admin"},
		"password":   {"gophish"},
		"csrf_token": {token},
	}.Encode()))
	if err != nil {
		t.Fatalf("error creating new /login request: %v", err)
	}
	req.Header.Set("Cookie", resp.Header.Get("Set-Cookie"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("error requesting the /login endpoint: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestCSRFOriginChecks ensures that logins submitted from the admin server's
// own origin succeed, over plain HTTP or behind a TLS terminating proxy, while
// cross-origin submissions are rejected.
func TestCSRFOriginChecks(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)
	host := strings.TrimPrefix(ctx.adminServer.URL, "http://")
	tests := []struct {
		name     string
		headers  map[string]string
		expected int
	}{
		{"no origin over HTTP", nil, http.StatusFound},
		{"same origin over HTTP", map[string]string{"Origin": "http://" + host}, http.StatusFound},
		{"cross origin", map[string]string{"Origin": "http://evil.example.com"}, http.StatusForbidden},
		{"same origin behind a TLS proxy", map[string]string{
			"Origin":            "https://" + host,
			"X-Forwarded-Proto": "https",
		}, http.StatusFound},
		{"cross origin behind a TLS proxy", map[string]string{
			"Origin":            "https://evil.example.com",
			"X-Forwarded-Proto": "https",
		}, http.StatusForbidden},
		{"HTTP referer behind a TLS proxy", map[string]string{
			"Referer":           "http://" + host + "/login",
			"X-Forwarded-Proto": "https",
		}, http.StatusForbidden},
	}
	for _, tc := range tests {
		got := loginWithHeaders(t, ctx, tc.headers)
		if got != tc.expected {
			t.Fatalf("%s: expected status %d got %d", tc.name, tc.expected, got)
		}
	}
}
