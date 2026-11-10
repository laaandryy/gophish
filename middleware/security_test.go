package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gophish/gophish/auth"
	ctx "github.com/gophish/gophish/context"
	"github.com/gophish/gophish/models"
)

// TestRequireAPIKeyLockedAccount ensures that the API key of a locked account
// is rejected.
func TestRequireAPIKeyLockedAccount(t *testing.T) {
	setupTest(t)
	role, err := models.GetRoleBySlug(models.RoleUser)
	if err != nil {
		t.Fatalf("error getting role: %v", err)
	}
	u := models.User{Username: "locked", Hash: "x", ApiKey: "lockedkey", Role: role, RoleID: role.ID, AccountLocked: true}
	if err := models.PutUser(&u); err != nil {
		t.Fatalf("error saving user: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/", nil)
	req.Header.Set("Authorization", "Bearer lockedkey")
	response := httptest.NewRecorder()
	RequireAPIKey(successHandler).ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("incorrect status code. expected %d got %d", http.StatusUnauthorized, response.Code)
	}
}

// sessionRequest returns a request carrying a session cookie for the user.
func sessionRequest(t *testing.T, u models.User) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	session, _ := Store.Get(req, "gophish")
	SetSessionUser(session, u)
	rec := httptest.NewRecorder()
	if err := session.Save(req, rec); err != nil {
		t.Fatalf("error saving session: %v", err)
	}
	next := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		next.AddCookie(c)
	}
	return next
}

// contextUser runs GetContext and returns the user it found, if any.
func contextUser(req *http.Request) interface{} {
	var user interface{}
	h := GetContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user = ctx.Get(r, "user")
	}))
	h.ServeHTTP(httptest.NewRecorder(), req)
	return user
}

// TestGetContextSessionRevocation ensures that sessions are revoked when the
// account is locked or when the password changes.
func TestGetContextSessionRevocation(t *testing.T) {
	setupTest(t)
	u, err := models.GetUser(1)
	if err != nil {
		t.Fatalf("error getting user: %v", err)
	}
	if contextUser(sessionRequest(t, u)) == nil {
		t.Fatal("expected a valid session for the user")
	}

	// Changing the password invalidates sessions created before the change
	old := sessionRequest(t, u)
	u.Hash, _ = auth.GeneratePasswordHash("a new password")
	models.PutUser(&u)
	if contextUser(old) != nil {
		t.Fatal("expected the session to be invalidated after a password change")
	}
	if contextUser(sessionRequest(t, u)) == nil {
		t.Fatal("expected a new session to be valid after a password change")
	}

	// Locking the account invalidates every session
	current := sessionRequest(t, u)
	u.AccountLocked = true
	models.PutUser(&u)
	if contextUser(current) != nil {
		t.Fatal("expected the session of a locked account to be rejected")
	}
}

// TestMoveAPIKeyToHeader ensures that an API key sent in the query string is
// moved to the Authorization header and removed from the URL.
func TestMoveAPIKeyToHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/campaigns/?api_key=secret&foo=bar", nil)
	var got *http.Request
	MoveAPIKeyToHeader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
	})).ServeHTTP(httptest.NewRecorder(), req)
	if got.Header.Get("Authorization") != "Bearer secret" {
		t.Fatalf("unexpected Authorization header: %q", got.Header.Get("Authorization"))
	}
	if got.URL.Query().Get("api_key") != "" || got.URL.Query().Get("foo") != "bar" {
		t.Fatalf("unexpected query string: %q", got.URL.RawQuery)
	}
	if got.RequestURI != "/api/campaigns/?foo=bar" {
		t.Fatalf("unexpected request URI: %q", got.RequestURI)
	}
}

// TestTrustedProxyHeaders ensures that proxy headers are only honored when
// they come from a trusted proxy.
func TestTrustedProxyHeaders(t *testing.T) {
	var remote string
	record := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote = r.RemoteAddr
	})
	tests := []struct {
		proxies  []string
		peer     string
		expected string
	}{
		// Default: loopback proxies only
		{nil, "127.0.0.1:1234", "1.2.3.4"},
		{nil, "203.0.113.10:1234", "203.0.113.10:1234"},
		// Explicit list
		{[]string{"10.0.0.0/8"}, "10.1.2.3:1234", "1.2.3.4"},
		{[]string{"10.0.0.0/8"}, "127.0.0.1:1234", "127.0.0.1:1234"},
		// Legacy behavior
		{[]string{"*"}, "203.0.113.10:1234", "1.2.3.4"},
	}
	for _, tc := range tests {
		h, err := TrustedProxyHeaders(tc.proxies, record)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = tc.peer
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		h.ServeHTTP(httptest.NewRecorder(), req)
		if remote != tc.expected {
			t.Fatalf("proxies %v, peer %s: expected remote address %s got %s", tc.proxies, tc.peer, tc.expected, remote)
		}
	}
	if _, err := TrustedProxyHeaders([]string{"not an ip"}, record); err == nil {
		t.Fatal("expected an error for an invalid trusted proxy")
	}
}
