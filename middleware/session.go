package middleware

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"net/http"

	"github.com/gophish/gophish/models"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// init registers the necessary models to be saved in the session later
func init() {
	gob.Register(&models.User{})
	gob.Register(&models.Flash{})
	Store.Options.HttpOnly = true
	// Lax keeps normal navigation working while preventing the session
	// cookie from being sent on cross-site subrequests and form posts.
	Store.Options.SameSite = http.SameSiteLaxMode
	// This sets the maxAge to 5 days for all cookies
	Store.MaxAge(86400 * 5)
}

// Store contains the session information for the request
var Store = sessions.NewCookieStore(
	[]byte(securecookie.GenerateRandomKey(64)), //Signing key
	[]byte(securecookie.GenerateRandomKey(32)))

// sessionUserKey and sessionPasswordKey are the session keys used to store
// the logged in user.
const (
	sessionUserKey     = "id"
	sessionPasswordKey = "pwfp"
)

// passwordFingerprint returns a short, non reversible fingerprint of the
// user's password hash. It is stored in the session so that changing a
// password invalidates every other session of that user.
func passwordFingerprint(u models.User) string {
	sum := sha256.Sum256([]byte(u.Hash))
	return hex.EncodeToString(sum[:16])
}

// SetSessionUser marks the session as belonging to the provided user. It must
// be called again after the user's password changes to keep the current
// session valid.
func SetSessionUser(session *sessions.Session, u models.User) {
	session.Values[sessionUserKey] = u.Id
	session.Values[sessionPasswordKey] = passwordFingerprint(u)
}

// isSessionValidForUser reports whether the session was created for the
// current password of the user.
func isSessionValidForUser(session *sessions.Session, u models.User) bool {
	fp, ok := session.Values[sessionPasswordKey].(string)
	return ok && fp == passwordFingerprint(u)
}
