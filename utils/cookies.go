package utils

import (
	"net/http"
	"time"
)

// SetCookies sets a cookie on the given http.ResponseWriter with the given name and value.
// The cookie will expire in one hour.
// If only is true, the cookie will be set to HttpOnly, meaning it will not be accessible to JavaScript.
func SetCookies(w http.ResponseWriter, sessionID string, name string, only bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    sessionID,
		Expires:  time.Now().Add(1 * time.Hour),
		HttpOnly: only,
	})
}

// DeleteAllCookies deletes all cookies from the request.
// It sets the cookies' MaxAge to -1 and their expiration date to the Unix epoch (January 1, 1970, 00:00:00 UTC),
// effectively deleting the cookies from the browser.
func DeleteAllCookies(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range r.Cookies() {
		http.SetCookie(w, &http.Cookie{
			Name:     cookie.Name,
			Value:    "",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
		})
	}
}
