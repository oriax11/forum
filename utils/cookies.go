package utils

import (
	"net/http"
	"time"
)

func SetCookies(w http.ResponseWriter, sessionID string, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    sessionID,
		Expires:  time.Now().Add(1 * time.Hour),
		HttpOnly: true,
	})
}

// Delete all cookies
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
