package forum_full

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// AboutTime converts a time object into a "time ago" format.
func AboutTime(t time.Time) string {
	duration := time.Since(t)

	switch {
	case duration < time.Minute:
		return fmt.Sprintf("%d sec ago", int(duration.Seconds()))
	case duration < time.Hour:
		return fmt.Sprintf("%d min ago", int(duration.Minutes()))
	case duration < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(duration.Hours()))
	case duration < 30*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(duration.Hours()/24))
	case duration < 12*30*24*time.Hour:
		return fmt.Sprintf("%d months ago", int(duration.Hours()/24/30))
	default:
		return fmt.Sprintf("%d years ago", int(duration.Hours()/24/365))
	}
}

// GenerateSessionID generates a random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Delete all cookies
func deleteAllCookies(w http.ResponseWriter, r *http.Request) {
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
