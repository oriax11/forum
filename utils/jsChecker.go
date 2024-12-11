package utils

import "net/http"

func jsCheckHandler(w http.ResponseWriter, r *http.Request) {
	// Check for the presence of a query parameter or cookie
	jsEnabled := r.URL.Query().Get("js")
	if jsEnabled != "true" {
		// Redirect to the root if JavaScript is not detected
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// JavaScript is enabled, proceed normally
	w.Write([]byte("JavaScript is enabled!"))
}
