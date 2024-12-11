package utils

import "net/http"

// NoScriptCheckHandler verifies access when JavaScript is disabled.
func NoScriptCheckHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.NotFound(w, r)
        return
    }

    verification := r.FormValue("noscript_verification")
    if verification != "true" {
        http.Error(w, "Unauthorized access", http.StatusForbidden)
        return
    }

    http.Redirect(w, r, "/", http.StatusSeeOther)
}

