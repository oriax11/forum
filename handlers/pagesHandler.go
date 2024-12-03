package handlers

import (
	"fmt"
	"net/http"

	"forum_full/database"
)

// ProfileHandler handles a request to a user's profile page
// It retrieves the session cookie and checks if the user is logged in
// If the user is not logged in, it redirects to the login page
// If the user is logged in, it retrieves the user's information from the database
// and renders the profile.html template
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	email, exists := database.Sessions[cookie.Value]
	if !exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, err := database.GetUserInfo(email)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	err = database.Tpl.ExecuteTemplate(w, "profile.html", user)
	if err != nil {
		fmt.Println("Profile template error : ", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}
}

// 404 Handler
func NotFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	database.Tpl.ExecuteTemplate(w, "404.html", nil)
}
