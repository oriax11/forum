package handlers

import (
	"fmt"
	"net/http"

	"forum_full/database"
)

// ProfileHandler handles a request to a user's profile page
// It first checks if the user is logged in and if the user exists.
// If the user is not logged in, it redirects the user to the login page.
// If the user exists, it retrieves the user's information from the database
// and renders the profile.html template with the user's information.
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	userID, exists := database.Sessions[cookie.Value]
	if !exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, err := database.GetUserInfo(userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	err = database.Tpl.ExecuteTemplate(w, "profile.html", user)
	if err != nil {
		// If there is an error, print it to the console
		fmt.Println("Profile template error : ", err)
		// And return a 500 Internal Server Error
		http.Error(w, "Internal Server Error", 500)
		return
	}
}

// 404 Handler
func NotFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	database.Tpl.ExecuteTemplate(w, "404.html", nil)
}
