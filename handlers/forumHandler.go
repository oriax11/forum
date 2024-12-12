package handlers

import (
	"fmt"
	"net/http"

	"forum_full/database"
	"forum_full/utils"
)

// ForumHandler handles the forum homepage with pagination.
func ForumHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// Handle post creation
	if r.Method == http.MethodPost {
		database.CreatePost(w, r)
		return
	}

	

	// Fetch posts using offset and limit
	posts, pagination, err := database.GetPosts(r)
	if err != nil {
		http.Error(w, "Failed to load posts", http.StatusInternalServerError)
		return
	}

	guestCookie, _ := r.Cookie("Guest_token")
	sessionCookie, _ := r.Cookie("session_token")

	data := struct {
		P          []utils.Post
		Username   string
		Pagination *database.Pagination
	}{
		P:          posts,
		Pagination: pagination,
	}

	if guestCookie != nil {
		data.Username = ""
	} else if sessionCookie != nil {
		userID, exists := database.Sessions[sessionCookie.Value]
		if !exists || userID == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		userInfo, err := database.GetUserInfo(userID)
		if err != nil {
			http.Error(w, "Failed to load user info", http.StatusInternalServerError)
			return
		}

		data.Username = userInfo.Username
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}

	if err := database.Tpl.ExecuteTemplate(w, "forum.html", data); err != nil {
		fmt.Println(err)
		http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
		return
	}
}

// GuestHandler handles requests for guest users, generating a session and redirecting them to the homepage.
func GuestHandler(w http.ResponseWriter, r *http.Request) {
	cookies := r.Cookies()
	if len(cookies) != 0 {
		utils.DeleteAllCookies(w, r)
	}

	// Generate a new session ID for the guest user
	sessionID, err := utils.GenerateSessionID()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Store guest session information in memory
	database.Sessions[sessionID] = "guest"

	// Set a cookie for the guest session
	name := "Guest_token"
	utils.SetCookies(w, sessionID, name, false)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
