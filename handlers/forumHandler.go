package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"forum_full/database"
	"forum_full/utils"
)


// ForumHandler handles the forum homepage with pagination.
func ForumHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the correct route
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Handle post creation
	if r.Method == http.MethodPost {
		database.CreatePost(w, r)
		return
	}

	// Default pagination parameters
	offset := 0 

	// Get pagination parameters from the request
	offsetStr := r.FormValue("offset")
	// Parse the offset
	if offsetStr != "" {
		parsedOffset, err := strconv.Atoi(offsetStr)
		if err == nil {
			offset = parsedOffset
		}
	}



	// Fetch posts using offset and limit
	posts, err := database.GetPosts(offset)
	if err != nil {
		http.Error(w, "Failed to load posts", http.StatusInternalServerError)
		return
	}

	// Determine offsets for pagination buttons


	// Check cookies for user session or guest
	guestCookie, _ := r.Cookie("Guest_token")
	sessionCookie, _ := r.Cookie("session_token")

	if guestCookie != nil {
		// Guest user data
		data := struct {
			P         []utils.Post
			Username  string
			Offset    int
		}{
			P:         posts,
			Username:  "",
			Offset:    offset + 6,
		}

		err = database.Tpl.ExecuteTemplate(w, "forum.html", data)
		if err != nil {
			fmt.Println(err)
			http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
		}
	} else if sessionCookie != nil {
		// Logged-in user
		userID, exists := database.Sessions[sessionCookie.Value]
		if !exists {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		userInfo, err := database.GetUserInfo(userID)
		if err != nil {
			http.Error(w, "Failed to load user info", http.StatusInternalServerError)
			return
		}

		data := struct {
			P         []utils.Post
			Username  string
			Offset    int

		}{
			P:         posts,
			Username:  userInfo.Username,
			Offset:    offset,

		}

		err = database.Tpl.ExecuteTemplate(w, "forum.html", data)
		if err != nil {
			fmt.Println(err)
			http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
			return
		}
	} else {
		// No valid cookie, redirect to login
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}


// GuestHandler handles requests for guest users, generating a session and redirecting them to the homepage.
func GuestHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve all cookies from the request
	cookies := r.Cookies()
	if len(cookies) != 0 {
		// Delete all cookies if any exist
		utils.DeleteAllCookies(w, r)
	}

	// Generate a new session ID for the guest user
	sessionID, err := utils.GenerateSessionID()
	if err != nil {
		// Respond with an internal server error if session generation fails
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Store guest session information in memory
	database.Sessions[sessionID] = "guest"

	// Set a cookie for the guest session
	name := "Guest_token"
	utils.SetCookies(w, sessionID, name, false)

	// Redirect the guest user to the homepage
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
