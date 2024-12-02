package handlers

import (
	"fmt"
	"net/http"

	"forum_full/database"
	"forum_full/utils"
)

// Forum Handler
func ForumHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		NotFound(w, r)
		return
	}
	if r.Method == http.MethodPost {
		database.CreatePost(w, r)
		return
	}
	guestCookie, _ := r.Cookie("Guest_token")

	sessionCookie, _ := r.Cookie("session_token")


	posts, err := database.GetPosts()
	if err != nil {
		http.Error(w, "Failed to load posts", http.StatusInternalServerError)
		return
	}

	if guestCookie != nil {
		// Guest user, render index with posts only
		data := struct {
			P       []utils.Post
			Username string
		}{
			P:       posts,
			Username: "",
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
			P       []utils.Post
			Username string
		}{
			P:       posts,
			Username: userInfo.Username,
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

func GuestHandler(w http.ResponseWriter, r *http.Request) {

	cookies := r.Cookies()
	if len(cookies) != 0 {
		utils.DeleteAllCookies(w, r)
	}
	sessionID, err := utils.GenerateSessionID()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Store guest session information in memory
	database.Sessions[sessionID] = "guest"
	name := "Guest_token"
	utils.SetCookies(w, sessionID, name, false )

	http.Redirect(w, r, "/", http.StatusSeeOther)
}