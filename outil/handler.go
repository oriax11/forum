package forum_full

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"
)

// Forum Handler
func ForumHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		NotFound(w, r)
		return
	}
	if r.Method == http.MethodPost {
		HandleFormSubmission(w, r)
		return
	}

	guestCookie, err := r.Cookie("Guest_token")
	if err != nil && err != http.ErrNoCookie {
		http.Error(w, "Error retrieving cookies", http.StatusInternalServerError)
		return
	}

	sessionCookie, err := r.Cookie("session_token")
	if err != nil && err != http.ErrNoCookie {
		http.Error(w, "Error retrieving cookies", http.StatusInternalServerError)
		return
	}

	posts, err := getPosts()
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to load posts", http.StatusInternalServerError)
		return
	}

	if guestCookie != nil {
		// Guest user, render index with posts only
		data := struct {
			P       []Post
			Message string
		}{
			P:       posts,
			Message: "",
		}

		err = tpl.ExecuteTemplate(w, "forum.html", data) // Use a different template for guests if needed
		if err != nil {
			fmt.Println(err)
			http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
		}
	} else if sessionCookie != nil {
		// Logged-in user
		email, exists := sessions[sessionCookie.Value]
		if !exists {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		userInfo, err := Userinfo(email)
		if err != nil {
			http.Error(w, "Failed to load user info", http.StatusInternalServerError)
			return
		}

		data := struct {
			P       []Post
			Message string
		}{
			P:       posts,
			Message: userInfo.Username,
		}

		err = tpl.ExecuteTemplate(w, "forum.html", data)
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

func Userinfo(email string) (User, error) {
	row := db.QueryRow(`SELECT u.user_id, u.username, u.email, u.fullname, u.created_at
                       FROM Users u 
                       WHERE u.email = ?`, email)

	var user User
	if err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Fullname, &user.Created_at); err != nil {
		if err == sql.ErrNoRows {
			return User{}, fmt.Errorf("no user found with email: %s", email)
		}
		return User{}, err
	}
	return user, nil
}

// Register Handler
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		HandleFormSubmission(w, r)
		return
	}
	tpl.ExecuteTemplate(w, "register.html", nil)
}

// Profile Handler
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	email, exists := sessions[cookie.Value]
	if !exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, err := getUserInfo(email)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tpl.ExecuteTemplate(w, "profile.html", user)
}

// Logout Handler
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	deleteAllCookies(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// 404 Handler
func NotFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	tpl.ExecuteTemplate(w, "404.html", nil)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		HandleFormSubmission(w, r)
		return
	}
	err := tpl.ExecuteTemplate(w, "login.html", nil)
	if err != nil {
		http.Error(w, "Error loading the login page", http.StatusInternalServerError)
	}
}

func GuestHandler(w http.ResponseWriter, r *http.Request) {
	cookies := r.Cookies()
	if len(cookies) != 0 {
		deleteAllCookies(w, r)
	}
	sessionID, err := generateSessionID()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Store guest session information in memory
	sessions[sessionID] = "guest"
	http.SetCookie(w, &http.Cookie{
		Name:     "Guest_token",
		Value:    sessionID,
		Expires:  time.Now().Add(1 * time.Hour),
		HttpOnly: false,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
