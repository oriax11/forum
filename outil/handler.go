package forum_full

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Forum Handler
func ForumHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		NotFound(w, r)
		return
	}
	if r.Method == http.MethodPost {
		CreatePost(w, r)
		CommentReactions(w,r)
		PostComment(w,r)
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
		action := r.FormValue("query")
		if action == "reg" {
			username := r.FormValue("username")
			email := r.FormValue("email")
			fullname := r.FormValue("fullname")
			password := r.FormValue("password")

			if len(username) > 20 {
				erro := Errors{
					ErrorType: "Username cannot exceed 20 characters.",
				}
				tpl.ExecuteTemplate(w, "register.html", erro)
				return
			}
			if len(password) < 8 {
				erro := Errors{
					ErrorType: "Password cannot be less than 8 characters.",
				}
				tpl.ExecuteTemplate(w, "register.html", erro)
				return
			}

			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, "Error processing password", http.StatusInternalServerError)
				return
			}

			_, err = db.Exec("INSERT INTO Users (username, email, fullname, password) VALUES (?, ?, ?, ?)",
				username, email, fullname, string(hashedPassword))
			if err != nil {
				if strings.Contains(err.Error(), "UNIQUE constraint failed: Users.username") {
					erro := Errors{
						ErrorType: "Username already exists",
					}
					tpl.ExecuteTemplate(w, "register.html", erro)
					return
				}
				http.Error(w, "User registration failed", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {
			http.Error(w, "Bad request\nHmmm its looks like you are lost!!", http.StatusBadRequest)
			return
		}

	} else if r.Method == http.MethodGet {
		tpl.ExecuteTemplate(w, "register.html", nil)
	} else {
		http.Error(w, "Method Not Allowed!!", http.StatusMethodNotAllowed)
		return
	}
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

	err = tpl.ExecuteTemplate(w, "profile.html", user)
	if err != nil {
		fmt.Println("Profile template error : ", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}
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
	action := r.FormValue("query")
	if r.Method == http.MethodPost {
		if action == "login" {
			email := r.FormValue("email")
			password := r.FormValue("password")

			type Cred struct {
				HashedPassword string
			}
			var cred Cred

			err := db.QueryRow("SELECT password FROM Users WHERE email = ?", email).Scan(&cred.HashedPassword)
			if err == sql.ErrNoRows {
				erro := Errors{
					ErrorType: "No user with this email!",
				}
				tpl.ExecuteTemplate(w, "login.html", erro)
				return
			} else if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}

			err = bcrypt.CompareHashAndPassword([]byte(cred.HashedPassword), []byte(password))
			if err != nil {
				erro := Errors{
					ErrorType: "Incorrect password!",
				}
				tpl.ExecuteTemplate(w, "login.html", erro)
				return
			}
			for key, value := range sessions {
				if value == email {
					delete(sessions, key)
				}
			}
			deleteAllCookies(w, r)

			sessionID, err := generateSessionID()
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// Store session information in memory
			sessions[sessionID] = email

			// Set session cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    sessionID,
				Expires:  time.Now().Add(1 * time.Hour),
				HttpOnly: true,
			})

			// login = true
			fmt.Println("Successfully logged in")

			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		} else {
			http.Error(w, "Bad request\nHmmm its looks like you are lost!!", http.StatusBadRequest)
			return
		}
	} else if r.Method == http.MethodGet {
		err := tpl.ExecuteTemplate(w, "login.html", nil)
		if err != nil {
			fmt.Println("login template error :", err)
			http.Error(w, "Internal Server Error", 500)
		}

	} else {
		http.Error(w, "Method Not Allowed!!", http.StatusMethodNotAllowed)
		return
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
