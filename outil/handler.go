package forum_full

import (
	"database/sql"
	"encoding/json"
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

func Postreact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var reactionData struct {
		PostID       string `json:"post_id"`
		ReactionType string `json:"reaction_type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reactionData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	sessionCookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	email := sessions[sessionCookie.Value]
	var userID int
	if err := db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&userID); err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	var currentReaction string
	db.QueryRow("SELECT reaction_type FROM Reactions WHERE post_id = ? AND user_id = ?", reactionData.PostID, userID).Scan(&currentReaction)

	if currentReaction == "" {
		_, err = db.Exec(
			"INSERT INTO Reactions (post_id, user_id, reaction_type) VALUES (?, ?, ?)",
			reactionData.PostID, userID, reactionData.ReactionType,
		)
	} else if currentReaction != reactionData.ReactionType {
		_, err = db.Exec(
			"UPDATE Reactions SET reaction_type = ? WHERE post_id = ? AND user_id = ?",
			reactionData.ReactionType, reactionData.PostID, userID,
		)
	} else if  currentReaction == reactionData.ReactionType {
		_, err = db.Exec(
			"DELETE FROM Reactions WHERE post_id = ? AND user_id = ?", reactionData.PostID, userID,
		)
	}

	if err != nil {
		http.Error(w, "Failed to update reaction", http.StatusInternalServerError)
		return
	}

	var likes, dislikes int
	db.QueryRow("SELECT COUNT(*) FROM Reactions WHERE post_id = ? AND reaction_type = 'LIKE'", reactionData.PostID).Scan(&likes)
	db.QueryRow("SELECT COUNT(*) FROM Reactions WHERE post_id = ? AND reaction_type = 'DISLIKE'", reactionData.PostID).Scan(&dislikes)


	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"likes":    likes,
		"dislikes": dislikes,
	})
}
