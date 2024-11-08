package forum_full

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func HandleFormSubmission(w http.ResponseWriter, r *http.Request) {
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

	} else if action == "newpost" {
		_, err := r.Cookie("Guest_token")
		if err == nil {
			erro := Errors{
				ErrorType: "Please Log in to post posts!",
			}
			tpl.ExecuteTemplate(w, "login.html", erro)
			return
		}

		userID := 1

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		title := r.FormValue("title")
		content := r.FormValue("content")
		category_type := r.Form["type"]

		Allcategories := strings.Join(category_type, " ")
		// category_content := "#" + strings.Join(category_type, " #")
		// fmt.Println(category_content)
		// fmt.Println(category_type, "hello")

		if len(title) > 150 {
			http.Error(w, "Post title cannot exceed 150 characters.", http.StatusBadRequest)
			return
		}
		if len(content) > 3000 {
			http.Error(w, "Post content cannot exceed 3000 characters.", http.StatusBadRequest)
			return
		}

		cookie, _ := r.Cookie("session_token")
		email := sessions[cookie.Value]

		if len(category_type) == 0 {
			http.Error(w, "category cannot be emty", http.StatusBadRequest)
			return
		}
		if title == "" || content == "" {
			http.Error(w, "Title and content cannot be empty", http.StatusBadRequest)
			return
		}

		db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&userID)

		_, err = db.Exec(
			"INSERT INTO Posts (user_id, title, content, categories) VALUES (?, ?, ?, ?)",
			userID, title, content, Allcategories,
		)
		if err != nil {
			http.Error(w, "Post creation failed", http.StatusInternalServerError)
			return
		}

	} else if action == "login" {
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
	} else if action == "react" {
		var userID int

		_, err := r.Cookie("Guest_token")
		if err == nil {
			erro := Errors{
				ErrorType: "Only registred Users can react!",
			}
			tpl.ExecuteTemplate(w, "login.html", erro)
			return
		}

		cookie, _ := r.Cookie("session_token")
		email := sessions[cookie.Value]

		db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&userID)

		like_btn := r.FormValue("like-btn")
		dislike_btn := r.FormValue("dislike-btn")
		post_id := r.FormValue("post_id")
		var react_holder string
		var reaction_type string
		if len(like_btn) == 0 && len(dislike_btn) > 0 {
			react_holder = dislike_btn
		} else if len(like_btn) > 0 && len(dislike_btn) == 0 {
			react_holder = like_btn
		}

		db.QueryRow("SELECT reaction_type FROM Reactions WHERE post_id = ? AND user_id = ?", post_id, userID).Scan(&reaction_type)

		if len(reaction_type) == 0 {
			_, err = db.Exec(
				"INSERT INTO Reactions (post_id ,user_id, reaction_type) VALUES (?, ?, ?)",
				post_id, userID, react_holder,
			)
			if err != nil {
				fmt.Print(err, "insert")
				http.Error(w, "Post creation failed", http.StatusInternalServerError)
				return
			}
		} else {
			if react_holder == reaction_type {
				_, err = db.Exec(
					"DELETE FROM Reactions WHERE post_id = ? AND user_id = ?",
					post_id, userID,
				)
				if err != nil {
					fmt.Print(err, "Delete")
					http.Error(w, "Post creation failed", http.StatusInternalServerError)
					return
				}
			} else {
				_, err = db.Exec(
					"UPDATE Reactions SET reaction_type = ? WHERE post_id = ? AND user_id = ?",
					react_holder, post_id, userID,
				)
				if err != nil {
					fmt.Print(err, "Update")
					http.Error(w, "Post creation failed", http.StatusInternalServerError)
					return
				}
			}
		}
		// fmt.Println(react_holder , post_id , userID)

	} else if action == "comment" {
		var username string
		comment_content := r.FormValue("comment-content")
		post_id := r.FormValue("post_id")
		_, err := r.Cookie("Guest_token")
		if err == nil {
			erro := Errors{
				ErrorType: "Only registred Users can react!",
			}
			tpl.ExecuteTemplate(w, "login.html", erro)
			return
		}

		cookie, _ := r.Cookie("session_token")
		email := sessions[cookie.Value]

		db.QueryRow("SELECT username FROM Users WHERE email = ?", email).Scan(&username)

		if len(comment_content) > 0 {
			_, err = db.Exec(
				"INSERT INTO Comment (post_id ,username, comment_content) VALUES (?, ?, ?)",
				post_id, username, comment_content,
			)
			if err != nil {
				fmt.Print(err, "insert")
				http.Error(w, "Post creation failed", http.StatusInternalServerError)
				return
			}
		} else {
			fmt.Print("empty string")
		}
	} else if action == "Liked" {
		rows, _ := db.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at
		FROM Posts p
		JOIN Reactions r ON p.user_id = r.user_id
		WHERE r.reaction_type = 'LIKE'`)
		defer rows.Close()
		var posts []Post
		for rows.Next() {
			var post Post
			rows.Scan(&post.ID, &post.Title, &post.Content, &post.Categories, &post.CreatedAt)
			posts = append(posts, post)
		}
		fmt.Println(posts)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
