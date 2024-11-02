package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var (
	sessions = make(map[string]string) // session store with sessionID to email mapping sessions = make(map[string]string) // session store with sessionID to email mapping
	db       *sql.DB
	tpl      *template.Template
)

func init() {
	tpl = template.Must(template.ParseGlob("templates/*.html"))
}

type Errors struct {
	ErrorType string
}

type User struct {
	ID         int
	Username   string
	Email      string
	Fullname   string
	Created_at string
}

type Post struct {
	ID             int
	UserID         int
	Title          string
	Content        string
	Username       string
	Categorie_type string
	CreatedAt      time.Time
	TimeAgo			string
}

func main() {

	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", (http.StripPrefix("/static/", fs)))

	var err error
	// Open the SQLite database
	db, err = sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Fatal("Failed to open the database:", err)
	}

	// Set up the route to serve the forum page
	http.HandleFunc("/", forumHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/profile", Profile)
	http.HandleFunc("/404", NotFound)
	http.HandleFunc("/Guest", GuestHandler)
	http.HandleFunc("/Logout", Logout)


	// Start the server
	log.Println("Server is running on port http://localhost:9080/")
	log.Fatal(http.ListenAndServe(":9080", nil))
}


func Logout (w http.ResponseWriter, r *http.Request) {
	deleteAllCookies(w,r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
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

func deleteAllCookies(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range r.Cookies() {
		// Set the cookie's MaxAge to -1 and Expires to a past time to delete it
		http.SetCookie(w, &http.Cookie{
			Name:     cookie.Name,
			Value:    "",
			Expires:  time.Unix(0, 0), // Set to the past
			MaxAge:   -1,              // MaxAge -1 deletes the cookie
			HttpOnly: true,
		})
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

func Profile(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("query")
	if r.Method == http.MethodGet {
		if action == "profile" {
			cookie, err := r.Cookie("session_token")
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Get email from session store
			email, exists := sessions[cookie.Value]
			if !exists {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			// Get user info from database using the email
			user, err := Userinfo(email)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return

			}

			// Create data structure to pass to template
			data := struct {
				User User
			}{
				User: user,
			}

			err = tpl.ExecuteTemplate(w, "profile.html", data)
			if err != nil {
				http.Error(w, "Error loading the profile page", http.StatusInternalServerError)
			}
		} else {
			NotFound(w, r)

		}
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		handleFormSubmission(w, r)
		return
	}
	err := tpl.ExecuteTemplate(w, "login.html", nil)
	if err != nil {
		http.Error(w, "Error loading the login page", http.StatusInternalServerError)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		handleFormSubmission(w, r)
		return
	}
	err := tpl.ExecuteTemplate(w, "register.html", nil)
	if err != nil {
		http.Error(w, "Error loading the registration page", http.StatusInternalServerError)
	}
}

func forumHandler(w http.ResponseWriter, r *http.Request) {
	if(r.URL.Path != "/"){
        NotFound(w, r)
        return
    }
	if r.Method == http.MethodPost {
		handleFormSubmission(w, r)
		return
	}

	// Check for guest cookie
	guestCookie, err := r.Cookie("Guest_token")
	if err != nil && err != http.ErrNoCookie {
		// Handle error if needed
		http.Error(w, "Error retrieving cookies", http.StatusInternalServerError)
		return
	}

	// Check for session cookie
	sessionCookie, err := r.Cookie("session_token")
	if err != nil && err != http.ErrNoCookie {
		// Handle error if needed
		http.Error(w, "Error retrieving cookies", http.StatusInternalServerError)
		return
	}

	// Load posts regardless of user type
	posts, err := getPosts()
	if err != nil {
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

func handleFormSubmission(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("query")

	if action == "reg" {
		username := r.FormValue("username")
		email := r.FormValue("email")
		fullname := r.FormValue("fullname")
		password := r.FormValue("password")

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
		title := r.FormValue("title")
		content := r.FormValue("content")
		category_type := r.FormValue("category_type")
		cookie, _ := r.Cookie("session_token")
		email := sessions[cookie.Value]

		if title == "" || content == "" || category_type == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		
		db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&userID)

		_, err = db.Exec(
			"INSERT INTO Posts (user_id, title, content, category_name) VALUES (?, ?, ?, ?)",
			userID, title, content, category_type,
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
		if (len(like_btn) == 0 && len(dislike_btn) > 0){
			react_holder = dislike_btn
		}else if (len(like_btn) > 0 && len(dislike_btn) == 0) {
			react_holder = like_btn
		}

		db.QueryRow("SELECT reaction_type FROM Reactions WHERE post_id = ? AND user_id = ?", post_id, userID).Scan(&reaction_type)

		// fmt.Println(reaction_type)
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
		}else {
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
					react_holder,post_id, userID,
				)
				if err != nil {
					fmt.Print(err, "Update")
					http.Error(w, "Post creation failed", http.StatusInternalServerError)
					return
				}
			}
		}
		// fmt.Println(react_holder , post_id , userID)
		
	}else if action == "comment" {
		var userID int
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
		
		db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&userID)


		if len(comment_content) > 0 {
			_, err = db.Exec(
				"INSERT INTO Comment (post_id ,user_id, comment_content) VALUES (?, ?, ?)",
				post_id, userID, comment_content,
			)
			if err != nil {
				fmt.Print(err, "insert")
				http.Error(w, "Post creation failed", http.StatusInternalServerError)
				return
			}
		}else {
			fmt.Print("empty string")
		}

		// fmt.Println(comment_content, post_id)

	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}


func AboutTime(t time.Time) string {
    duration := time.Since(t)

    switch {
    case duration < time.Minute:
        return fmt.Sprintf("%d sec ago", int(duration.Seconds()))
    case duration < time.Hour:
        return fmt.Sprintf("%d min ago", int(duration.Minutes()))
    case duration < 24*time.Hour:
        return fmt.Sprintf("%d hours ago", int(duration.Hours()))
    case duration < 30*24*time.Hour:
        return fmt.Sprintf("%d days ago", int(duration.Hours()/24))
    case duration < 12*30*24*time.Hour:
        return fmt.Sprintf("%d months ago", int(duration.Hours()/24/30))
    default:
        return fmt.Sprintf("%d years ago", int(duration.Hours()/24/365))
    }
}

func getPosts() ([]Post, error) {
    rows, err := db.Query(`SELECT p.post_id, p.title, p.content, p.created_at, u.username, p.category_name
                           FROM Posts p
                           JOIN Users u ON p.user_id = u.user_id
                           ORDER BY p.created_at DESC`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var posts []Post
    for rows.Next() {
        var post Post
        if err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.CreatedAt, &post.Username, &post.Categorie_type); err != nil {
            return nil, err
        }

        post.TimeAgo = AboutTime(post.CreatedAt)
        posts = append(posts, post)
    }
    return posts, nil
}

func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func NotFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	tpl.ExecuteTemplate(w, "404.html", nil)
}
