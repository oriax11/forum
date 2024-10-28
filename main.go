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
	db  *sql.DB
	tpl *template.Template
)

func init() {
	tpl = template.Must(template.ParseGlob("templates/*.html"))
}

type Errors struct {
	ErrorType string
}

type User struct {
	ID       int
	Username string
	Email    string
	Fullname string
}

type Post struct {
	ID        int
	UserID    int
	Title     string
	Content   string
	Username  string
	Categorie_type string
	CreatedAt string
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

	// Start the server
	log.Println("Server is running on port http://localhost:7080/")
	log.Fatal(http.ListenAndServe(":7080", nil))
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
	if r.Method == http.MethodPost {
		handleFormSubmission(w, r)
		return
	}
	cookie, ok  := r.Cookie("session_token")
	if  ok != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return 
	}
	
	email, exist := sessions[cookie.Value]
	if !exist {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return 
	}


	// Retrieve posts to display
	posts, err := getPosts()
	if err != nil {
		http.Error(w, "Failed to load posts", http.StatusInternalServerError)
		return
	}
	data := struct {
		P       []Post
		Message string
	}{
		P:       posts,
		Message:  email,
	}

	// Render the template with posts
	err = tpl.ExecuteTemplate(w, "forum.html", data)
	if err != nil {
		http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
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
		userID := 1
		title := r.FormValue("title")
		content := r.FormValue("content")
		category_type := r.FormValue("category_type")
		cookie, ok:= r.Cookie("session_token")
		if ok != nil  {



		}
		
		email:= sessions[cookie.Value]
		 db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&userID)

		 _, err := db.Exec(
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
	} else if action == "logout" {
		// Remove session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "",
			Expires:  time.Now().Add(-1 * time.Hour),
			HttpOnly: true,
		})
		// login = false
		fmt.Println("Successfully logged out")
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getPosts() ([]Post, error) {
	rows, err := db.Query(`SELECT p.post_id, p.title, p.content, p.created_at, u.username , p.category_name
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
