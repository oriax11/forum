package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	// "golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

var (
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

	// Retrieve posts to display
	posts, err := getPosts()
	if err != nil {
		http.Error(w, "Failed to load posts", http.StatusInternalServerError)
		return
	}

	// Render the template with posts
	err = tpl.ExecuteTemplate(w, "forum.html", posts)
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

		_, err := db.Exec("INSERT INTO Users (username, email, fullname , password) VALUES (?, ?, ?, ?)", username, email, fullname, password)
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
		userID := 1 // Placeholder for logged-in user ID (implement real authentication)
		title := r.FormValue("title")
		content := r.FormValue("content")

		_, err := db.Exec("INSERT INTO Posts (user_id, title, content) VALUES (?, ?, ?)", userID, title, content)
		if err != nil {
			http.Error(w, "Post creation failed", http.StatusInternalServerError)
			return
		}
	}else if action == "login" {
		email := r.FormValue("email")
		
		password := r.FormValue("password")
	
		type Cred struct {
			Password string
		}
		var ab Cred
		err :=  db.QueryRow("SELECT password FROM Users WHERE email = ?", email).Scan(&ab.Password)
		if err == sql.ErrNoRows {
			erro := Errors{
				ErrorType: "no user with this email!!",
			}
			tpl.ExecuteTemplate(w, "login.html", erro)
			return
		}

		if password != ab.Password {
			erro := Errors{
				ErrorType: "password is uncorrect!!",
			}
			tpl.ExecuteTemplate(w, "login.html", erro)
			return
		} else {	
			fmt.Println("logged in")
			fmt.Println(ab.Password)
		}



	http.Redirect(w, r, "/", http.StatusSeeOther)
}
}

func getPosts() ([]Post, error) {
	rows, err := db.Query(`SELECT p.post_id, p.title, p.content, p.created_at, u.username 
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
		if err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.CreatedAt, &post.Username); err != nil {
			return nil, err
		}
		posts = append(posts, post)
	}
	return posts, nil
}
