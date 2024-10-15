package main

import (
    "database/sql"
    "fmt"
    "html/template"
    "log"
    "net/http"
    _ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var tpl *template.Template

// User represents a user in the forum
type User struct {
    ID       int
    Username string
    Email    string
    Fullname string
}

// Post represents a post in the forum
type Post struct {
    ID        int
    UserID    int
    Title     string
    Content   string
    Username  string
    CreatedAt string
}

func main() {
    var err error
    // Open the SQLite database
    db, err = sql.Open("sqlite3", "./forum.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Load the single HTML template
    tpl = template.Must(template.ParseFiles("forum.html"))

    // Set up the route to serve the forum page
    http.HandleFunc("/", forumHandler)

    // Start the server
    fmt.Println("Server is running on port 8080...")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

// forumHandler serves the forum page, handles form submissions and shows posts
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
    tpl.Execute(w, posts)
}

// handleFormSubmission processes registration or new post form submissions
func handleFormSubmission(w http.ResponseWriter, r *http.Request) {
    action := r.FormValue("action")

    if action == "register" {
        username := r.FormValue("username")
        email := r.FormValue("email")
        fullname := r.FormValue("fullname")

        _, err := db.Exec("INSERT INTO Users (username, email, fullname) VALUES (?, ?, ?)", username, email, fullname)
        if err != nil {
            http.Error(w, "User registration failed", http.StatusInternalServerError)
            return
        }
    } else if action == "newpost" {
        userID := 1 // Assuming logged-in user ID (you can extend it for real authentication)
        title := r.FormValue("title")
        content := r.FormValue("content")
        categoryID := 1 // Default category

        _, err := db.Exec("INSERT INTO Posts (user_id, title, content, category_id) VALUES (?, ?, ?, ?)", userID, title, content, categoryID)
        if err != nil {
            http.Error(w, "Post creation failed", http.StatusInternalServerError)
            return
        }
    }

    http.Redirect(w, r, "/", http.StatusSeeOther)
}

// getPosts retrieves posts from the database
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
