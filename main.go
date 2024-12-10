package main

import (
	"log"
	"net/http"

	"forum_full/database"
	"forum_full/handlers"
)


func main() {
	err := database.InitDB()
	if err != nil {
		log.Fatal("Failed to open the database:", err)
	}

	// Set up routes
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", handlers.ForumHandler)
	http.HandleFunc("/register", handlers.RegisterHandler)
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/profile", handlers.ProfileHandler)
	http.HandleFunc("/404", handlers.NotFound)
	http.HandleFunc("/guest", handlers.GuestHandler)
	http.HandleFunc("/logout", handlers.LogoutHandler)
	http.HandleFunc("/report", handlers.ReportHandler)
	http.HandleFunc("/filter", handlers.FilterHandler)
	http.HandleFunc("/created", handlers.CreatedHandler)
	http.HandleFunc("/liked", handlers.LikedHandler)
	http.HandleFunc("/api/postreact", database.Postreact)
	http.HandleFunc("/api/postComment", database.PostComment)
	http.HandleFunc("/api/postCommentReact", database.CommentReact)

	// Start the server
	log.Println("Server is running on port http://localhost:9080/")
	log.Fatal(http.ListenAndServe(":9080", nil))
}
