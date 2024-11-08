package main

import (
	outil "forum_full/outil"
	"log"
	"net/http"
)

var err error

func main() {
	err = outil.InitDB()
	if err != nil {
		log.Fatal("Failed to open the database:", err)
	}

	// Set up routes
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", outil.ForumHandler)
	http.HandleFunc("/register", outil.RegisterHandler)
	http.HandleFunc("/login", outil.LoginHandler)
	http.HandleFunc("/profile", outil.ProfileHandler)
	http.HandleFunc("/404", outil.NotFound)
	http.HandleFunc("/Guest", outil.GuestHandler)
	http.HandleFunc("/Logout", outil.LogoutHandler)

	// Start the server
	log.Println("Server is running on port http://localhost:9080/")
	log.Fatal(http.ListenAndServe(":9080", nil))
}
