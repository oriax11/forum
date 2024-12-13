package database

import (
	"net/http"
	"strings"
)

// CreatePost handles a POST request to create a new post.
// It validates the categories and rejects the request if the categories are empty.
// It redirects the user to the homepage if the request is successful.
func CreatePost(w http.ResponseWriter, r *http.Request) {
	// A guest user cannot create a post
	if _, err := r.Cookie("Guest_token"); err == nil {
		http.Redirect(w, r, "/login", http.StatusPermanentRedirect)
	}

	// Parse the form
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Get the post title and content from the form
	title := r.FormValue("title")
	content := r.FormValue("content")

	// Get the selected categories from the form
	categoryType := r.Form["type"]
	allowedCategories := []string{"General", "Art", "News", "Technology", "Sport"}

	// Validate the categories
	categorySet := make(map[string]bool)
	for _, category := range categoryType {
		for _, allowed := range allowedCategories {
			if category == allowed {
				categorySet[category] = true
				break
			}
		}
	}

	// Fill the unique categories back to the slice
	filteredCategories := []string{}
	for category := range categorySet {
		filteredCategories = append(filteredCategories, category)
	}

	// Join the categories with a space
	allCategories := strings.Join(filteredCategories, " ")

	// Validate the title and content
	if len(title) > 150 {
		http.Error(w, "Post title cannot exceed 150 characters.", http.StatusBadRequest)
		return
	}
	if len(content) > 3000 {
		http.Error(w, "Post content cannot exceed 3000 characters.", http.StatusBadRequest)
		return
	}

	// Get the session token from the cookie
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Get the user ID from the session token
	userID := Sessions[cookie.Value]
	if userID == "" {
		http.Error(w, "Failed to load Post", http.StatusInternalServerError)
		return
	}

	// Validate the categories again
	if len(filteredCategories) == 0 {
		http.Error(w, "Category cannot be empty", http.StatusBadRequest)
		return
	}
	if title == "" || content == "" {
		http.Error(w, "Title and content cannot be empty", http.StatusBadRequest)
		return
	}

	// Insert the post into the database
	_, err = DB.Exec(
		"INSERT INTO Posts (user_id, title, content, categories) VALUES (?, ?, ?, ?)",
		userID, strings.TrimSpace(title), strings.TrimSpace(content), allCategories,
	)
	if err != nil {
		http.Error(w, "Post creation failed", http.StatusInternalServerError)
		return
	}

	// Redirect the user to the homepage
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
