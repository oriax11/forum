package database

import (
	"net/http"
	"strings"

	"forum_full/utils"
)

// CreatePost handles a POST request to create a new post.
//
// It validates the request body to ensure that the title and content of the
// post are not empty, and that the title does not exceed 150 characters.
// It also validates that the user is logged in and that the categories are not
// empty.
//
// If the validation fails, it returns an error to the client with a 400 status
// code. If the validation succeeds, it inserts the post into the database and
// redirects the user to the home page with a 303 status code.
func CreatePost(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("query")

	if action != "newpost" {
		http.Error(w, "Bad request\nHmmm, it looks like you are lost!!", http.StatusBadRequest)
		return
	}

	if action == "newpost" {
		// Check if the user is logged in as a guest
		_, err := r.Cookie("Guest_token")
		if err == nil {
			erro := utils.Errors{
				ErrorType: "Please Log in to post posts!",
			}
			Tpl.ExecuteTemplate(w, "login.html", erro)
			return
		}

		// Parse the form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		// Get the form data
		title := r.FormValue("title")
		content := r.FormValue("content")
		category_type := r.Form["type"]

		// Join the categories into a single string
		Allcategories := strings.Join(category_type, " ")

		// Validate the form data
		if len(title) > 150 {
			http.Error(w, "Post title cannot exceed 150 characters.", http.StatusBadRequest)
			return
		}
		if len(content) > 3000 {
			http.Error(w, "Post content cannot exceed 3000 characters.", http.StatusBadRequest)
			return
		}

		// Validate the user is logged in
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		userID := Sessions[cookie.Value]
		if (userID == "") {
			http.Error(w,"Faild to load Post", http.StatusInternalServerError)
			return
		}

		// Validate the categories
		if len(category_type) == 0 {
			http.Error(w, "category cannot be emty", http.StatusBadRequest)
			return
		}
		if title == "" || content == "" {
			http.Error(w, "Title and content cannot be empty", http.StatusBadRequest)
			return
		}

		// Insert the post into the database
		_, err = DB.Exec(
			"INSERT INTO Posts (user_id, title, content, categories) VALUES (?, ?, ?, ?)",
			userID, title, content, Allcategories,
		)
		if err != nil {
			http.Error(w, "Post creation failed", http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
