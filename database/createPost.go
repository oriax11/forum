package database

import (
	"net/http"
	"strings"

	"forum_full/utils"
)

//func Creat Posts
func CreatePost(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("query")

	if action != "newpost" {
		http.Error(w, "Bad request\nHmmm, it looks like you are lost!!", http.StatusBadRequest)
		return
	}

	if action == "newpost" {
		_, err := r.Cookie("Guest_token")
		if err == nil {
			erro := utils.Errors{
				ErrorType: "Please Log in to post posts!",
			}
			Tpl.ExecuteTemplate(w, "login.html", erro)
			return
		}


		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		title := r.FormValue("title")
		content := r.FormValue("content")
		category_type := r.Form["type"]

		Allcategories := strings.Join(category_type, " ")

		if len(title) > 150 {
			http.Error(w, "Post title cannot exceed 150 characters.", http.StatusBadRequest)
			return
		}
		if len(content) > 3000 {
			http.Error(w, "Post content cannot exceed 3000 characters.", http.StatusBadRequest)
			return
		}

		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		userID := Sessions[cookie.Value]

		if len(category_type) == 0 {
			http.Error(w, "category cannot be emty", http.StatusBadRequest)
			return
		}
		if title == "" || content == "" {
			http.Error(w, "Title and content cannot be empty", http.StatusBadRequest)
			return
		}

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
