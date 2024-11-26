package forum_full

import (
	"net/http"
	"strings"
)

func CreatePost(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("query")

	if action == "newpost" {
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

	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
