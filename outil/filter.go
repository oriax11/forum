package forum_full

import (
	"fmt"
	"net/http"
)

func FilterHandler(w http.ResponseWriter, r *http.Request) {
	var id string
	cookie, _ := r.Cookie("session_token")
	email := sessions[cookie.Value]
	if r.Method == http.MethodGet {
		// Retrieve the "query" parameter
		action := r.URL.Query().Get("query")
		fmt.Println(action)
		if action == "cat_filter" {
			category := r.URL.Query().Get("categories")

			categoriesField := []string{"General", "Art", "News", "Technology", "Sport"}
			isValidCategory := false

			for _, value := range categoriesField {
				if value == category {
					isValidCategory = true
					break
				}
			}

			if !isValidCategory {
				http.Error(w, "Oops! Wrong category name", http.StatusBadRequest)
				return
			}

			db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&id)
			rows, _ := db.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
						   FROM Posts p
						   JOIN Users u ON p.user_id = u.user_id
						   WHERE p.categories LIKE ? `, "%"+category+"%")

			defer rows.Close()
			posts, err := Getcontent(rows)
			// fmt.Println(posts)
			if err != nil {
				http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
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

			tpl.ExecuteTemplate(w, "forum.html", data)
			return
		} else {
			http.Error(w, "Invalid action", http.StatusBadRequest)
		}
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}
