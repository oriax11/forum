package forum_full

import (
	"fmt"
	"net/http"
)

func FilterHandler(w http.ResponseWriter, r *http.Request) {
	var id string
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
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
			rows, err := db.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
						   FROM Posts p
						   JOIN Users u ON p.user_id = u.user_id
						   WHERE p.categories LIKE ? `, "%"+category+"%")
			if err != nil {
				http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
			}

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

			err = tpl.ExecuteTemplate(w, "forum.html", data)
			if err != nil {
				http.Error(w, "Failed to execute template", http.StatusInternalServerError)
			}
			return
		} else {
			http.Error(w, "Invalid action", http.StatusBadRequest)
			return 
		}
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return 
	}
}

func LikedHandler(w http.ResponseWriter, r *http.Request) {
	var id string
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
	}
	email := sessions[cookie.Value]
	if r.Method == http.MethodGet {

		action := r.URL.Query().Get("query")
		if action == "liked" {
			db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&id)
			rows, err := db.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
							   FROM Posts p
							   JOIN Users u ON p.user_id = u.user_id
			JOIN Reactions r ON p.post_id = r.post_id
			WHERE r.reaction_type = 'LIKE' AND r.user_id=?`, id)
			if err != nil {
				http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
			}
			defer rows.Close()
			posts, err := Getcontent(rows)
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

			err = tpl.ExecuteTemplate(w, "forum.html", data)
			if err != nil {
				http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
			}

		} else {
			http.Error(w, "Invalid request ", http.StatusBadRequest)
			return 
		}
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return 
	}
}

func CreatedHandler(w http.ResponseWriter, r *http.Request) {
	var id string
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	email := sessions[cookie.Value]
	if r.Method == http.MethodGet {

		action := r.URL.Query().Get("query")
		if action == "created" {
			db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&id)
			rows, err := db.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
							   FROM Posts p
							   JOIN Users u ON p.user_id = u.user_id
							   WHERE u.user_id = ? `, id)
			if err != nil {
				http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
			}
			defer rows.Close()
			posts, err := Getcontent(rows)
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

			err = tpl.ExecuteTemplate(w, "forum.html", data)
			if err != nil {
				http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
			}

		} else {
			http.Error(w, "Invalid request ", http.StatusBadRequest)
			return 
		}
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
}
