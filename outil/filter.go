package forum_full

import (
	"net/http"
)

func FilterHandler(w http.ResponseWriter, r *http.Request) {
	guestCookie, _ := r.Cookie("Guest_token")
	sessionCookie, _ := r.Cookie("session_token")

	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	action := r.URL.Query().Get("query")
	if action != "cat_filter" {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

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

	email, sessionExists := "", false
	if sessionCookie != nil {
		email, sessionExists = sessions[sessionCookie.Value]
	}

	if !sessionExists && guestCookie == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var id string
	if sessionExists {
		db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&id)
	}

	rows, err := db.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
						   FROM Posts p
						   JOIN Users u ON p.user_id = u.user_id
						   WHERE p.categories LIKE ?`, "%"+category+"%")
	if err != nil {
		http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	posts, err := Getcontent(rows)
	if err != nil {
		http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		return
	}

	if guestCookie != nil {
		data := struct {
			P       []Post
			Message string
		}{
			P:       posts,
			Message: "",
		}
		if err := tpl.ExecuteTemplate(w, "forum.html", data); err != nil {
			http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
		}
		return
	}

	if sessionExists {
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
		if err := tpl.ExecuteTemplate(w, "forum.html", data); err != nil {
			http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
		}
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func LikedHandler(w http.ResponseWriter, r *http.Request) {
	var id string
	cookie, err := r.Cookie("session_token")
	if err != nil {

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
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
