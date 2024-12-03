package handlers

import (
	"net/http"

	"forum_full/database"
	"forum_full/utils"
)

// FilterHandler handles a GET request to filter posts by category.
func FilterHandler(w http.ResponseWriter, r *http.Request) {
	guestCookie, _ := r.Cookie("Guest_token")
	sessionCookie, _ := r.Cookie("session_token")

	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	action := r.FormValue("query")
	if action != "cat_filter" {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	category := r.FormValue("categories")
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

	userID, sessionExists := "", false
	if sessionCookie != nil {
		userID, sessionExists = database.Sessions[sessionCookie.Value]
		if userID == "" {
			http.Error(w, "Failed to Load Post", http.StatusInternalServerError)
			return
		}
	}

	if !sessionExists && guestCookie == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// Query the database to get the posts that match the category
	rows, err := database.DB.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
						   FROM Posts p
						   JOIN Users u ON p.user_id = u.user_id
						   WHERE p.categories LIKE ?`, "%"+category+"%")
	if err != nil {
		http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Get the posts content and comments
	posts, err := database.Getcontent(rows)
	if err != nil {
		http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		return
	}

	if guestCookie != nil {
		data := struct {
			P       []utils.Post
			Username string
		}{
			P:       posts,
			Username: "",
		}
		if err := database.Tpl.ExecuteTemplate(w, "forum.html", data); err != nil {

			http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
		}
		return
	}

	if sessionExists {
		// Get the user info
		userInfo, err := database.GetUserInfo(userID)
		if err != nil {
			http.Error(w, "Failed to load user info", http.StatusInternalServerError)
			return
		}

		data := struct {
			P       []utils.Post
			Username string
		}{
			P:       posts,
			Username: userInfo.Username,
		}
		if err := database.Tpl.ExecuteTemplate(w, "forum.html", data); err != nil {
			http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
		}
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func LikedHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	userID := database.Sessions[cookie.Value]
	if userID == "" {
		http.Error(w, "Failed to Load Liked Posts", http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodGet {

		action := r.URL.Query().Get("query")
		if action == "liked" {
			rows, err := database.DB.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
							   FROM Posts p
							   JOIN Users u ON p.user_id = u.user_id
			JOIN Reactions r ON p.post_id = r.post_id
			WHERE r.reaction_type = 'LIKE' AND r.user_id=?`, userID)
			if err != nil {
				http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
			}
			defer rows.Close()
			posts, err := database.Getcontent(rows)
			if err != nil {
				http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
			}
			userInfo, err :=  database.GetUserInfo(userID)
			if err != nil {
				http.Error(w, "Failed to load user info", http.StatusInternalServerError)
				return
			}

			data := struct {
				P       []utils.Post
				Username string
			}{
				P:       posts,
				Username: userInfo.Username,
			}

			err = database.Tpl.ExecuteTemplate(w, "forum.html", data)
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
	cookie, err := r.Cookie("session_token")
	if err != nil {

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	userID := database.Sessions[cookie.Value]
	if userID == "" {
		http.Error(w, "Failed to Load Posts", http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodGet {

		action := r.URL.Query().Get("query")
		if action == "created" {
			rows, err := database.DB.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
							   FROM Posts p
							   JOIN Users u ON p.user_id = u.user_id
							   WHERE u.user_id = ? `, userID)
			if err != nil {
				http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
			}
			defer rows.Close()
			posts, err := database.Getcontent(rows)
			if err != nil {
				http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
			}
			userInfo, err :=  database.GetUserInfo(userID)
			if err != nil {
				http.Error(w, "Failed to load user info", http.StatusInternalServerError)
				return
			}

			data := struct {
				P       []utils.Post
				Username string
			}{
				P:       posts,
				Username: userInfo.Username,
			}

			err = database.Tpl.ExecuteTemplate(w, "forum.html", data)
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
