package handlers

import (
	"fmt"
	"net/http"

	"forum_full/database"
	"forum_full/utils"
)

// FilterHandler handles a GET request to filter posts by category.
// handlers/filterHandler.go
func FilterHandler(w http.ResponseWriter, r *http.Request) {
	guestCookie, _ := r.Cookie("Guest_token")
	sessionCookie, _ := r.Cookie("session_token")

	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
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

	// Get total count for pagination
	var totalPosts int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM Posts WHERE categories LIKE ?", "%"+category+"%").Scan(&totalPosts); err != nil {
		http.Error(w, "Failed to count posts", http.StatusInternalServerError)
		return
	}

	// Get pagination parameters
	pagination := database.GetPagination(r, totalPosts, fmt.Sprintf("filter?query=cat_filter&categories=%s&", category))

	rows, err := database.DB.Query(`
        SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
        FROM Posts p
        JOIN Users u ON p.user_id = u.user_id
        WHERE p.categories LIKE ?
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?`, "%"+category+"%", pagination.PageSize, pagination.OffSet)
	if err != nil {
		http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	posts, err := database.Getcontent(rows)
	if err != nil {
		http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		return
	}

	data := struct {
		P          []utils.Post
		Username   string
		Pagination *database.Pagination
	}{
		P:          posts,
		Pagination: pagination,
	}

	// Handle user session
	if guestCookie != nil {
		data.Username = ""
	} else if sessionCookie != nil {
		userID, exists := database.Sessions[sessionCookie.Value]
		if !exists || userID == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		userInfo, err := database.GetUserInfo(userID)
		if err != nil {
			http.Error(w, "Failed to load user info", http.StatusInternalServerError)
			return
		}

		data.Username = userInfo.Username
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}

	if err := database.Tpl.ExecuteTemplate(w, "forum.html", data); err != nil {
		http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
		return
	}
}

// handlers/filterHandler.go
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

	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	action := r.URL.Query().Get("query")
	if action != "liked" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Get total count for pagination
	var totalPosts int
	err = database.DB.QueryRow(`SELECT COUNT(*) FROM Posts p
        JOIN Reactions r ON p.post_id = r.post_id
        WHERE r.reaction_type = 'LIKE' AND r.user_id = ?`, userID).Scan(&totalPosts)
	if err != nil {
		http.Error(w, "Failed to count posts", http.StatusInternalServerError)
		return
	}

	// Get pagination parameters
	pagination := database.GetPagination(r, totalPosts, "liked?query=liked&")

	rows, err := database.DB.Query(`
        SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
        FROM Posts p
        JOIN Users u ON p.user_id = u.user_id
        JOIN Reactions r ON p.post_id = r.post_id
        WHERE r.reaction_type = 'LIKE' AND r.user_id = ?
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?`, userID, pagination.PageSize, pagination.OffSet)
	if err != nil {
		http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	posts, err := database.Getcontent(rows)
	if err != nil {
		http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		return
	}

	userInfo, err := database.GetUserInfo(userID)
	if err != nil {
		http.Error(w, "Failed to load user info", http.StatusInternalServerError)
		return
	}

	data := struct {
		P          []utils.Post
		Username   string
		Pagination *database.Pagination
	}{
		P:          posts,
		Username:   userInfo.Username,
		Pagination: pagination,
	}

	if err := database.Tpl.ExecuteTemplate(w, "forum.html", data); err != nil {
		http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
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

	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	action := r.URL.Query().Get("query")
	if action != "created" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Get total count for pagination
	var totalPosts int
	
	if err = database.DB.QueryRow("SELECT COUNT(*) FROM Posts WHERE user_id = ?",userID).Scan(&totalPosts);err != nil {
		http.Error(w, "Failed to count posts", http.StatusInternalServerError)
		return
	}

	// Get pagination parameters
	pagination := database.GetPagination(r, totalPosts, "created?query=created&")

	rows, err := database.DB.Query(`
        SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
        FROM Posts p
        JOIN Users u ON p.user_id = u.user_id
        WHERE u.user_id = ?
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?`,userID,pagination.PageSize,pagination.OffSet)
	if err != nil {
		http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	posts, err := database.Getcontent(rows)
	if err != nil {
		http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		return
	}

	userInfo, err := database.GetUserInfo(userID)
	if err != nil {
		http.Error(w, "Failed to load user info", http.StatusInternalServerError)
		return
	}

	data := struct {
		P          []utils.Post
		Username   string
		Pagination *database.Pagination
	}{
		P:          posts,
		Username:   userInfo.Username,
		Pagination: pagination,
	}

	if err := database.Tpl.ExecuteTemplate(w, "forum.html", data); err != nil {
		http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
	}
}
