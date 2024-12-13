package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"forum_full/database"
	"forum_full/utils"
)

// FilterHandler handles a GET request to filter posts by category.
//
// It first checks if the request method is GET and that the category name is
// valid. Then it retrieves the total count of posts for the given category and
// uses it to get the pagination parameters.
//
// It then queries the database to retrieve the posts for the given category and
// page. It uses the Getcontent function to retrieve the posts content from the
// database rows.
//
// It then handles the user session by retrieving the user ID from the session
// cookie and getting the user information from the database.
//
// Finally, it renders the forum.html template with the retrieved data.
func FilterHandler(w http.ResponseWriter, r *http.Request) {
	guestCookie, _ := r.Cookie("Guest_token")
	sessionCookie, _ := r.Cookie("session_token")

	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	category := strings.TrimPrefix(r.URL.Path, "/filter/")
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
	pagination := database.GetPagination(r, totalPosts)

	rows, err := database.DB.Query(`
        SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
        FROM Posts p
        JOIN Users u ON p.user_id = u.user_id
        WHERE p.categories LIKE ?
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?`, "%"+category+"%", pagination.PageSize, pagination.Offset)
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

// LikedHandler handles requests to display posts liked by the logged-in user.
// It requires a valid session token and supports pagination of the liked posts.
func LikedHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session token from cookies
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Get user ID from session
	userID := database.Sessions[cookie.Value]
	if userID == "" {
		http.Error(w, "Failed to Load Liked Posts", http.StatusInternalServerError)
		return
	}

	// Ensure the request method is GET
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Get total count of liked posts for pagination
	var totalPosts int
	err = database.DB.QueryRow(`SELECT COUNT(*) FROM Posts p
        JOIN Reactions r ON p.post_id = r.post_id
        WHERE r.reaction_type = 'LIKE' AND r.user_id = ?`, userID).Scan(&totalPosts)
	if err != nil {
		http.Error(w, "Failed to count posts", http.StatusInternalServerError)
		return
	}

	// Get pagination parameters based on total liked posts
	pagination := database.GetPagination(r, totalPosts)

	// Query the database for liked posts with pagination
	rows, err := database.DB.Query(`
        SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
        FROM Posts p
        JOIN Users u ON p.user_id = u.user_id
        JOIN Reactions r ON p.post_id = r.post_id
        WHERE r.reaction_type = 'LIKE' AND r.user_id = ?
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?`, userID, pagination.PageSize, pagination.Offset)
	if err != nil {
		http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Retrieve post content from query results
	posts, err := database.Getcontent(rows)
	if err != nil {
		http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		return
	}

	// Get user information for displaying the username
	userInfo, err := database.GetUserInfo(userID)
	if err != nil {
		http.Error(w, "Failed to load user info", http.StatusInternalServerError)
		return
	}

	// Prepare data for rendering the template
	data := struct {
		P          []utils.Post
		Username   string
		Pagination *database.Pagination
	}{
		P:          posts,
		Username:   userInfo.Username,
		Pagination: pagination,
	}

	// Render the forum page with liked posts
	if err := database.Tpl.ExecuteTemplate(w, "forum.html", data); err != nil {
		fmt.Println(err)
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


	// Get total count for pagination
	var totalPosts int

	if err = database.DB.QueryRow("SELECT COUNT(*) FROM Posts WHERE user_id = ?", userID).Scan(&totalPosts); err != nil {
		http.Error(w, "Failed to count posts", http.StatusInternalServerError)
		return
	}

	// Get pagination parameters
	pagination := database.GetPagination(r, totalPosts)

	rows, err := database.DB.Query(`
        SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
        FROM Posts p
        JOIN Users u ON p.user_id = u.user_id
        WHERE u.user_id = ?
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?`, userID, pagination.PageSize, pagination.Offset)
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
