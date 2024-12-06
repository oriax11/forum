package database

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"forum_full/utils"
)

// PostComment handles a POST request to add a new comment to a post.
// It validates the request method and session, decodes the request body,
// checks for empty comment content, and inserts the comment into the database.
// Finally, it returns a JSON response with the new comment's details.
func PostComment(w http.ResponseWriter, r *http.Request) {
	// Validate request method
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Decode request body
	var CommentData struct {
		PostID  string `json:"post_id"`
		Content string `json:"comment_content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&CommentData); err != nil {
		fmt.Println(err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate session
	sessionCookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get username from session
	userID := Sessions[sessionCookie.Value]
	if userID == "" {
		http.Error(w, "Failed to update comment", http.StatusInternalServerError)
		return
	}
	var username string
	err = DB.QueryRow("SELECT username FROM Users WHERE user_id = ?", userID).Scan(&username)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Validate comment content
	if CommentData.Content == "" {
		http.Error(w, "Comment cannot be empty", http.StatusBadRequest)
		return
	}

	// Trim whitespace from comment content
	CommentData.Content = strings.Trim(CommentData.Content, " ")

	// Insert comment into the database
	_, err = DB.Exec(
		"INSERT INTO Comment (user_id, post_id, username, comment_content) VALUES (?, ?, ?, ?)",
		userID, CommentData.PostID, username, CommentData.Content,
	)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to insert comment", http.StatusInternalServerError)
		return
	}

	// Retrieve the inserted comment's ID and date
	var commentID int
	var commentDate time.Time
	DB.QueryRow(`
		SELECT comment_id, comment_date
		FROM Comment
		WHERE post_id = ? AND user_id = ?
		ORDER BY comment_date DESC
		LIMIT 1
	`, CommentData.PostID, userID).Scan(&commentID, &commentDate)

	// Format comment date
	comment_date := utils.AboutTime(commentDate)

	// Return success response with comment details
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"comment": map[string]interface{}{
			"id":       commentID,
			"username": username,
			"content":  CommentData.Content,
			"date":     comment_date,
		},
	})
}
