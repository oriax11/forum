package database

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"forum_full/utils"
)

func PostComment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var CommentData struct {
		PostID  string `json:"post_id"`
		Content string `json:"comment_content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&CommentData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	sessionCookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID := Sessions[sessionCookie.Value]
	if userID == "" {
		http.Error(w, "Failed to update comment", http.StatusInternalServerError)
		return
	}

	var username string

	if err = DB.QueryRow("SELECT username FROM Users WHERE user_id = ?", userID).Scan(&username); err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	
	CommentData.Content = strings.Trim(CommentData.Content, " ")

	if CommentData.Content == "" {
		http.Error(w, "Comment cannot be empty", http.StatusBadRequest)
		return
	}

	_, err = DB.Exec("INSERT INTO Comment (user_id ,post_id, username, comment_content) VALUES ( ?,?, ?, ?)", userID, CommentData.PostID, username, CommentData.Content)
	if err != nil {
		http.Error(w, "Failed to insert comment", http.StatusInternalServerError)
		return
	}

	var commentID int
	var commentDate time.Time
	DB.QueryRow(`
		SELECT comment_id, comment_date
		FROM Comment
		WHERE post_id = ? AND user_id = ?
		ORDER BY comment_date DESC
		LIMIT 1
	`, CommentData.PostID, userID).Scan(&commentID, &commentDate)
	comment_date := utils.AboutTime(commentDate)

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
