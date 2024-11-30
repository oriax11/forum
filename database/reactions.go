package database

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func Postreact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var reactionData struct {
		PostID       string `json:"post_id"`
		ReactionType string `json:"reaction_type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reactionData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	sessionCookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID := Sessions[sessionCookie.Value]
	var currentReaction string
	DB.QueryRow("SELECT reaction_type FROM Reactions WHERE post_id = ? AND user_id = ?", reactionData.PostID, userID).Scan(&currentReaction)

	if currentReaction == "" {
		_, err = DB.Exec(
			"INSERT INTO Reactions (post_id, user_id, reaction_type) VALUES (?, ?, ?)",
			reactionData.PostID, userID, reactionData.ReactionType,
		)
	} else if currentReaction != reactionData.ReactionType {
		_, err = DB.Exec(
			"UPDATE Reactions SET reaction_type = ? WHERE post_id = ? AND user_id = ?",
			reactionData.ReactionType, reactionData.PostID, userID,
		)
	} else if currentReaction == reactionData.ReactionType {
		_, err = DB.Exec(
			"DELETE FROM Reactions WHERE post_id = ? AND user_id = ?", reactionData.PostID, userID,
		)
	}

	if err != nil {
		http.Error(w, "Failed to update reaction", http.StatusInternalServerError)
		return
	}

	var likes, dislikes int
	DB.QueryRow("SELECT COUNT(*) FROM Reactions WHERE post_id = ? AND reaction_type = 'LIKE'", reactionData.PostID).Scan(&likes)
	DB.QueryRow("SELECT COUNT(*) FROM Reactions WHERE post_id = ? AND reaction_type = 'DISLIKE'", reactionData.PostID).Scan(&dislikes)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"likes":    likes,
		"dislikes": dislikes,
	})
}

func CommentReact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Decode request body
	var CommentReact struct {
		CommentID    string `json:"comment_id"`
		ReactionType string `json:"reaction_type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&CommentReact); err != nil {
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
	var currentReaction string
	DB.QueryRow("SELECT reaction_type FROM CommentReactions WHERE comment_id = ? AND user_id = ?", CommentReact.CommentID, userID).Scan(&currentReaction)

	if currentReaction == "" {
		_, err = DB.Exec(
			"INSERT INTO CommentReactions (comment_id, user_id, reaction_type) VALUES (?, ?, ?)",
			CommentReact.CommentID, userID, CommentReact.ReactionType,
		)
	} else if currentReaction != CommentReact.ReactionType {
		_, err = DB.Exec(
			"UPDATE CommentReactions SET reaction_type = ? WHERE comment_id = ? AND user_id = ?",
			CommentReact.ReactionType, CommentReact.CommentID, userID,
		)
	} else if currentReaction == CommentReact.ReactionType {
		_, err = DB.Exec(
			"DELETE FROM CommentReactions WHERE comment_id = ? AND user_id = ?", CommentReact.CommentID, userID,
		)
	}

	if err != nil {
		http.Error(w, "Failed to update reaction", http.StatusInternalServerError)
		return
	}

	var likes, dislikes int
	DB.QueryRow("SELECT COUNT(*) FROM CommentReactions WHERE comment_id = ? AND reaction_type = 'LIKE'", CommentReact.CommentID).Scan(&likes)
	DB.QueryRow("SELECT COUNT(*) FROM CommentReactions WHERE comment_id = ? AND reaction_type = 'DISLIKE'", CommentReact.CommentID).Scan(&dislikes)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"likes":    likes,
		"dislikes": dislikes,
	})
}
