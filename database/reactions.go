package database

import (
	"encoding/json"
	"net/http"
)

// Postreact handles a POST request to update a user's reaction to a post.
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
	if userID == "" {
		http.Error(w, "Failed to update reaction", http.StatusInternalServerError)
		return
	}

	var currentReaction string
	// Get the current reaction type for the user
	DB.QueryRow("SELECT reaction_type FROM Reactions WHERE post_id = ? AND user_id = ?", reactionData.PostID, userID).Scan(&currentReaction)

	// Update the reaction
	if currentReaction == "" {
		// Insert a new reaction
		_, err = DB.Exec(
			"INSERT INTO Reactions (post_id, user_id, reaction_type) VALUES (?, ?, ?)",
			reactionData.PostID, userID, reactionData.ReactionType,
		)
	} else if currentReaction != reactionData.ReactionType {
		// Update the reaction type
		_, err = DB.Exec(
			"UPDATE Reactions SET reaction_type = ? WHERE post_id = ? AND user_id = ?",
			reactionData.ReactionType, reactionData.PostID, userID,
		)
	} else if currentReaction == reactionData.ReactionType {
		// Delete the reaction if it's the same as the current reaction
		_, err = DB.Exec(
			"DELETE FROM Reactions WHERE post_id = ? AND user_id = ?", reactionData.PostID, userID,
		)
	}

	if err != nil {
		http.Error(w, "Failed to update reaction", http.StatusInternalServerError)
		return
	}

	// Get the likes and dislikes count for the post
	var likes, dislikes int
	DB.QueryRow("SELECT COUNT(*) FROM Reactions WHERE post_id = ? AND reaction_type = 'LIKE'", reactionData.PostID).Scan(&likes)
	DB.QueryRow("SELECT COUNT(*) FROM Reactions WHERE post_id = ? AND reaction_type = 'DISLIKE'", reactionData.PostID).Scan(&dislikes)

	// Return the updated counts
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"likes":    likes,
		"dislikes": dislikes,
	})
}

// CommentReact handles a POST request to update a user's reaction to a comment.
// The request body should contain the comment_id and reaction_type.
// The reaction_type can be either "LIKE" or "DISLIKE".
// The function returns a JSON response with the updated counts of likes and dislikes.
func CommentReact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Decode request body
	var CommentReact struct {
		CommentID    string `json:"comment_id"`   // The ID of the comment being reacted to.
		ReactionType string `json:"reaction_type"` // The type of reaction, either "LIKE" or "DISLIKE".
	}

	if err := json.NewDecoder(r.Body).Decode(&CommentReact); err != nil {
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
		http.Error(w, "Failed to update reaction", http.StatusInternalServerError)
		return
	}

	var currentReaction string
	// Get the current reaction type for the user
	DB.QueryRow("SELECT reaction_type FROM CommentReactions WHERE comment_id = ? AND user_id = ?", CommentReact.CommentID, userID).Scan(&currentReaction)

	if currentReaction == "" {
		// Insert a new reaction
		_, err = DB.Exec(
			"INSERT INTO CommentReactions (comment_id, user_id, reaction_type) VALUES (?, ?, ?)",
			CommentReact.CommentID, userID, CommentReact.ReactionType,
		)
	} else if currentReaction != CommentReact.ReactionType {
		// Update the reaction type
		_, err = DB.Exec(
			"UPDATE CommentReactions SET reaction_type = ? WHERE comment_id = ? AND user_id = ?",
			CommentReact.ReactionType, CommentReact.CommentID, userID,
		)
	} else if currentReaction == CommentReact.ReactionType {
		// Delete the reaction if it's the same as the current reaction
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

	// Return the updated counts
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"likes":    likes,
		"dislikes": dislikes,
	})
}
