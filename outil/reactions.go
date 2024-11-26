package forum_full

import (
	"encoding/json"
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

	email := sessions[sessionCookie.Value]
	var userID int
	if err := db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&userID); err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	var currentReaction string
	db.QueryRow("SELECT reaction_type FROM Reactions WHERE post_id = ? AND user_id = ?", reactionData.PostID, userID).Scan(&currentReaction)

	if currentReaction == "" {
		_, err = db.Exec(
			"INSERT INTO Reactions (post_id, user_id, reaction_type) VALUES (?, ?, ?)",
			reactionData.PostID, userID, reactionData.ReactionType,
		)
	} else if currentReaction != reactionData.ReactionType {
		_, err = db.Exec(
			"UPDATE Reactions SET reaction_type = ? WHERE post_id = ? AND user_id = ?",
			reactionData.ReactionType, reactionData.PostID, userID,
		)
	} else if currentReaction == reactionData.ReactionType {
		_, err = db.Exec(
			"DELETE FROM Reactions WHERE post_id = ? AND user_id = ?", reactionData.PostID, userID,
		)
	}

	if err != nil {
		http.Error(w, "Failed to update reaction", http.StatusInternalServerError)
		return
	}

	var likes, dislikes int
	db.QueryRow("SELECT COUNT(*) FROM Reactions WHERE post_id = ? AND reaction_type = 'LIKE'", reactionData.PostID).Scan(&likes)
	db.QueryRow("SELECT COUNT(*) FROM Reactions WHERE post_id = ? AND reaction_type = 'DISLIKE'", reactionData.PostID).Scan(&dislikes)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"likes":    likes,
		"dislikes": dislikes,
	})
}
