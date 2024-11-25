package forum_full

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

func CommentReactions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		action := r.FormValue("query")
	if action == "comment_react" {
		var userID int

		_, err := r.Cookie("Guest_token")
		if err == nil {
			erro := Errors{
				ErrorType: "Only registered Users can react!",
			}
			w.WriteHeader(http.StatusForbidden)

			tpl.ExecuteTemplate(w, "login.html", erro)
			return
		}

		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		email := sessions[cookie.Value]

		db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&userID)

		like_btn := r.FormValue("like-btn")
		dislike_btn := r.FormValue("dislike-btn")
		comment_id := r.FormValue("comment_id")
		var react_holder string
		var reaction_type string

		if len(like_btn) == 0 && len(dislike_btn) > 0 {
			react_holder = dislike_btn
		} else if len(like_btn) > 0 && len(dislike_btn) == 0 {
			react_holder = like_btn
		}
		db.QueryRow("SELECT reaction_type FROM CommentReactions WHERE comment_id = ? AND user_id = ?", comment_id, userID).Scan(&reaction_type)

		if len(reaction_type) == 0 {
			_, err = db.Exec(
				"INSERT INTO CommentReactions (comment_id, user_id, reaction_type) VALUES ($1, $2, $3)",
				comment_id, userID, react_holder,
			)
			if err != nil {
				fmt.Print(err, "insert")
				http.Error(w, "Comment reaction failed", http.StatusInternalServerError)
				return
			}
		} else {
			if react_holder == reaction_type {
				_, err = db.Exec(
					"DELETE FROM CommentReactions WHERE comment_id = ? AND user_id = ?",
					comment_id, userID,
				)
				if err != nil {
					fmt.Print(err, "Delete")
					http.Error(w, "Failed to remove reaction", http.StatusInternalServerError)
					return
				}
			} else {
				_, err = db.Exec(
					"UPDATE CommentReactions SET reaction_type = ? WHERE comment_id = ? AND user_id = ?",
					react_holder, comment_id, userID,
				)
				if err != nil {
					fmt.Print(err, "Update")
					http.Error(w, "Failed to update reaction", http.StatusInternalServerError)
					return
				}
			}
		}
	}
	}else {
		http.Error(w, "method not allowed", 400)
		return
	}
}
