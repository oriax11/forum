package forum_full

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
)

func PostComment(w http.ResponseWriter, r *http.Request) {
    // Validate request method
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    // Decode request body
    var CommentData struct {
        PostID  string `json:"post_id"`
        Content string `json:"comment-content"`
    }
    if err := json.NewDecoder(r.Body).Decode(&CommentData); err != nil {
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
    email := sessions[sessionCookie.Value]
    var username string
    err = db.QueryRow("SELECT username FROM Users WHERE email = ?", email).Scan(&username)
    if err != nil {
        http.Error(w, "User not found", http.StatusUnauthorized)
        return
    }

    // Validate comment content
    if CommentData.Content == "" {
        http.Error(w, "Comment cannot be empty", http.StatusBadRequest)
        return
    }

    // Insert comment
    _, err = db.Exec(
        "INSERT INTO Comment (post_id, username, comment_content) VALUES (?, ?, ?)",
        CommentData.PostID, username, CommentData.Content,
    )
    if err != nil {
        http.Error(w, "Failed to insert comment", http.StatusInternalServerError)
        return
    }

    var commentID int
    var commentDate string
	db.QueryRow("SELECT LAST_INSERT_ID(), NOW()").Scan(&commentID, &commentDate)

	fmt.Println(commentDate, commentID)
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
        "comment": map[string]interface{}{
            "id": commentID,
            "username": username,
            "content": CommentData.Content,
            "date": commentDate,
        },
    })
}

func getPosts() ([]Post, error) {
	rows, err := db.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
						   FROM Posts p
						   JOIN Users u ON p.user_id = u.user_id
						   ORDER BY p.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var posts []Post

	posts, err = Getcontent(rows)
	if err != nil {
		return nil, err
	}
	return posts, nil
}

func Getcontent(rows *sql.Rows) ([]Post, error) {
	var posts []Post
	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Categories, &post.CreatedAt, &post.Username); err != nil {
			return nil, fmt.Errorf("failed to scan post: %w", err)
		}

		// Get post reactions
		if err := db.QueryRow("SELECT COUNT(*) FROM Reactions WHERE reaction_type = ? AND post_id = ?", "LIKE", post.ID).Scan(&post.Likes); err != nil {
			return nil, fmt.Errorf("failed to get post likes: %w", err)
		}

		if err := db.QueryRow("SELECT COUNT(*) FROM Reactions WHERE reaction_type = ? AND post_id = ?", "DISLIKE", post.ID).Scan(&post.Dislikes); err != nil {
			return nil, fmt.Errorf("failed to get post dislikes: %w", err)
		}

		if err := db.QueryRow("SELECT COUNT(*) FROM Comment WHERE post_id = ?", post.ID).Scan(&post.Comments_counter); err != nil {
			return nil, fmt.Errorf("failed to get comments count: %w", err)
		}

		// Get comments for each post
		commentRows, err := db.Query(`SELECT comment_id, username, comment_content, comment_date 
                                    FROM Comment WHERE post_id = ?
                                    ORDER BY comment_date ASC`, post.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to query comments: %w", err)
		}
		defer commentRows.Close()

		var comments []Comment
		for commentRows.Next() {
			var comment Comment
			if err := commentRows.Scan(&comment.ID, &comment.Author, &comment.Content, &comment.Creation); err != nil {
				return nil, fmt.Errorf("failed to scan comment: %w", err)
			}

			// Get comment reactions
			if err := db.QueryRow("SELECT COUNT(*) FROM CommentReactions WHERE reaction_type = ? AND comment_id = ?", "LIKE", comment.ID).Scan(&comment.Likes); err != nil {
				return nil, fmt.Errorf("failed to get comment likes: %w", err)
			}

			if err := db.QueryRow("SELECT COUNT(*) FROM CommentReactions WHERE reaction_type = ? AND comment_id = ?", "DISLIKE", comment.ID).Scan(&comment.Dislikes); err != nil {
				return nil, fmt.Errorf("failed to get comment dislikes: %w", err)
			}

			comment.TimeAgo_com = AboutTime(comment.Creation)
			comments = append(comments, comment)
		}

		// Check for errors from iterating over commentRows
		if err := commentRows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating comment rows: %w", err)
		}

		post.Comments = comments
		post.TimeAgo = AboutTime(post.CreatedAt)
		posts = append(posts, post)
	}

	// Check for errors from iterating over rows
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating post rows: %w", err)
	}

	return posts, nil
}
