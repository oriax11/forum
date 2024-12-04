package database

import (
	"database/sql"
	"fmt"

	"forum_full/utils"
)

// GetPosts retrieves all posts from the database.
//
// It returns a slice of Post objects containing all the posts from the database.
func GetPosts(limit, offset int) ([]utils.Post, error) {
	// Query the database with LIMIT and OFFSET
	rows, err := DB.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
						   FROM Posts p
						   JOIN Users u ON p.user_id = u.user_id
						   ORDER BY p.created_at DESC
						   LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		// If there is an error querying the database, return it
		return nil, err
	}
	defer rows.Close()
	
	var posts []utils.Post

	// Call the helper function to get the post content
	posts, err = Getcontent(rows)
	if err != nil {
		// If there is an error getting the post content, return it
		return nil, err
	}
	return posts, nil
}


func Getcontent(rows *sql.Rows) ([]utils.Post, error) {
	var posts []utils.Post
	for rows.Next() {
		var post utils.Post
		if err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Categories, &post.CreatedAt, &post.Username); err != nil {
			return nil, fmt.Errorf("failed to scan post: %w", err)
		}

		// Get post reactions
		if err := DB.QueryRow("SELECT COUNT(*) FROM Reactions WHERE reaction_type = ? AND post_id = ?", "LIKE", post.ID).Scan(&post.Likes); err != nil {
			return nil, fmt.Errorf("failed to get post likes: %w", err)
		}

		if err := DB.QueryRow("SELECT COUNT(*) FROM Reactions WHERE reaction_type = ? AND post_id = ?", "DISLIKE", post.ID).Scan(&post.Dislikes); err != nil {
			return nil, fmt.Errorf("failed to get post dislikes: %w", err)
		}

		if err := DB.QueryRow("SELECT COUNT(*) FROM Comment WHERE post_id = ?", post.ID).Scan(&post.Comments_counter); err != nil {
			return nil, fmt.Errorf("failed to get comments count: %w", err)
		}

		// Get comments for each post
		commentRows, err := DB.Query(`SELECT comment_id, username, comment_content, comment_date 
                                    FROM Comment WHERE post_id = ?
                                    ORDER BY comment_date DESC`, post.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to query comments: %w", err)
		}
		defer commentRows.Close()

		var comments []utils.Comment
		for commentRows.Next() {
			var comment utils.Comment
			if err := commentRows.Scan(&comment.ID, &comment.Author, &comment.Content, &comment.Creation); err != nil {
				return nil, fmt.Errorf("failed to scan comment: %w", err)
			}

			// Get comment reactions
			if err := DB.QueryRow("SELECT COUNT(*) FROM CommentReactions WHERE reaction_type = ? AND comment_id = ?", "LIKE", comment.ID).Scan(&comment.Likes); err != nil {
				return nil, fmt.Errorf("failed to get comment likes: %w", err)
			}

			if err := DB.QueryRow("SELECT COUNT(*) FROM CommentReactions WHERE reaction_type = ? AND comment_id = ?", "DISLIKE", comment.ID).Scan(&comment.Dislikes); err != nil {
				return nil, fmt.Errorf("failed to get comment dislikes: %w", err)
			}

			comment.TimeAgo_com = utils.AboutTime(comment.Creation)
			comments = append(comments, comment)
		}

		// Check for errors from iterating over commentRows
		if err := commentRows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating comment rows: %w", err)
		}

		post.Comments = comments
		post.TimeAgo = utils.AboutTime(post.CreatedAt)
		posts = append(posts, post)
	}

	// Check for errors from iterating over rows
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating post rows: %w", err)
	}

	return posts, nil
}
