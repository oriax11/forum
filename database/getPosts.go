package database

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"

	"forum_full/utils"
)

type Pagination struct {
	CurrentPage int
	PageSize    int
	OffSet      int
	HasPrevious bool
	HasNext     bool
	PrevPage    string
	NextPage    string
}

// GetPosts retrieves all posts from the database.
// It returns a slice of Post objects containing all the posts from the database.
func GetPosts(r *http.Request) ([]utils.Post, *Pagination, error) {
	var totalPosts int
	if err := DB.QueryRow("SELECT COUNT(*) FROM Posts").Scan(&totalPosts); err != nil {
		return nil, nil, fmt.Errorf("failed to get total posts count")
	}

	pagination := GetPagination(r, totalPosts, "?")

	// Query the database with LIMIT and OFFSET
	rows, err := DB.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
						   FROM Posts p
						   JOIN Users u ON p.user_id = u.user_id
						   ORDER BY p.created_at DESC
						   LIMIT ? OFFSET ?`, pagination.PageSize, pagination.OffSet)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	posts, err := Getcontent(rows)
	if err != nil {
		return nil, nil, err
	}

	return posts, pagination, nil
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

// GetPagination extracts pagination parameters
func GetPagination(r *http.Request, totalPosts int, url string) (*Pagination) {
	currentPage := 1
	pageSize := 2
	totalPages := (totalPosts + pageSize - 1) / pageSize

	if page, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && page > 0 && page <= totalPages {
		currentPage = page
	}

	offset := (currentPage - 1) * pageSize

	return &Pagination{
		CurrentPage: currentPage,
		PageSize:    pageSize,
		OffSet:      offset,
		HasNext:     currentPage < totalPages,
		HasPrevious: currentPage > 1,
		PrevPage:    fmt.Sprintf("/%spage=%v", url, currentPage-1),
		NextPage:    fmt.Sprintf("/%spage=%v", url, currentPage+1),
	}
}
