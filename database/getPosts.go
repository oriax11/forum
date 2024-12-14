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
	Offset      int
	HasNext     bool
	HasPrevious bool
	Next        int
	Previous    int
}

// GetPosts retrieves all posts from the database.
// It returns a slice of Post objects containing all the posts from the database.
// The function takes a http.Request object as an argument and uses it to
// determine the pagination parameters such as page size and offset.
func GetPosts(r *http.Request) ([]utils.Post, *Pagination, error) {
	// Get the total number of posts in the database
	var totalPosts int
	if err := DB.QueryRow("SELECT COUNT(*) FROM Posts").Scan(&totalPosts); err != nil {
		return nil, nil, fmt.Errorf("failed to get total posts count: %w", err)
	}

	// Get pagination parameters from the request
	pagination := GetPagination(r, totalPosts)

	// Query the database with LIMIT and OFFSET
	rows, err := DB.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
						   FROM Posts p
						   JOIN Users u ON p.user_id = u.user_id
						   ORDER BY p.created_at DESC
						   LIMIT ? OFFSET ?`, pagination.PageSize, pagination.Offset)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query posts: %w", err)
	}
	defer rows.Close()

	// Get the posts content from the rows
	posts, err := Getcontent(rows)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get posts content: %w", err)
	}

	return posts, pagination, nil
}

// Getcontent retrieves the content of the posts from the database
// It takes a pointer to a sql.Rows object as an argument and returns a slice of Post objects
// The function also returns an error if any of the database operations fail
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

func GetPagination(r *http.Request, totalPosts int) *Pagination {
	// Default values
	currentPage := 1
	pageSize := 10
	totalPages := (totalPosts + pageSize -1 ) / pageSize

	// Parse the "page" query parameter
	if page, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && page > 0 && page <= totalPages {
		currentPage = page
	}

	// Calculate offset
	offset := (currentPage - 1) * pageSize

	// Calculate Previous and Next page
	previousPage := 0
	if currentPage > 1 {
		previousPage = currentPage - 1
	}

	nextPage := 0
	if currentPage < totalPages {
		nextPage = currentPage + 1
	}

	return &Pagination{
		CurrentPage: currentPage,
		PageSize:    pageSize,
		Offset:      offset,
		HasNext:     currentPage < totalPages,
		HasPrevious: currentPage > 1,
		Next:        nextPage,
		Previous:    previousPage,
	}
}



