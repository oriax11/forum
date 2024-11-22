package forum_full

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
)

func HandleFormSubmission(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("query")

	if action == "newpost" {
		_, err := r.Cookie("Guest_token")
		if err == nil {
			erro := Errors{
				ErrorType: "Please Log in to post posts!",
			}
			tpl.ExecuteTemplate(w, "login.html", erro)
			return
		}

		userID := 1

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		title := r.FormValue("title")
		content := r.FormValue("content")
		category_type := r.Form["type"]

		Allcategories := strings.Join(category_type, " ")
		// category_content := "#" + strings.Join(category_type, " #")
		// fmt.Println(category_content)
		// fmt.Println(category_type, "hello")

		if len(title) > 150 {
			http.Error(w, "Post title cannot exceed 150 characters.", http.StatusBadRequest)
			return
		}
		if len(content) > 3000 {
			http.Error(w, "Post content cannot exceed 3000 characters.", http.StatusBadRequest)
			return
		}

		cookie, _ := r.Cookie("session_token")
		email := sessions[cookie.Value]

		if len(category_type) == 0 {
			http.Error(w, "category cannot be emty", http.StatusBadRequest)
			return
		}
		if title == "" || content == "" {
			http.Error(w, "Title and content cannot be empty", http.StatusBadRequest)
			return
		}

		db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&userID)

		_, err = db.Exec(
			"INSERT INTO Posts (user_id, title, content, categories) VALUES (?, ?, ?, ?)",
			userID, title, content, Allcategories,
		)
		if err != nil {
			http.Error(w, "Post creation failed", http.StatusInternalServerError)
			return
		}

	} else if action == "react" {
		var userID int

		_, err := r.Cookie("Guest_token")
		if err == nil {
			erro := Errors{
				ErrorType: "Only registred Users can react!",
			}
			tpl.ExecuteTemplate(w, "login.html", erro)
			return
		}

		cookie, _ := r.Cookie("session_token")
		email := sessions[cookie.Value]

		db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&userID)

		like_btn := r.FormValue("like-btn")
		dislike_btn := r.FormValue("dislike-btn")
		post_id := r.FormValue("post_id")
		var react_holder string
		var reaction_type string

		if len(like_btn) == 0 && len(dislike_btn) > 0 {
			react_holder = dislike_btn
		} else if len(like_btn) > 0 && len(dislike_btn) == 0 {
			react_holder = like_btn
		}

		db.QueryRow("SELECT reaction_type FROM Reactions WHERE post_id = ? AND user_id = ?", post_id, userID).Scan(&reaction_type)

		if len(reaction_type) == 0 {
			_, err = db.Exec(
				"INSERT INTO Reactions (post_id ,user_id, reaction_type) VALUES (?, ?, ?)",
				post_id, userID, react_holder,
			)
			if err != nil {
				fmt.Print(err, "insert")
				http.Error(w, "Post creation failed", http.StatusInternalServerError)
				return
			}
		} else {
			if react_holder == reaction_type {
				_, err = db.Exec(
					"DELETE FROM Reactions WHERE post_id = ? AND user_id = ?",
					post_id, userID,
				)
				if err != nil {
					fmt.Print(err, "Delete")
					http.Error(w, " Failed to remove reaction", http.StatusInternalServerError)
					return
				}
			} else {
				_, err = db.Exec(
					"UPDATE Reactions SET reaction_type = ? WHERE post_id = ? AND user_id = ?",
					react_holder, post_id, userID,
				)
				if err != nil {
					fmt.Print(err, "Update")
					http.Error(w, "Post creation failed", http.StatusInternalServerError)
					return
				}
			}
		}
		fmt.Println(react_holder, post_id, userID)

	} else if action == "comment_react" {
		var userID int

		_, err := r.Cookie("Guest_token")
		if err == nil {
			erro := Errors{
				ErrorType: "Only registered Users can react!",
			}
			tpl.ExecuteTemplate(w, "login.html", erro)
			return
		}

		cookie, _ := r.Cookie("session_token")
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

	} else if action == "comment" {
		var username string
		comment_content := r.FormValue("comment-content")
		post_id := r.FormValue("post_id")
		_, err := r.Cookie("Guest_token")
		if err == nil {
			erro := Errors{
				ErrorType: "Only registred Users can react!",
			}
			tpl.ExecuteTemplate(w, "login.html", erro)
			return
		}

		cookie, _ := r.Cookie("session_token")
		email := sessions[cookie.Value]

		db.QueryRow("SELECT username FROM Users WHERE email = ?", email).Scan(&username)

		if len(comment_content) > 0 {
			_, err = db.Exec(
				"INSERT INTO Comment (post_id ,username, comment_content) VALUES (?, ?, ?)",
				post_id, username, comment_content,
			)
			if err != nil {
				fmt.Print(err, "insert")
				http.Error(w, "Post creation failed", http.StatusInternalServerError)
				return
			}
		} else {
			fmt.Print("empty string")
		}
	} else if action == "Liked" {
		var id string
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		}
		email := sessions[cookie.Value]

		db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&id)
		rows, err := db.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
						   FROM Posts p
						   JOIN Users u ON p.user_id = u.user_id
		JOIN Reactions r ON p.post_id = r.post_id
		WHERE r.reaction_type = 'LIKE' AND r.user_id=?`, id)
		if err != nil {
			http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		}
		defer rows.Close()
		posts, err := Getcontent(rows)
		if err != nil {
			http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		}
		userInfo, err := Userinfo(email)
		if err != nil {
			http.Error(w, "Failed to load user info", http.StatusInternalServerError)
			return
		}

		data := struct {
			P       []Post
			Message string
		}{
			P:       posts,
			Message: userInfo.Username,
		}

		err = tpl.ExecuteTemplate(w, "forum.html", data)
		if err != nil {
			fmt.Println(err)
			http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
		}
		return
	} else if action == "created" {
		var id string
		cookie, _ := r.Cookie("session_token")
		email := sessions[cookie.Value]

		db.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&id)
		rows, _ := db.Query(`SELECT p.post_id, p.title, p.content, p.categories, p.created_at, u.username
						   FROM Posts p
						   JOIN Users u ON p.user_id = u.user_id
						   WHERE u.user_id = ? `, id)

		defer rows.Close()
		posts, err := Getcontent(rows)
		if err != nil {
			http.Error(w, "Failed to load Posts", http.StatusInternalServerError)
		}
		userInfo, err := Userinfo(email)
		if err != nil {
			http.Error(w, "Failed to load user info", http.StatusInternalServerError)
			return
		}


		data := struct {
			P       []Post
			Message string
		}{
			P:       posts,
			Message: userInfo.Username,
		}

		err = tpl.ExecuteTemplate(w, "forum.html", data)
		if err != nil {
			fmt.Println(err)
			http.Error(w, "Error rendering the forum page", http.StatusInternalServerError)
		}

		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
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
