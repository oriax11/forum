package forum_full


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
	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Categories, &post.CreatedAt, &post.Username); err != nil {
			return nil, err
		}
		db.QueryRow("SELECT COUNT(*) FROM Reactions where reaction_type = ? AND post_id = ?", "LIKE", post.ID).Scan(&post.Likes)
		db.QueryRow("SELECT COUNT(*) FROM Reactions where reaction_type = ? AND post_id = ?", "DISLIKE", post.ID).Scan(&post.Dislikes)
		db.QueryRow("SELECT COUNT(*) FROM Comment WHERE post_id = ?", post.ID).Scan(&post.Comments_counter)

		// Get comments for each post
		commentRows, err := db.Query(`SELECT comment_id ,username , comment_content, comment_date
									  FROM Comment WHERE post_id = ?
									  ORDER BY comment_date ASC`, post.ID)
		if err != nil {
			return nil, err
		}
		defer commentRows.Close()

		var comments []Comment
		for commentRows.Next() {
			var comment Comment
			if err := commentRows.Scan(&comment.Id, &comment.Author, &comment.Content, &comment.Creation); err != nil {
				return nil, err
			}
			comments = append(comments, comment)
		}
		post.Comments = comments

		post.TimeAgo = AboutTime(post.CreatedAt)
		posts = append(posts, post)
	}
	return posts, nil
}
