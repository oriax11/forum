package forum_full

import "time"

type Errors struct {
	ErrorType string
}

type User struct {
	ID         int
	Username   string
	Email      string
	Fullname   string
	Created_at string
}

type Comment struct {
	Id       int
	Content  string
	Author   string
	Creation time.Time
	TimeAgo_com   string
}

type Post struct {
	ID             int
	UserID         int
	Title          string
	Content        string
	Username       string
	Categories string
	CreatedAt      time.Time
	TimeAgo        string
	Likes		int
	Dislikes	int
	Comments_counter int
	Comments       []Comment
}

