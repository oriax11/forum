package database

import (
	"database/sql"
	"fmt"
	"html/template"

	"forum_full/utils"

	_ "github.com/mattn/go-sqlite3"
)

var (
	Sessions = make(map[string]string) 
	DB       *sql.DB
	Tpl      *template.Template
)

func init() {
	Tpl = template.Must(template.ParseGlob("templates/*.html"))
}

func InitDB() error {
	var err error
	DB, err = sql.Open("sqlite3", "./forum.db")
	return err
}

// GetUserInfo retrieves a user from the database by ID and returns the user object.
// If the user does not exist, it returns an error.
func GetUserInfo(userID string) (utils.User, error) {
	// Query the database for the user
	row := DB.QueryRow(`SELECT user_id, username, email, fullname, created_at FROM Users WHERE user_id = ?`, userID)

	var user utils.User
	if err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Fullname, &user.Created_at); err != nil {
		// If the user does not exist, return an error
		if err == sql.ErrNoRows {
			return utils.User{}, fmt.Errorf("no user found with ID: %s", userID)
		}
		// If there was an error querying the database, return an error
		return utils.User{}, err
	}

	// Return the user object
	return user, nil
}
