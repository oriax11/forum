package database

import (
	"database/sql"
	"fmt"
	"html/template"

	"forum_full/utils"

	_ "github.com/mattn/go-sqlite3"
)

var (
	Sessions = make(map[string]string) // session store with sessionID to email mapping sessions = make(map[string]string) // session store with sessionID to email mapping
	DB       *sql.DB
	Tpl      *template.Template
)

func init() {
	Tpl = template.Must(template.New("").Funcs(template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
	}).ParseGlob("templates/*.html"))
}

func InitDB() error {
	var err error
	DB, err = sql.Open("sqlite3", "./forum.db")
	return err
}

// GetUserInfo retrieves a user from the database by ID
func GetUserInfo(userID string) (utils.User, error) {
	// Query the database for the user with the given ID
	row := DB.QueryRow(`SELECT user_id, username, email, fullname, created_at FROM Users WHERE user_id = ?`, userID)

	var user utils.User
	// Scan the row into the user struct
	if err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Fullname, &user.Created_at); err != nil {
		// If no rows were found, return an error
		if err == sql.ErrNoRows {
			return utils.User{}, fmt.Errorf("no user found with ID: %s", userID)
		}
		// Otherwise, return the error
		return utils.User{}, err
	}
	// Return the user without error
	return user, nil
}
