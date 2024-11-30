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
	Tpl = template.Must(template.ParseGlob("templates/*.html"))
}

func InitDB() error {
	var err error
	DB, err = sql.Open("sqlite3", "./forum.db")
	return err
}

func GetUserInfo(userID string) (utils.User, error) {
	row := DB.QueryRow(`SELECT user_id, username, email, fullname, created_at FROM Users WHERE user_id = ?`, userID)

	var user utils.User
	if err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Fullname, &user.Created_at); err != nil {
		if err == sql.ErrNoRows {
			return utils.User{}, fmt.Errorf("no user found with Id: %s", userID)
		}
		return utils.User{}, err
	}
	return user, nil
}
