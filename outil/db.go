package forum_full

import (
	"database/sql"
	"html/template"

	_ "github.com/mattn/go-sqlite3"
)

var (
	sessions = make(map[string]string) // session store with sessionID to email mapping sessions = make(map[string]string) // session store with sessionID to email mapping
	db       *sql.DB
	// err      error
	tpl *template.Template
)

func init() {
	tpl = template.Must(template.ParseGlob("templates/*.html"))
}

func InitDB() error {
	var err error
	db, err = sql.Open("sqlite3", "./forum.db")
	return err
}

func getUserInfo(email string) (User, error) {
	row := db.QueryRow(`SELECT user_id, username, email, fullname, created_at FROM Users WHERE email = ?`, email)
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Fullname, &user.Created_at)
	if err != nil {
		return User{}, err
	}
	return user, nil
}
