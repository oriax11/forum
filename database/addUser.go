package database

import (
	"strings"

	"forum_full/utils"

	"golang.org/x/crypto/bcrypt"
)

func AddUser(user utils.User) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = DB.Exec("INSERT INTO Users (username, email, fullname, password) VALUES (?, ?, ?, ?)",
		user.Username, user.Email, user.Fullname, string(hashedPassword))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: Users.username") {
			return err
		}
		return err
	}
	return nil
}
