package database

import (
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func GetUser(email, password string) error {
	var hashedPassword string

	err := DB.QueryRow("SELECT password FROM Users WHERE email = ?", email).Scan(&hashedPassword)
	if err == sql.ErrNoRows {
		return fmt.Errorf("no user with this email")
	} else if err != nil {
		return err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return fmt.Errorf("incorrect password")
	}

	return nil
}
