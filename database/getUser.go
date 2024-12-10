package database

import (
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// GetUser gets a user from the database by email and checks the password.
// It returns an error if the user does not exist or the password is incorrect.
func GetUser(email, password string) (string, error) {
	var hashedPassword string
	var userId string
	err := DB.QueryRow("SELECT user_id, password FROM Users WHERE email = ?", email).Scan(&userId, &hashedPassword)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no user with this email")
	} else if err != nil {
		return "", err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return "", fmt.Errorf("incorrect password")
	}

	return userId, nil
}
