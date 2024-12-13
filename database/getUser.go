package database

import (
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// GetUser gets a user from the database by email and checks the password.
// It returns an error if the user does not exist or the password is incorrect.
func GetUser(email, password string) (string, error) {
	// Query the database for the user's hashed password
	var hashedPassword string
	var userId string
	err := DB.QueryRow("SELECT user_id, password FROM Users WHERE email = ?", email).Scan(&userId, &hashedPassword)
	if err == sql.ErrNoRows {
		// If the user does not exist, return an error
		return "", fmt.Errorf("no user with this email")
	} else if err != nil {
		// If there was an error querying the database, return an error
		return "", err
	}

	// Check the password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		// If the password is incorrect, return an error
		return "", fmt.Errorf("incorrect password")
	}

	// If everything is good, return the user's ID
	return userId, nil
}
