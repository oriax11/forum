package database

import (
	"database/sql"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// GetUser gets a user from the database by email and checks the password.
// It returns an error if the user does not exist or the password is incorrect.
func GetUser(email, password string) error {
	var hashedPassword string

	// Query the database for the user with the given email and get the hashed password
	err := DB.QueryRow("SELECT password FROM Users WHERE email = ?", email).Scan(&hashedPassword)
	if err == sql.ErrNoRows {
		// If no rows were found, return an error
		return fmt.Errorf("no user with this email")
	} else if err != nil {
		// If the query failed, return the error
		return err
	}

	// Compare the given password with the hashed password from the database
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		// If the password is incorrect, return an error
		return fmt.Errorf("incorrect password")
	}

	return nil
}

