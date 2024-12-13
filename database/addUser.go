package database

import (
	"strings"

	"forum_full/utils"

	"golang.org/x/crypto/bcrypt"
)

// AddUser adds a new user to the database. It takes a utils.User object as an argument.
// It first generates a hashed password from the user's password, then inserts the user
// into the database. If the username already exists in the database, it returns an error.
func AddUser(user utils.User) error {
	// Generate a hashed password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		// Return the error if something goes wrong
		return err
	}

	// Insert the user into the database
	_, err = DB.Exec("INSERT INTO Users (username, email, fullname, password) VALUES (?, ?, ?, ?)",
		user.Username, user.Email, user.Fullname, string(hashedPassword))
	if err != nil {
		// If the username already exists in the database, return an error
		if strings.Contains(err.Error(), "UNIQUE constraint failed: Users.username") {
			return err
		}
		// Return the error if something goes wrong
		return err
	}
	// Otherwise, return nil
	return nil
}
