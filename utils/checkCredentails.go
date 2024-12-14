package utils

import "regexp"

// CheckCredentials checks if the user credentials are valid. It checks if the
// username length between 3 and 15 characters, and if the password length is
// between 8 and 32 characters. If the user credentials
// are invalid, it renders the register.html template with an error message.
func CheckCredentials(user User) string {
	// check if the credential are not empty.
	if user.Username == "" || user.Fullname == "" || user.Email == "" || user.Password == "" {
		return "All the credentials are requiared"
	}

	// check username
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{3,15}$`).MatchString(user.Username) || !regexp.MustCompile(`^[a-zA-Z0-9_-]{3,15}$`).MatchString(user.Fullname) {
		return "invalid full name or username format"
	}

	// check Password
	if len(user.Password) <= 8 || len(user.Password) > 32 {
		return "Password must be between 8 and 32 characters."
	}

	// check email Format
	if len(user.Email) < 6 || len(user.Email) > 50 {
		return "Password must be between 6 and 50 characters."
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9]+\.?[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-z]+$`).MatchString(user.Email) {
		return "invalid Email format"
	}

	return ""
}
