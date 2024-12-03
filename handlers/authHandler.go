package handlers

import (
	"fmt"
	"net/http"
	"regexp"

	"forum_full/database"
	"forum_full/utils"
)

// RegisterHandler handles a request to the /register endpoint. It checks if the
// user is already logged in and redirects them to the home page if they are.
// If the request is a GET request, it renders the register.html template. If the
// request is a POST request, it validates the form data and adds the user to the
// database. If the user already exists, it renders the register.html template with
// an error message.
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		sessionID := cookie.Value
		email, sessionExists := database.Sessions[sessionID]
		if sessionExists && email != "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		// Render the register.html template
		err := database.Tpl.ExecuteTemplate(w, "register.html", nil)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}

	case http.MethodPost:
		// Validate the form data
		action := r.FormValue("query")
		if action != "reg" {
			http.Error(w, "Bad request\nHmmm, it looks like you are lost!!", http.StatusBadRequest)
			return
		}
		var user utils.User
		user.Username = r.FormValue("username")
		user.Email = r.FormValue("email")
		user.Fullname = r.FormValue("fullname")
		user.Password = r.FormValue("password")

		// Check if the user credentials are valid
		CheckCredentials(user, w)

		// Add the user to the database
		err := database.AddUser(user)
		if err != nil {
			err := utils.Errors{
				ErrorType: "User already Exist",
			}
			database.Tpl.ExecuteTemplate(w, "register.html", err)
			return
		}

		// Redirect the user to the login page
		http.Redirect(w, r, "/login", http.StatusSeeOther)

	default:
		// Method Not Allowed
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// CheckCredentials checks if the user credentials are valid. It checks if the
// username length is greater than 15 characters, and if the password length is
// less than 8 characters or greater than 32 characters. If the user credentials
// are invalid, it renders the register.html template with an error message.
func CheckCredentials(user utils.User, w http.ResponseWriter) {
	if len(user.Username) > 15 {
		erro := utils.Errors{
			ErrorType: "Username cannot exceed 15 characters.",
		}
		database.Tpl.ExecuteTemplate(w, "register.html", erro)
		return
	}
	if len(user.Password) < 8 || len(user.Password) > 32 {
		erro := utils.Errors{
			ErrorType: "Password cannot be less than 8 characters.",
		}
		database.Tpl.ExecuteTemplate(w, "register.html", erro)
		return
	}
	// check Password Format
	// regPassword := regexp.MustCompile(`[a-zA-Z]*\d*[@$!%*?&]*`)
	// if !regPassword.MatchString(user.Password) {
	// 	err := utils.Errors{
	// 		ErrorType: `Must be at least :
	// 		1 lower case
	// 		1 upper case
	// 		1 Number
	// 		1 special character (@$!%*?&)`,
	// 	}
	// 	database.Tpl.ExecuteTemplate(w, "register.html", err)
	// 	return
	// }

	// check email Format
	regEmail := regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]{3,4}$`)
	if !regEmail.MatchString(user.Email) {
		err := utils.Errors{
			ErrorType: "Email Format Incorrect Try Again",
		}
		database.Tpl.ExecuteTemplate(w, "register.html", err)
		return
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("session_token")
	if err == nil {
		cookie, err := r.Cookie("session_token")
		if err == nil {
			sessionID := cookie.Value
			email, sessionExists := database.Sessions[sessionID]

			if !sessionExists || email == "" {
				utils.DeleteAllCookies(w, r)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		err := database.Tpl.ExecuteTemplate(w, "login.html", nil)
		if err != nil {
			fmt.Println("login template error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}

	case http.MethodPost:
		action := r.FormValue("query")
		if action != "login" {
			http.Error(w, "Bad request\nHmmm, it looks like you are lost!!", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		err := database.GetUser(email, password)
		if err != nil {
			err := utils.Errors{
				ErrorType: err.Error(),
			}
			database.Tpl.ExecuteTemplate(w, "login.html", err)
			return
		}

		for key, value := range database.Sessions {
			if value == email {
				delete(database.Sessions, key)
			}
		}
		utils.DeleteAllCookies(w, r)

		sessionID, err := utils.GenerateSessionID()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		var userID string
		database.DB.QueryRow("SELECT user_id FROM Users WHERE email = ?", email).Scan(&userID)

		database.Sessions[sessionID] = userID
		utils.SetCookies(w, sessionID, "session_token", true)

		fmt.Println("Successfully logged in")
		http.Redirect(w, r, "/", http.StatusSeeOther)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// Logout Handler
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	utils.DeleteAllCookies(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
