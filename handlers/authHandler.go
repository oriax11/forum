package handlers

import (
	"fmt"
	"net/http"
	"strings"

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
	if cookie, err := r.Cookie("session_token"); err == nil {
		if _, sessionExists := database.Sessions[cookie.Value]; !sessionExists {
			utils.DeleteAllCookies(w, r)
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Render the register.html template
		if err := database.Tpl.ExecuteTemplate(w, "register.html", nil); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
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
		user.Email = strings.TrimSpace(r.FormValue("email"))
		user.Fullname = strings.TrimSpace(r.FormValue("fullname"))
		user.Password = r.FormValue("password")

		// Check if the user credentials are valid
		if err := utils.CheckCredentials(user); err != "" {
			database.Tpl.ExecuteTemplate(w, "register.html", utils.Errors{ErrorType: err})
			return
		}

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

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session_token"); err == nil {
		if _, sessionExists := database.Sessions[cookie.Value]; !sessionExists {
			utils.DeleteAllCookies(w, r)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	switch r.Method {
	case http.MethodGet:
		err := database.Tpl.ExecuteTemplate(w, "login.html", nil)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		action := r.FormValue("query")
		if action != "login" {
			http.Error(w, "Bad request\nHmmm, it looks like you are lost!!", http.StatusBadRequest)
			return
		}

		var user utils.User
		user.Email = r.FormValue("email")
		user.Password = r.FormValue("password")

		if err := database.GetUser(user.Email, user.Password); err != nil {
			database.Tpl.ExecuteTemplate(w, "login.html", utils.Errors{ErrorType: err.Error()})
			return
		}

		for key, value := range database.Sessions {
			if value == user.Email {
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
		database.DB.QueryRow("SELECT user_id FROM Users WHERE email = ?", user.Email).Scan(&userID)
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
