package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"forum_full/database"
	"forum_full/utils"
)


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
		if err := database.Tpl.ExecuteTemplate(w, "register.html", nil); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
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

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	default:
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
		var user utils.User
		user.Email = r.FormValue("email")
		user.Password = r.FormValue("password")

		userID, err := database.GetUser(user.Email, user.Password)
		if err != nil {
			database.Tpl.ExecuteTemplate(w, "login.html", utils.Errors{ErrorType: err.Error()})
			return
		}

		//check if the user is aleardy have an oppened session
		for key, value := range database.Sessions {
			if value == userID {
				delete(database.Sessions, key)
			}
		}
		utils.DeleteAllCookies(w, r)

		sessionID, err := utils.GenerateSessionID()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

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
