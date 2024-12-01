package handlers

import (
	"fmt"
	"net/http"

	"forum_full/database"
	"forum_full/utils"
)

// Register Handler
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
		err := database.Tpl.ExecuteTemplate(w, "register.html", nil)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}

	case http.MethodPost:
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

		if len(user.Username) > 20 {
			erro := utils.Errors{
				ErrorType: "Username cannot exceed 20 characters.",
			}
			database.Tpl.ExecuteTemplate(w, "register.html", erro)
			return
		}
		if len(user.Password) < 8 {
			erro := utils.Errors{
				ErrorType: "Password cannot be less than 8 characters.",
			}
			database.Tpl.ExecuteTemplate(w, "register.html", erro)
			return
		}

		// Add user to database
		err := database.AddUser(user)
		if err != nil {
			err := utils.Errors{
				ErrorType: "User alrready Exist",
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
		utils.SetCookies(w, sessionID, "session_token")

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
