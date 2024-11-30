package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"forum_full/database"
	"forum_full/utils"

	"golang.org/x/crypto/bcrypt"
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

		username := r.FormValue("username")
		email := r.FormValue("email")
		fullname := r.FormValue("fullname")
		password := r.FormValue("password")

		if len(username) > 20 {
			erro := utils.Errors{
				ErrorType: "Username cannot exceed 20 characters.",
			}
			database.Tpl.ExecuteTemplate(w, "register.html", erro)
			return
		}
		if len(password) < 8 {
			erro := utils.Errors{
				ErrorType: "Password cannot be less than 8 characters.",
			}
			database.Tpl.ExecuteTemplate(w, "register.html", erro)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error processing password", http.StatusInternalServerError)
			return
		}

		_, err = database.DB.Exec("INSERT INTO Users (username, email, fullname, password) VALUES (?, ?, ?, ?)",
			username, email, fullname, string(hashedPassword))
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed: Users.username") {
				erro := utils.Errors{
					ErrorType: "Username already exists",
				}
				database.Tpl.ExecuteTemplate(w, "register.html", erro)
				return
			}
			http.Error(w, "User registration failed", http.StatusInternalServerError)
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

		type Cred struct {
			HashedPassword string
		}
		var cred Cred
		err := database.DB.QueryRow("SELECT password FROM Users WHERE email = ?", email).Scan(&cred.HashedPassword)
		if err == sql.ErrNoRows {
			erro := utils.Errors{
				ErrorType: "No user with this email!",
			}
			database.Tpl.ExecuteTemplate(w, "login.html", erro)
			return
		} else if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(cred.HashedPassword), []byte(password))
		if err != nil {
			erro := utils.Errors{
				ErrorType: "Incorrect password!",
			}
			database.Tpl.ExecuteTemplate(w, "login.html", erro)
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

		database.Sessions[sessionID] = email
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
