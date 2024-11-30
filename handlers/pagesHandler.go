package handlers

import (
	"fmt"
	"net/http"
	"net/url"

	"forum_full/database"
)

// Profile Handler
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	email, exists := database.Sessions[cookie.Value]
	if !exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, err := database.GetUserInfo(email)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	err = database.Tpl.ExecuteTemplate(w, "profile.html", user)
	if err != nil {
		fmt.Println("Profile template error : ", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}
}

func ReportHandler(w http.ResponseWriter, r *http.Request) {
	// if r.Method == http.MethodGet {
	database.Tpl.ExecuteTemplate(w, "report.html", nil)
	// 	return
	// }
	if r.Method == http.MethodPost {
		// Parse the form data
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form data", http.StatusBadRequest)
			return
		}

		// Retrieve form values
		name := r.FormValue("Name")
		email := r.FormValue("email")
		message := r.FormValue("message")

		botToken := "7239461576:AAEPLw-vzHgPJtcN--EYMa9j5VNEe03uqxI"
		chatID := "1518093759"

		// Format the message
		text := fmt.Sprintf("Name: %s\nEmail: %s\nMessage: %s", name, email, message)

		// Send the message to Telegram
		apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
		data := url.Values{}
		data.Set("chat_id", chatID)
		data.Set("text", text)

		resp, err := http.PostForm(apiURL, data)
		if err != nil {
			http.Error(w, "Failed to send message to Telegram", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
	}
}

// 404 Handler
func NotFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	database.Tpl.ExecuteTemplate(w, "404.html", nil)
}
