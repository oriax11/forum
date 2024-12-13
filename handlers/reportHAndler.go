package handlers

import (
	"fmt"
	"net/http"
	"net/url"

	"forum_full/database"
)

// ReportHandler handles the report page, providing a form for users to send a message to the administrators.
// The form is processed by sending a POST request to Telegram's API to send the message to a specific chat.
func ReportHandler(w http.ResponseWriter, r *http.Request) {
	// Handle POST requests
	if r.Method == http.MethodPost {
		// Parse the form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Unable to parse form data", http.StatusBadRequest)
			return
		}

		// Retrieve form values
		name := r.FormValue("Name")
		email := r.FormValue("email")
		message := r.FormValue("message")

		// Telegram bot token and chat ID
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

	// Render the report page
	database.Tpl.ExecuteTemplate(w, "report.html", nil)
}
