package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// Azure AD app
const (
	clientID     = ""
	clientSecret = ""
	tenantID     = ""
	redirectURI  = "http://localhost:8080/callback"
)

var scopes = []string{"https://outlook.office.com/IMAP.AccessAsUser.All", "offline_access"}

func main() {
	// Initialize Microsoft confidential client
	msCred, err := confidential.NewCredFromSecret(clientSecret)
	if err != nil {
		log.Fatalf("could not create microsoft cred: %v", err)
	}
	app, err := confidential.New(fmt.Sprintf("https://login.microsoftonline.com/%s", tenantID), clientID, msCred)
	if err != nil {
		log.Fatalf("could not create microsoft confidential client: %v", err)
	}

	// Handler for oauth2 callback. Exchanges code for token and fails if not successful
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "code not found", http.StatusBadRequest)
			return
		}

		// Exchange code for token
		_, err := app.AcquireTokenByAuthCode(r.Context(), code, redirectURI, scopes)
		if err != nil {
			msg := fmt.Sprintf("could not exchange code for token: %v", err)
			http.Error(w, msg, http.StatusInternalServerError)
			log.Println(msg)
			return
		}

		// Use token
		fmt.Fprintf(w, "aquired all tokens successfully!")
	})

	// Print out authorization url for user to visit
	authURI, err := app.AuthCodeURL(context.Background(), clientID, redirectURI, scopes)
	if err != nil {
		log.Fatalf("could not create auth code url: %v", err)
	}
	log.Printf("open %s to authenticate...", authURI)

	// Serve http server listening for oauth2 callback
	http.ListenAndServe(":8080", nil)
}
