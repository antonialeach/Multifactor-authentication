package main

import (
	"errors"
	"fmt"
	"net/http"
)

var AuthError = errors.New("Unauthorized")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	fmt.Println("Username:", username)

	user, ok := users[username]
	if !ok {
		fmt.Println("User not found.")
		return AuthError
	}

	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		fmt.Println("Session token validation failed.")
		if st != nil {
			fmt.Printf("Session Token (Cookie): '%s'\n", st.Value)
		} else {
			fmt.Println("Session Token (Cookie): Cookie not found or error")
		}
		fmt.Printf("Session Token (Stored): '%s'\n", user.SessionToken)
		return AuthError
	}

	csrf := r.Header.Get("X-CSRF-Token")
	if csrf == "" || csrf != user.CSRFToken {
		fmt.Println("CSRF token validation failed.")
		fmt.Printf("CSRF Token (Header): '%s'\n", csrf)
		fmt.Printf("CSRF Token (Stored): '%s'\n", user.CSRFToken)
		return AuthError
	}

	fmt.Println("Authorization successful.")
	return nil
}
