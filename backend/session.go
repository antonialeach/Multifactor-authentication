package main

import (
	"errors"
	"net/http"
)

var AuthError = errors.New("Unauthorized")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	if username == "" {
		return errors.New("username missing")
	}

	sessionTokenCookie, err := r.Cookie("session_token")
	if err != nil {
		return errors.New("session token missing")
	}

	csrfTokenCookie, err := r.Cookie("csrf_token")
	if err != nil {
		return errors.New("csrf token missing")
	}

	csrfTokenHeader := r.Header.Get("X-Csrf-Token")
	if csrfTokenHeader == "" {
		return errors.New("csrf token header missing")
	}

	var storedSessionToken, storedCsrfToken string
	err = db.QueryRow("SELECT session_token, csrf_token FROM users WHERE username = ?", username).Scan(&storedSessionToken, &storedCsrfToken)
	if err != nil {
		return errors.New("user not found or database error")
	}

	if sessionTokenCookie.Value != storedSessionToken || csrfTokenCookie.Value != storedCsrfToken || csrfTokenHeader != storedCsrfToken {
		return errors.New("invalid session or csrf token")
	}

	return nil
}
