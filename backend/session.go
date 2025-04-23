package main

import (
	"errors"
	"net/http"
)

var AuthError = errors.New("Unauthorized")

func Authorize(r *http.Request) (string, error) {
	sessCookie, err := r.Cookie("session_token")
	if err != nil {
		return "", AuthError
	}

	csrfCookie, err := r.Cookie("csrf_token")
	if err != nil {
		return "", AuthError
	}

	csrfHeader := r.Header.Get("X-Csrf-Token")
	if csrfHeader == "" {
		return "", AuthError
	}

	var username, storedCsrf string
	err = db.QueryRow(
		"SELECT username, csrf_token FROM users WHERE session_token = ?",
		sessCookie.Value,
	).Scan(&username, &storedCsrf)
	if err != nil {
		return "", AuthError
	}

	if storedCsrf != csrfCookie.Value || storedCsrf != csrfHeader {
		return "", AuthError
	}

	return username, nil
}
