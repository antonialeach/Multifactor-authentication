package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	_ "modernc.org/sqlite"
)

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("sqlite", "./users.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			username TEXT PRIMARY KEY,
			email TEXT UNIQUE,
			hashed_password TEXT,
			session_token TEXT,
			csrf_token TEXT,
			totp_secret TEXT
		)
	`)
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.HandleFunc("/generate-totp-setup", generateTOTPSetup)
	http.HandleFunc("/verify-totp-setup", verifyTOTPSetup)

	http.Handle("/", http.FileServer(http.Dir("./frontend")))

	fmt.Println("Server running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Cannot parse form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	if len(username) < 5 || len(password) < 5 {
		http.Error(w, "Invalid username or password. Minimum 5 characters.", http.StatusNotAcceptable)
		return
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "MyApp",
		AccountName: email,
	})
	if err != nil {
		http.Error(w, "Error generating TOTP", http.StatusInternalServerError)
		return
	}
	secret := key.Secret()

	_, err = db.Exec(
		"INSERT INTO users (username, email, hashed_password, totp_secret) VALUES (?, ?, ?, ?)",
		username, email, hashedPassword, secret,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			http.Error(w, "Username or email already exists.", http.StatusConflict)
			return
		}
		http.Error(w, "Database error during registration", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Println("Registered user:", username)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Cannot parse form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var hashed string
	err = db.QueryRow("SELECT hashed_password FROM users WHERE username = ?", username).Scan(&hashed)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	if !checkPasswordHash(password, hashed) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)
	_, err = db.Exec(
		"UPDATE users SET session_token = ?, csrf_token = ? WHERE username = ?",
		sessionToken, csrfToken, username,
	)
	if err != nil {
		http.Error(w, "Database error updating session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: sessionToken, Expires: time.Now().Add(24 * time.Hour), Path: "/", HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: csrfToken, Expires: time.Now().Add(24 * time.Hour), Path: "/"})

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Login successful")
}

func logout(w http.ResponseWriter, r *http.Request) {
	username, err := Authorize(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", Expires: time.Unix(0, 0), Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "", Expires: time.Unix(0, 0), Path: "/"})
	_, _ = db.Exec("UPDATE users SET session_token = '', csrf_token = '' WHERE username = ?", username)
	fmt.Fprintln(w, "Logged out")
}

func protected(w http.ResponseWriter, r *http.Request) {
	_, err := Authorize(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Write([]byte("Welcome to the protected area"))
}

func generateTOTPSetup(w http.ResponseWriter, r *http.Request) {
	username, err := Authorize(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var email, secret string
	err = db.QueryRow("SELECT email, totp_secret FROM users WHERE username = ?", username).Scan(&email, &secret)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	uri := fmt.Sprintf("otpauth://totp/MyApp:%s?secret=%s&issuer=MyApp", email, secret)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"uri": uri})
}

func verifyTOTPSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Cannot parse form", http.StatusBadRequest)
		return
	}

	username, err := Authorize(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	totpCode := r.FormValue("totp_code")
	var secret string
	err = db.QueryRow("SELECT totp_secret FROM users WHERE username = ?", username).Scan(&secret)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if !totp.Validate(totpCode, secret) {
		http.Error(w, "Invalid TOTP code", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("TOTP verified"))
}
