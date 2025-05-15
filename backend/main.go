package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/pquerna/otp/totp"
	"gopkg.in/gomail.v2"
	"log"
	_ "modernc.org/sqlite"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"
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
	http.HandleFunc("/send-otp-email", sendGoMail)
	http.HandleFunc("/verify-otp-setup", verifyOTPSetup)

	http.Handle("/", http.FileServer(http.Dir("./frontend")))

	fmt.Println("Server running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func isValidPassword(password string) bool {
	var (
		hasMinLen  = false
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	if len(password) >= 8 {
		hasMinLen = true
	}
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasNumber = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}
	return hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial
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

	if len(username) < 5 {
		http.Error(w, "Invalid username. The username must have minimum 5 characters.", http.StatusNotAcceptable)
		return
	}

	var exitingUser string
	err = db.QueryRow("SELECT username FROM users WHERE username = ?", username).Scan(&exitingUser)
	if !errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	if !isValidPassword(password) {
		http.Error(w, "Invalid password. The password must have minimum 8 characters, uppercase, lowercase, digit and special symbol. ", http.StatusNotAcceptable)
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

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

type OTPEntry struct {
	Code      string
	CreatedAt time.Time
}

var otpStore = make(map[string]OTPEntry)

const otpChars = "1234567890"

func GenerateOTP(length int) (string, error) {
	buffer := make([]byte, length)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", err
	}

	otpCharsLength := len(otpChars)
	for i := 0; i < length; i++ {
		buffer[i] = otpChars[int(buffer[i])%otpCharsLength]
	}

	return string(buffer), nil
}

func sendGoMail(w http.ResponseWriter, r *http.Request) {
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

	var userEmail string
	err = db.QueryRow("SELECT email FROM users WHERE username = ?", username).Scan(&userEmail)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	otp, _ := GenerateOTP(6)
	otpStore[username] = OTPEntry{
		Code:      otp,
		CreatedAt: time.Now(),
	}

	email := os.Getenv("GMAIL_ADDRESS")
	password := os.Getenv("GMAIL_APP_PASSWORD")

	m := gomail.NewMessage()
	m.SetHeader("From", email)
	m.SetHeader("To", userEmail)
	m.SetHeader("Subject", "Your verification code from MyApp")

	message := fmt.Sprintf("Here is your verification code: %s.\nThis code will expire in 5 minutes.\nIf you did not request this, please ignore this message.", otp)
	m.SetBody("text/plain", message)

	d := gomail.NewDialer("smtp.gmail.com", 587, email, password)

	if err := d.DialAndSend(m); err != nil {
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		fmt.Println("Email error:", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "OTP sent"})
}

func verifyOTPSetup(w http.ResponseWriter, r *http.Request) {
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

	userInput := r.FormValue("otp_code")

	entry, exists := otpStore[username]
	if !exists || userInput != entry.Code {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	if time.Since(entry.CreatedAt) > 5*time.Minute {
		delete(otpStore, username)
		http.Error(w, "OTP expired", http.StatusUnauthorized)
		return
	}

	delete(otpStore, username)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OTP verified"))
}
