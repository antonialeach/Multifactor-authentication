# Multifactor Authentication (Go)

This application demonstrates a basic secure login portal implemented in Go, utilizing password-based authentication with CSRF protection and user-selected two-factor authentication (2FA).

## Overview

This project includes a backend API written in Go for user registration, login, 2FA configuration, and protected session access. The frontend is built with HTML and JavaScript for user interaction.

**Key Features:**

* **User Registration** – Create new user accounts.
* **Login** – Authenticate users using their credentials.
* **2FA Method Selection** – Upon login, users must choose between:

    * **TOTP (Time-based One-Time Password)** using Google Authenticator app.
    * **Email OTP** (One-Time Password sent to the user’s registered email).
* **Protected Area** – Accessible only after completing 2FA.
* **Logout** – Securely end user sessions.
* **CSRF Protection** – Protects sensitive actions via CSRF tokens.
* **Email Integration** – Sends OTPs using Gmail (requires credentials in `.env`).

## Getting Started

### 1. Prerequisites

* Go 1.18 or newer
* SQLite
* `.env` file with your Gmail credentials:

  ```
  GMAIL_ADDRESS=your-email@gmail.com
  GMAIL_APP_PASSWORD=your-app-password
  ```

### 2. Build and Run the Backend

1. Navigate to the `backend` directory.
2. Run the build command:

   ```bash
   go build
   ```
3. Start the backend:

   ```bash
   ./backend
   ```

Server starts at: `http://localhost:8080`

### 3. Access the Frontend

Open your browser and go to: `http://localhost:8080`
This loads the main interface (`index.html`) for registration and login.

---

## Workflow

### Registration

1. Sign up with a unique username, email, and password.
2. Upon registration, a TOTP secret is automatically generated and stored.

### Login & 2FA Setup

1. Enter username and password to login.
2. Choose your preferred 2FA method:

    * **TOTP:** Scan a QR code with Google Authenticator. Enter the 6-digit TOTP.
    * **Email OTP:** A 6-digit one-time code is emailed. Enter it within 5 minutes.
3. Upon successful verification, access to the protected area is granted.

### Protected Area

Accessible only after full login and successful 2FA. Displays a welcome message and includes logout functionality.

### Logout

Ends the session and invalidates the CSRF and session tokens.

---

## API Endpoints

### POST `/register`

Registers a new user.

**Form Data:**

```
username=<string>
email=<string>
password=<string>
```

---

### POST `/login`

Logs in an existing user.

**Form Data:**

```
username=<string>
password=<string>
```

Returns session & CSRF cookies.

---

### POST `/send-otp-email`

Triggers sending an OTP to the user's email.

Headers:

* `X-Csrf-Token: <token>`

---

### POST `/verify-otp-setup`

Verifies the entered email OTP.

**Form Data:**

```
otp_code=<6-digit-code>
```

---

### POST `/verify-totp-setup`

Verifies the entered TOTP from Google Authenticator.

**Form Data:**

```
totp_code=<6-digit-code>
```

---

### GET `/generate-totp-setup`

Returns a URI to generate a QR code for the authenticator app.

---

### POST `/protected`

Access the protected area.

Headers:

* `X-Csrf-Token: <token>`

---

### POST `/logout`

Ends the user session.

Headers:

* `X-Csrf-Token: <token>`

---

## Security Notes

* OTP codes (email-based) expire after **5 minutes**.
* TOTP codes are validated using standard time-based algorithms.
* Passwords are securely hashed.
* CSRF tokens protect all sensitive endpoints.


