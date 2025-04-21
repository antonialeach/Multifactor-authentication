# Multifactor Authentication (Go)

This application demonstrates a basic secure login portal implemented in Go, utilizing password-based authentication with CSRF protection.

## Overview

This project includes a backend API written in Go for user registration, login, accessing a protected area, and logout. The frontend consists of HTML and JavaScript for user interaction.

**Key Features:**

* **User Registration:** Allows new users to create accounts.
* **Login:** Authenticates existing users using their username and password.
* **Protected Area:** An area accessible only to authenticated users, protected by CSRF tokens.
* **Logout:** Allows authenticated users to end their session.
* **CSRF Protection:** Implements CSRF (Cross-Site Request Forgery) protection using tokens to enhance security.

## Getting Started

To test the application, follow these steps:

### 1. Build and Run the Backend

1.  Open your file explorer or IDE.
2.  Navigate to the `backend` directory within your `Multifactor-authentication` project.
3.  **Right-click within the `backend` directory.**
4.  **Select the option that executes the Go build command.** This option might be labeled differently depending on your IDE or system integration, but it should effectively run:
    ```
    go build multifactor-authentification/backend
    ```
    This will create an executable file named `backend` (or `backend.exe` on Windows) within the `backend` directory.
5.  **Run the backend executable.** You can do this by:
    * **Double-clicking** the `backend` or `backend.exe` file in your file explorer.
    * **Opening a terminal in the `backend` directory** and running:
        ```bash
        ./backend
        ```
        (or `backend.exe` on Windows)

    This will start the backend server, likely listening on `http://localhost:8080`.

### 2. Access the Frontend

1.  Open your web browser and navigate to `http://localhost:8080`. The `index.html` file in the `frontend` directory should be served, providing the login and signup interface.

### 3. Testing the API Endpoints

You can also use a tool like Postman or `curl` to directly interact with the API endpoints:

#### Register

* **Method:** `POST`
* **URL:** `http://localhost:8080/register`
* **Body (x-www-form-urlencoded):**
    ```
    username=<your_desired_username>
    password=<your_desired_password>
    ```
* Click "Send" to register a new user.

#### Login

* **Method:** `POST`
* **URL:** `http://localhost:8080/login`
* **Body (x-www-form-urlencoded):**
    ```
    username=<your_registered_username>
    password=<your_registered_password>
    ```
* After successful login via the frontend, a `session_token` and `csrf_token` cookie will be set in your browser. If testing with Postman, you'll need to inspect the response headers and manage cookies manually for subsequent requests.

#### Protected

* **Method:** `POST`
* **URL:** `http://localhost:8080/protected`
* **Headers:**
    * `Content-Type`: `application/x-www-form-urlencoded`
    * `X-Csrf-Token`: `<value_of_the_csrf_token_cookie_from_login>`
* **Body (x-www-form-urlencoded):**
    ```
    username=<your_logged_in_username>
    ```
* Click "Send" to access the protected area. Ensure you include the `X-Csrf-Token` header with the value of the `csrf_token` cookie obtained during the login process.

#### Logout

* **Method:** `POST`
* **URL:** `http://localhost:8080/logout`
* **Headers:**
    * `Content-Type`: `application/x-www-form-urlencoded`
    * `X-Csrf-Token`: `<value_of_the_csrf_token_cookie_from_login>`
* **Body (x-www-form-urlencoded):**
    ```
    username=<your_logged_in_username>
    ```
* Click "Send" to log out the specified user. Ensure you include the `X-Csrf-Token` header with the value of the `csrf_token` cookie.

**Note on Frontend Interaction:**

The primary way to interact with this application is through the provided HTML interface in the `frontend` directory. After successful login via the web browser, you will be redirected to the `/protected.html` page. The JavaScript on this page handles the display of the welcome message and the logout functionality, including sending the CSRF token with the logout request.
