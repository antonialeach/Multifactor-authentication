# Multifactor-authentication
Implementation of a Go programming language application integrating multifactor authentication, demonstrating how to combine passwords with generated tokens.

To test the API functionality for the secure login portal you have to:

1. Run the directory "Backend" that includes all the go files with the functions: Register, Login, Protected and Logout.
2. Use Postman to test the API endpoints
   1. Register:
      Method: POST;
      URL: http://localhost:8080/register;
      In the body introduce the data for username and password and click send.
   2. Login:
      Method: POST;
      URL: http://localhost:8080/login;
      In the body introduce the username and password that you used for Register.
   3. Protected:
      Method: POST;
      URL: http://localhost:8080/protected;
      Add an Authorization header: X-CSRF-Token with the value of the csrf cookie generate at Login.
   4. Logout:
      Method: POST;
      URL: http://localhost:8080/logout;
      Fill out the username and password of an existing account.
