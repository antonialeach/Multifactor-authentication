package main

import (
	"fmt"
	"log"
	"time"

	"github.com/pquerna/otp/totp"
)

func main() {
	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "My App",
		AccountName: "user@example.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Secret: ", secret.Secret())

	code, err := totp.GenerateCode(secret.Secret(), time.Now())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Code: ", code)

	valid := totp.Validate(code, secret.Secret())
	fmt.Println("Valid: ", valid)
}
