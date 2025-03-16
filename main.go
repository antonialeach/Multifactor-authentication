package main

import (
	"fmt"
	"log"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

func main() {
	//Gerating secret
	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "My App",
		AccountName: "user@example.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Secret: ", secret.Secret())

	//Generating QR code
	qrCode, err := qrcode.Encode(secret.URL(), qrcode.Medium, 256)
	if err != nil {
		log.Fatal(err)
	}
	err = qrcode.WriteFile(secret.URL(), qrcode.Medium, 256, "qrcode.png")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(qrCode))
	fmt.Println("QR Code saved successfully in qrcode.png")

	//Gerating TOTP code
	code, err := totp.GenerateCode(secret.Secret(), time.Now())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Code: ", code)

	valid := totp.Validate(code, secret.Secret())
	fmt.Println("Valid: ", valid)
}
