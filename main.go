package main

import (
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"log"
	"net/http"
)

func generateQRCode(c *gin.Context) {
	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "My App",
		AccountName: "user@example.com",
	})
	if err != nil {
		log.Fatal(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate secret"})
		return
	}

	qrCode, err := qrcode.Encode(secret.URL(), qrcode.Medium, 256)
	if err != nil {
		log.Fatal(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QRCode"})
	}

	c.Data(http.StatusOK, "image/png", []byte(qrCode))
}

func main() {
	router := gin.Default()
	router.GET("/", generateQRCode)
	err := router.Run(":8080")
	if err != nil {
		return
	}
}
