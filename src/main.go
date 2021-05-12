package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/dgrijalva/jwt-go"
)

type customClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// a single looper loop
func loop(id string, loops int, jwt string, done chan int) {
	rootURL := "https://ceh-broker-stocktrader-dev.devops-dev1-a01ee4194ed985a1e32b1d96fd4ae346-0000.us-east.containers.appdomain.cloud/broker"
	bearer := "Bearer " + jwt

	req, _ := http.NewRequest("GET", rootURL, nil)
	req.Header.Add("Authorization", bearer)
	client := &http.Client{}

	response := ""
	for i := 0; i < loops; i++ {
		req.URL.Path += "/"
		response += "\n\n1:  GET /broker\n"
		resp, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Fatal(err)
		}
		response += string(body)
		fmt.Println(response)
		response = ""
	}
	done <- 0
}

// pemToRSA turns a PEM-encoded RSA public key into an rsa.PublicKey value.
// Intended for use on startup, so panics if any part of the decoding fails.
func pemToRSA(pemtxt string) *rsa.PublicKey {
	var pubkey *rsa.PublicKey
	block, _ := pem.Decode([]byte(pemtxt))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	pubkey = cert.PublicKey.(*rsa.PublicKey)
	return pubkey
}

func readPemFile(filename string) []byte {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	return content
}

func createJWT(cert string, username string) string {
	claims := customClaims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			Issuer: "http://stock-trader.ibm.com",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	pemcontent := readPemFile("jwtsigner.pem")
	key, err := jwt.ParseRSAPrivateKeyFromPEM(pemcontent)
	if err != nil {
		log.Fatal(err)
	}
	signedToken, err := token.SignedString(key)
	if err != nil {
		log.Fatal(err)
	}
	return signedToken
}

func main() {
	args := os.Args
	count, err := strconv.Atoi(args[1])
	if err != nil {
		log.Fatal(err)
	}
	thread, err := strconv.Atoi(args[2])
	if err != nil {
		log.Fatal(err)
	}
	BASE_ID := "Looper"

	jwt := args[3]
	looper := ""
	done := make(chan int)
	for i := 1; i <= thread; i++ {
		looper = fmt.Sprintf("%s%d", BASE_ID, count)
		go loop(looper, count, jwt, done)
	}
	<-done
}
