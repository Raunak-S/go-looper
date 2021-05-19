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

func request(urlExtension string, step string, client *http.Client, req *http.Request) string {
	req.URL.Path += urlExtension
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	return step + string(body)
}

// a single looper loop
func loop(id string, loops int, jwt string, done chan int) {
	rootURL := "https://ceh-broker-stocktrader-dev.devops-dev1-a01ee4194ed985a1e32b1d96fd4ae346-0000.us-east.containers.appdomain.cloud/broker"
	bearer := "Bearer " + jwt

	req, _ := http.NewRequest("GET", rootURL, nil)
	req.Header.Add("Authorization", bearer)
	client := &http.Client{}
	looperId := "Looper" + id

	response := "Thread #" + id
	for i := 1; i <= loops; i++ {
		response += ", Iteration #" + fmt.Sprintf("%d", i)
		response += request("/", "\n\n1:  GET /broker\n", client, req)

		response += request("/"+looperId, "\n\n2:  POST /broker/"+looperId+"\n", client, req)

		response += request("/")

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

	jwt := args[3]
	done := make(chan int)
	for i := 1; i <= thread; i++ {
		go loop(fmt.Sprintf("%d", i), count, jwt, done)
	}
	<-done
}
