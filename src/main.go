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

var SYMBOL1 = "IBM"
var SYMBOL2 = "AAPL"
var SYMBOL3 = "GOOG"
var rootURL = "https://ceh-broker-stocktrader.devops-dev1-a01ee4194ed985a1e32b1d96fd4ae346-0000.us-east.containers.appdomain.cloud/broker"

type customClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func request(requestMethod string, urlExtension string, step string, client *http.Client, req *http.Request) string {
	req.Method = requestMethod
	req.URL.Path = rootURL + urlExtension
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
	bearer := "Bearer " + jwt

	req, _ := http.NewRequest("GET", rootURL, nil)
	req.Header.Add("Authorization", bearer)
	client := &http.Client{}
	looperId := "Looper" + id

	response := "Thread #" + id
	for i := 1; i <= loops; i++ {
		q := req.URL.Query()
		response += ", Iteration #" + fmt.Sprintf("%d", i)

		response += request("GET", "/", "\n\n1:  GET /broker\n", client, req)
		response += request("POST", "/"+looperId, "\n\n2:  POST /broker/"+looperId+"\n", client, req)
		q.Set("symbol", SYMBOL1)
		q.Set("shares", "1")
		req.URL.RawQuery = q.Encode()
		response += request("PUT", "/"+looperId, "\n\n3:  PUT /broker/"+looperId+"?symbol="+SYMBOL1+"&shares=1\n", client, req)
		q.Set("symbol", SYMBOL2)
		q.Set("shares", "2")
		req.URL.RawQuery = q.Encode()
		response += request("PUT", "/"+looperId, "\n\n4:  PUT /broker/"+looperId+"?symbol="+SYMBOL2+"&shares=2\n", client, req)
		q.Set("symbol", SYMBOL3)
		q.Set("shares", "3")
		req.URL.RawQuery = q.Encode()
		response += request("PUT", "/"+looperId, "\n\n5:  PUT /broker/"+looperId+"?symbol="+SYMBOL3+"&shares=3\n", client, req)
		response += request("GET", "/"+looperId, "\n\n6:  GET /broker/"+looperId+"\n", client, req)
		response += request("GET", "/", "\n\n7:  GET /broker\n", client, req)
		q.Set("symbol", SYMBOL1)
		q.Set("shares", "6")
		req.URL.RawQuery = q.Encode()
		response += request("PUT", "/"+looperId, "\n\n8:  PUT /broker/"+looperId+"?symbol="+SYMBOL1+"&shares=6\n", client, req)
		q.Set("symbol", SYMBOL3)
		q.Set("shares", "-3")
		req.URL.RawQuery = q.Encode()
		response += request("PUT", "/"+looperId, "\n\n9:  PUT /broker/"+looperId+"?symbol="+SYMBOL3+"&shares=-3\n", client, req)
		response += request("GET", "/"+looperId, "\n\n10: GET /broker/"+looperId+"\n", client, req)
		response += request("DELETE", "/"+looperId, "\n\n11: DELETE /broker/"+looperId+"\n", client, req)
		response += request("GET", "/", "\n\n12: GET /broker\n", client, req)

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
		fmt.Println("Created Thread " + fmt.Sprintf("%d", i))
		go loop(fmt.Sprintf("%d", i), count, jwt, done)
	}
	for i := 0; i < thread; i++ {
		<-done
	}
}
