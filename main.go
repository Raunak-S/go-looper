package main

import (
	"fmt"
	"net/http"
)

func loop(id int, loops int) {

	rootURL := "http://ceh-broker-service:9080/broker"
	response := ""

	for i := 0; i < loops; i++ {
		response += "\n\n1:  GET /broker\n"
		resp, err := http.Get(rootURL)
		response += 
	}

}

func main() {
	fmt.Println("Hello World!")
}
