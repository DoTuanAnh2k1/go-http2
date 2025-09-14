package main

import (
	"fmt"
	"log"
)

// Server configuration constants
const (
	ServerAddress = "httpbin.org:80"
	ServerHost    = "httpbin.org"
	RequestPath   = "/get"
)

func main() {
	fmt.Println("HTTP/2 Client - Simple GET Request")
	fmt.Println("==================================")

	// Create HTTP/2 client
	client, err := NewClient(ServerAddress)
	if err != nil {
		log.Fatalf("Failed to create HTTP/2 client: %v", err)
	}
	defer client.Close()

	fmt.Printf("Connected to %s\n", ServerAddress)

	// Send GET request
	fmt.Printf("Sending GET %s...\n", RequestPath)
	response, err := client.GET(RequestPath, ServerHost)
	if err != nil {
		log.Fatalf("GET request failed: %v", err)
	}

	// Print response details
	fmt.Printf("Status: %s (%d)\n", response.Status, response.StatusCode)
	fmt.Printf("Response Headers:\n")
	for name, value := range response.Headers {
		fmt.Printf("  %s: %s\n", name, value)
	}

	fmt.Printf("\nResponse Body (%d bytes):\n", len(response.Body))
	fmt.Printf("%s\n", string(response.Body))

	fmt.Println("\n✓ Request completed successfully!")
}
