package main

import (
	"net/http"
	"testing"
)

func TestVirusUp(t *testing.T) {
	t.Log("Test to verify a 200 OK response from VirusTotal")

	url := "https://virustotal.com"

	// Perform the GET request
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("Failed to ping the website: %v", err)
	}

	defer resp.Body.Close()

	// Check if the status code is 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, but got %d", resp.StatusCode)
	}
}

func TestAPI(t *testing.T) {
	// Need to implement testing for a given SHA-256 hash in order to ensure that a JSON call is received
}
