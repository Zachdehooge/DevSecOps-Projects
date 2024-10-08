package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/antonholmquist/jason"
	"github.com/joho/godotenv"
)

// 1445f8dc16bf7f0e1c7b3d16bee14ef83e6170ab00a2381d509051c64617fbfd
func fileScan(sha256 string) {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	apikey := os.Getenv("apikey")

	fmt.Println("\nStarting the Virus Total Scan...")
	fmt.Println("")

	url := "https://www.virustotal.com/api/v3/files/" + sha256

	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apikey)

	res, _ := http.DefaultClient.Do(req)

	v, _ := jason.NewObjectFromReader(res.Body)

	threatLabel, _ := v.GetString("data", "attributes", "popular_threat_classification", "suggested_threat_label")

	malCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "malicious")
	susCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "suspicious")
	undetectedCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "undetected")
	harmlessCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "harmless")
	timeoutCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "timeout")
	confirmedtimeoutCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "confirmed-timeout")
	failureCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "failure")
	unsupportCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "type-unsupported")

	repCat, _ := v.GetInt64("data", "attributes", "reputation")

	fmt.Println("\nThreat Label: ", threatLabel)
	fmt.Println("____________________________________")
	fmt.Println("\nMalicious: ", malCat)
	fmt.Println("Suspicious: ", susCat)
	fmt.Println("Undetected: ", undetectedCat)
	fmt.Println("Harmless: ", harmlessCat)
	fmt.Println("Timeout: ", timeoutCat)
	fmt.Println("Confirmed Timeout: ", confirmedtimeoutCat)
	fmt.Println("Failure: ", failureCat)
	fmt.Println("Unsupported: ", unsupportCat)
	fmt.Println("____________________________________")

	fmt.Println("\nReputation: ", repCat)

	defer res.Body.Close()

	fmt.Println("\nVirus Total Scan Complete...")
	fmt.Println()
}

func main() {
	var i string

	fmt.Print("\nSHA256 of Sample: ")
	fmt.Scan(&i)
	fileScan(i)
}
