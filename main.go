package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

type CVE struct {
	CVE            string   `json:"CVE"`
	ThreatSeverity string   `json:"severity"`
	PublicDate     string   `json:"public_date"`
	CVSS           float64  `json:"cvss_score"`
	CVSS3          string   `json:"cvss3_score"`
	Advisories     []string `json:"advisories"`
}

type Advisory struct {
	AffectedProducts []string `json:"affected_products"`
	AffectedPackages []string `json:"affected_packages"`
}

func fetchOCPVersion(advisories []string) (string, error) {
	for _, advisory := range advisories {
		url := "https://access.redhat.com/hydra/rest/securitydata/advisory/" + advisory + ".json"
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("Error fetching advisory %s: %v", advisory, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			log.Printf("Advisory %s not found", advisory)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("non-OK response: %s", resp.Status)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Error reading response body for advisory %s: %v", advisory, err)
			continue
		}

		var adv Advisory
		if err := json.Unmarshal(body, &adv); err != nil {
			log.Printf("Error unmarshalling response for advisory %s: %v", advisory, err)
			continue
		}

		if len(adv.AffectedProducts) > 0 {
			for _, product := range adv.AffectedProducts {
				if strings.Contains(product, "OpenShift Container Platform") {
					return product, nil
				}
			}
		} else {
			// Check affected_packages (lowercase 'a')
			for _, pkg := range adv.AffectedPackages {
				if strings.Contains(pkg, "openshift") {
					return "OCP Version: Found in affected package", nil
				}
			}
		}
	}

	return "Unknown", nil
}

func printCVEData(cves []CVE) {
	for _, cve := range cves {
		fmt.Println("--------------------------------")
		fmt.Println("CVE:", cve.CVE)
		fmt.Println("Severity:", cve.ThreatSeverity)
		fmt.Println("Public Date:", cve.PublicDate)
		fmt.Println("CVSS Score:", cve.CVSS)
		fmt.Println("CVSS3:", cve.CVSS3)
		fmt.Println("Advisories:", cve.Advisories)

		if len(cve.Advisories) > 0 {
			ocpVersion, err := fetchOCPVersion(cve.Advisories)
			if err != nil {
				fmt.Println("Error fetching OCP version:", err)
			} else {
				fmt.Println("OCP Version:", ocpVersion)
			}
		}
	}
}

func main() {
	url := "https://access.redhat.com/hydra/rest/securitydata/cve.json?product=OpenShift%20Container%20Platform&severity=important&created_days_ago=30"
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var cves []CVE
	if err := json.Unmarshal(body, &cves); err != nil {
		log.Fatal(err)
	}

	printCVEData(cves)
	// fmt.Println("Advisory Response:", string(body)) // Add this to see the full response
}
