package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

type CVE struct {
	CVE            string   `json:"CVE"`
	ThreatSeverity string   `json:"severity"`
	PublicDate     string   `json:"public_date"`
	CVSS           float64  `json:"cvss_score"`
	CVSS3          string   `json:"cvss3_score"`
	Advisories     []string `json:"advisories"`
}

func main() {
	resp, err := http.Get("https://access.redhat.com/hydra/rest/securitydata/cve.json?product=OpenShift%20Container%20Platform&severity=important&created_days_ago=30")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var cves []CVE
	err = json.Unmarshal(body, &cves)
	if err != nil {
		log.Fatal(err)
		return
	}

	for _, cve := range cves {
		fmt.Println("--------------------------------")
		fmt.Println("CVE:", cve.CVE)
		fmt.Println("Severity:", cve.ThreatSeverity)
		fmt.Println("Public Date:", cve.PublicDate)
		fmt.Println("CVS Score:", cve.CVSS)
		fmt.Println("CVSS3:", cve.CVSS3)
		fmt.Println("Advisories:", cve.Advisories)
	}
}
