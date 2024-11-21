
package main

import (
	"fmt"
<<<<<<< HEAD
	"io"
	"net/http"
)

func main() {
	resp, err := http.Get("https://access.redhat.com/hydra/rest/securitydata/cve.json?product=OpenShift%20Container%20Platform&severity=important")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s", body)
=======
)

func main() {
	fmt.Println("boilerplate")
>>>>>>> 7e9afae (boilerplate done)
}
