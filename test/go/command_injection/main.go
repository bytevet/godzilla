package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func main() {
	http.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		// Vulnerable: OS command injection via untrusted query param
		out, err := exec.Command(cmd).CombinedOutput()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(out)
	})
	fmt.Println("Server starting on :8082")
	http.ListenAndServe(":8082", nil)
}
