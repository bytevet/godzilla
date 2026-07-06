package main

import (
	"net/http"
	"os/exec"

	"github.com/gorilla/mux"
)

// gorilla/mux path variables (mux.Vars) are an untrusted source; the value flows
// into an os/exec command. Exercises the mux.Vars source rule.
func main() {
	r := mux.NewRouter()
	r.HandleFunc("/run/{cmd}", func(w http.ResponseWriter, req *http.Request) {
		vars := mux.Vars(req)
		exec.Command("sh", "-c", vars["cmd"]).Run() // command injection
	})
	http.ListenAndServe(":8080", r)
}
