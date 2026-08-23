package main

// ENG-14(a): a map KEY selects among values the program already put in the map,
// so an attacker-chosen key cannot make the result attacker-controlled. Reading
// the container still carries taint, which is what the two handlers separate.

import (
	"net/http"
	"os"
)

// routes is built at startup: nothing a request says can add an entry.
var routes = map[string]string{"motd": "/etc/motd", "hosts": "/etc/hosts"}

// keySelects lets the request pick WHICH path is read, never what it is. Every
// traversal payload misses the map and yields the zero value, so this must not
// fire -- before the fix it did, and the tainted result then spread through every
// caller of everything it touched.
func keySelects(w http.ResponseWriter, r *http.Request) {
	path := routes[r.URL.Query().Get("p")]
	if path == "" {
		return
	}
	_, _ = os.ReadFile(path)
}

// contentsTainted puts the request INTO the map, so the container itself holds
// untrusted data and reading it back is a real flow. This is the recall half:
// the fix must not turn map reads inert.
func contentsTainted(w http.ResponseWriter, r *http.Request) {
	m := map[string]string{}
	m["p"] = r.URL.Query().Get("p")
	_, _ = os.ReadFile(m["p"])
}

func main() {
	http.HandleFunc("/select", keySelects)
	http.HandleFunc("/store", contentsTainted)
	_ = http.ListenAndServe(":8080", nil)
}
