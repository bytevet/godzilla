// Vulnerable sample: path traversal via a framework route-parameter accessor
// (CWE-22). Mirrors Grafana CVE-2021-43798 (getPluginAssets): the route wildcard
// is read via web.Params(r) — a free-function accessor like gorilla/mux.Vars —
// then joined onto a base directory and opened with no containment check, so
// `?file=../../etc/passwd` escapes the plugin directory. filepath.Join does not
// contain the input; web.Params is the untrusted source.
package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	"frameworkrouteparam/web"
)

func getAsset(w http.ResponseWriter, r *http.Request) {
	requestedFile := web.Params(r)["*"]                      // untrusted route param
	path := filepath.Join("/var/lib/plugins", requestedFile) // Join does not contain "../"
	f, err := os.Open(path)                                  // sink: path traversal
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	_, _ = io.Copy(w, f)
}

func main() {
	http.HandleFunc("/plugins/", getAsset)
	_ = http.ListenAndServe(":8080", nil)
}
