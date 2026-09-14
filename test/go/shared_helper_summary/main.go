// A helper's return summary belongs to the CALL SITE, not to the function.
//
// `normalize` is reached from two handlers that share nothing else — no variable,
// no struct, no receiver — so its return summary is the only thing that can
// connect them. Recorded per-function, the tainted caller's summary hands taint
// back to the constant caller, and `runBackup` is reported as a CRITICAL command
// injection on a string the program wrote itself.
//
// `normalize` is NOT a sanitizer: it trims and lower-cases, so a shell
// metacharacter passes through untouched. The tainted half must keep firing
// through it — dropping the helper's propagation would silence both halves and
// still satisfy a control that only counted the safe one.
package main

import (
	"net/http"
	"os/exec"
	"strings"
)

func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// runTagged normalizes attacker input, which leaves it attacker-controlled.
func runTagged(w http.ResponseWriter, r *http.Request) {
	tag := normalize(r.URL.Query().Get("tag"))
	_ = exec.Command("/bin/sh", "-c", "logger -t "+tag).Run()
	_ = w
}

// runBackup normalizes a CONSTANT. Nothing attacker-controlled is in scope.
func runBackup(w http.ResponseWriter, r *http.Request) {
	mode := normalize("  Daily-Full  ")
	_ = exec.Command("/bin/sh", "-c", "backup --mode "+mode).Run()
	_, _ = w, r
}

func main() {
	http.HandleFunc("/tag", runTagged)
	http.HandleFunc("/backup", runBackup)
	_ = http.ListenAndServe(":8080", nil)
}
