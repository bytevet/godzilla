// False-positive control for ENG-2 (flow-sensitivity / strong updates): request
// data is written into an address-taken local, then that same cell is
// overwritten with a constant before the sink. A monotonic, flow-insensitive
// engine keeps the cell tainted and flags the exec; a flow-sensitive engine with
// strong updates on the non-escaping alloc sees the constant overwrite and MUST
// NOT flag it.
package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	var cmd string
	p := &cmd
	*p = r.URL.Query().Get("cmd") // cell tainted...
	*p = "safe-constant"          // ...then strongly overwritten with a constant
	_ = exec.Command("sh", "-c", *p).Run()
	_ = w
}

func main() {
	http.HandleFunc("/x", handler)
	_ = http.ListenAndServe(":0", nil)
}
