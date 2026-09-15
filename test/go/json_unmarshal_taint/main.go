// The propagator half of the out-parameter fill (see binder_out_param for the
// unconditional source half): encoding/json.Unmarshal decodes an
// attacker-controlled byte slice into a caller-allocated struct. It returns
// only an error, so nothing taints `req` unless the propagator rule names the
// OUT-PARAMETER it fills (propagators: "...Unmarshal#1"), gated on the decoded
// bytes themselves being tainted.
package main

import (
	"encoding/json"
	"net/http"
	"os/exec"
)

type actionReq struct {
	Cmd string `json:"cmd"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	body := []byte(r.URL.Query().Get("body"))
	var req actionReq
	json.Unmarshal(body, &req)
	out, _ := exec.Command("sh", "-c", req.Cmd).Output() // command injection
	w.Write(out)
}

func main() {
	http.HandleFunc("/run", handler)
	_ = http.ListenAndServe(":8080", nil)
}
