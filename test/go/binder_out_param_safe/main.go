// FALSE-POSITIVE CONTROL for the propagator half of the out-parameter fill.
//
// json.Unmarshal fills its out-parameter (like a binder), but unlike a binder
// it does not read a request itself — it decodes whatever bytes it is handed —
// so the fill must be CONDITIONAL on some other operand already being tainted.
// Here the decoded blob is a CONSTANT, so params must stay clean: if this
// fires, the design (an unconditional fill for a propagator) is wrong, not
// this sample.
package main

import (
	"encoding/json"
	"os/exec"
)

type actionReq struct {
	Cmd string `json:"cmd"`
}

func main() {
	var params actionReq
	json.Unmarshal([]byte(`{"cmd":"echo hello"}`), &params)
	out, _ := exec.Command("sh", "-c", params.Cmd).Output()
	_ = out
}
