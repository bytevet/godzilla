package main

import (
	"net/http"
	"os/exec"
)

// buildOutbound constructs an OUTBOUND request from a constant URL. Its
// *http.Request is a call result (http.NewRequest), not an inbound param or a
// field read, so the type-based request-source seeding must NOT treat it as
// attacker-controlled. Reading a field off it and passing that to a sink must
// therefore produce NO finding — this is the control that keeps the broadened
// seeding "inbound only".
func buildOutbound() {
	req, err := http.NewRequest("GET", "https://api.internal.example.com/v1/status", nil)
	if err != nil {
		return
	}
	host := req.URL.Host // constant-derived, NOT tainted
	exec.Command("curl", host).Run()
}

func main() {
	buildOutbound()
}
