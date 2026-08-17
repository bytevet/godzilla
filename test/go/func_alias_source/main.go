package main

import (
	"net/http"
	"os"
	"path/filepath"

	"funcaliassource/macaron"
	"funcaliassource/web"
)

// A framework request context: the *http.Request is a field, not a parameter.
type ReqContext struct{ Req *http.Request }

// Through the alias. Before the alias was resolved this call had NO callee name,
// so it matched no source glob and the whole flow was invisible.
func viaAlias(c *ReqContext) {
	f, _ := os.Open(filepath.Join("/plugins", filepath.Clean(web.Params(c.Req)["*"])))
	defer f.Close()
}

// Direct call to the same function, for contrast.
func direct(c *ReqContext) {
	f, _ := os.Open(filepath.Join("/plugins", filepath.Clean(macaron.Params(c.Req)["*"])))
	defer f.Close()
}

// Reassigned, so it has no single answer and must stay unresolved -- this is the
// control that keeps the resolution sound rather than merely useful.
var Hook = macaron.Params

func init() {
	Hook = func(r *http.Request) map[string]string { return nil }
}

func viaReassigned(c *ReqContext) {
	f, _ := os.Open(filepath.Join("/plugins", filepath.Clean(Hook(c.Req)["*"])))
	defer f.Close()
}

func main() {}
