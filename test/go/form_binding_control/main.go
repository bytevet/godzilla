package main

import (
	"os"
	"path"
)

// Plain is a value struct, but the function taking it is NOT registered at a
// routing verb — so it is not a request-bound form and must not be seeded. This
// is the control that keeps form-param seeding scoped to route handlers: a plain
// helper's value-struct param stays clean, so its field reaching a sink produces
// NO finding. (If seeding ever widened to every value-struct param, this trips.)
type Plain struct {
	Path string
}

func consume(p Plain) {
	os.Remove(path.Join("/data", p.Path)) // no source: p is not request-bound
}

func main() {
	// A compile-time-constant struct, passed to a non-handler helper.
	consume(Plain{Path: "fixed/name"})
}
