// Taint reaching a sink THROUGH MEMORY: a struct field, a map, and a slice
// literal. Def-use alone cannot walk back out of any of them — the stored value
// is not an operand of anything the container's chain reaches — so the reported
// path jumps straight from the source to the container and loses every transform
// in between. `path` in expected.yaml names those lines.
//
// The `other` value is a DECOY, and the point of the sample: it is tainted from
// the same request and written into the same map, but never reaches the sink. A
// container is tainted as a unit, so both writes look alike to the engine; a
// backward walk that picks the wrong one reports a path through code the value
// never took. taint_path_decoy_test pins its lines OUT of the path.
package main

import (
	"net/http"
	"os/exec"
	"strings"
)

type job struct {
	name string
}

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("cmd")
	other := r.URL.Query().Get("other")
	trimmed := strings.TrimSpace(raw)
	j := job{name: trimmed}
	m := map[string]string{}
	m["used"] = j.name
	m["decoy"] = other
	args := []string{"-c", m["used"]}
	_ = exec.Command("sh", args...)
}

func main() {
	http.HandleFunc("/run", handler)
	_ = http.ListenAndServe(":8080", nil)
}
