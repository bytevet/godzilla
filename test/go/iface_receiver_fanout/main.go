// A tainted RECEIVER at an ambiguous interface call must not fan out; a tainted
// ARGUMENT must still flow.
//
// When the engine cannot tell which implementation runs it binds all of them. An
// argument is passed to whichever one actually runs, so seeding it approximates
// one real call. The RECEIVER is the object itself: seeding it into unrelated
// types asserts the object could be any of them, and each body then reads ITS OWN
// fields and dispatches again, so the error compounds through the dependency
// closure instead of staying local. In the wild, `defer c.Request.Body.Close()`
// seeded every io.ReadCloser in the program and the taint walked out through
// three unrelated libraries into a config reader.
//
// This is the discipline untyped_dispatch already applies to name-resolved calls,
// narrowed: there an ambiguous call seeds nothing, here it still seeds arguments.
//
// The receiver is a named STRING type on purpose. Boxing a struct into an
// interface drops its field-path taint, so a struct receiver would reproduce
// nothing and the control would be vacuous.
package main

import (
	"net/http"
	"os/exec"
)

// Store is AMBIGUOUS: two implementations, so a call on it binds both.
type Store interface {
	Put(data string) error
	Tag() string
}

// tag is the implementation the receiver actually holds.
type tag string

func (t tag) Put(data string) error {
	_ = exec.Command("/bin/sh", "-c", "log "+data).Run() // ARGUMENT: must fire
	return nil
}
func (t tag) Tag() string { return string(t) }

// audit is unrelated, and IS boxed below so the dispatch stays ambiguous — an
// implementation the program never boxes is eliminated by RTA, which would make
// this control vacuous. Its Put reaches a sink through its OWN constant field,
// so it can only fire if the ambiguous dispatch seeded its receiver.
type audit struct{ label string }

func (a *audit) Put(data string) error {
	_ = exec.Command("/bin/sh", "-c", "audit "+a.label).Run() // RECEIVER: must NOT fire
	return nil
}
func (a *audit) Tag() string { return a.label }

// registry boxes audit so both implementations are live candidates.
var registry Store = &audit{label: "static"}

func handler(w http.ResponseWriter, r *http.Request) {
	tainted := r.URL.Query().Get("q")

	var s Store = tag(tainted) // the receiver itself is attacker-controlled

	// Ambiguous dispatch: binds tag.Put (the real one, whose ARGUMENT is tainted
	// and must fire) and audit.Put (whose sink uses only its own constant field,
	// and fires only if the guessed-at receiver was seeded).
	_ = s.Put(tainted)
	_ = registry

	_ = w
}

func main() {
	http.HandleFunc("/", handler)
	_ = http.ListenAndServe(":8080", nil)
}
