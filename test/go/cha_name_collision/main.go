// FALSE-POSITIVE CONTROL for class-hierarchy analysis.
//
// An interface call resolves by bare METHOD NAME, because a name is all gIR
// guarantees across languages. Two unrelated types here share a name with a
// request accessor, and binding the call to them would make `Query`/`Close` the
// reported SOURCE of a flow that began at a database lookup — with a path
// leading through a library the value never entered.
//
// expected.yaml declares no findings: nothing here is attacker-controlled at a
// sink. What keeps it that way is the call site's own shape — the argument types
// it passes, and the method set the invoked interface demands.
package main

import (
	"io"
	"net/http"
	"os/exec"
)

// Ctx is a framework context. Its Query IS a request source.
type Ctx struct{ r *http.Request }

func (c *Ctx) Query(key string) string { return c.r.URL.Query().Get(key) }
func (c *Ctx) Close() error            { return nil }
func (c *Ctx) Read() string            { return c.r.URL.Path }

// Repo is a database repository. Its Query shares only the NAME: it takes a
// different type and returns a constant.
type Repo interface {
	Query(id uint64) string
}

type sqlRepo struct{}

func (s *sqlRepo) Query(id uint64) string { return "constant-from-db" }

func newRepo() Repo { return &sqlRepo{} }

// Blob implements Store below. Ctx does NOT (no Save), so a Store call must
// never bind to Ctx even though both spell Close and Read.
type Store interface {
	Read() string
	Close() error
	Save() error
}

type Blob struct{}

func (b *Blob) Read() string { return "constant-from-blob" }
func (b *Blob) Close() error { return nil }
func (b *Blob) Save() error  { return nil }

func newStore() Store { return &Blob{} }

// logBody is the shape that matters most: io.ReadCloser's real implementations
// live in the standard library, which is NOT lowered, so the ONLY candidate for
// this Close is some unrelated type that merely spells it. A lone candidate is
// the case most in need of rejecting, not least.
func logBody(body io.ReadCloser) { defer body.Close() }

func handler(w http.ResponseWriter, r *http.Request) {
	_ = &Ctx{r: r} // Ctx exists in the program, but nothing here calls its Query

	name := newRepo().Query(42) // argument type rules Ctx.Query out
	_ = exec.Command("sh", "-c", name)

	s := newStore()
	_ = s.Close() // method set rules Ctx.Close out
	_ = exec.Command("sh", "-c", s.Read())

	logBody(r.Body) // request-derived receiver; Ctx is not an io.ReadCloser
}

func main() {
	http.HandleFunc("/x", handler)
	_ = http.ListenAndServe(":8080", nil)
}
