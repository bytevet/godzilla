// Package varweb is an unmodeled web framework (no Godzilla rules) that registers
// route handlers VARIADICALLY — GET(path, ...HandlerFunc) — exactly like gin,
// echo, chi, and fiber. go/ssa lowers such a registration to a stack array whose
// elements are the (ChangeType-wrapped) handler funcs, sliced into the call, so
// the handler is only recognizable if collectRouteHandlers unwraps the variadic
// slice. Its bodies are lowered as a dependency, so request taint flows through
// them.
package varweb

type Ctx struct{ vals map[string]string }

func (c *Ctx) Query(key string) string { return c.vals[key] }

// Bind fills an out-parameter with request-derived data (framework-agnostic
// request-object provenance covers the pointer out-arg).
func (c *Ctx) Bind(dst *string) { *dst = c.vals["body"] }

type HandlerFunc func(c *Ctx)

type Router struct{}

func New() *Router { return &Router{} }

// GET registers handlers variadically (middleware... , handler).
func (r *Router) GET(path string, h ...HandlerFunc) {}
