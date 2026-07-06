// Package miniweb is a stand-in for a web framework Godzilla has no rules for.
// It is a separate module so its method bodies are dependencies (not lowered),
// exactly like a real third-party framework.
package miniweb

type Ctx struct{ req map[string]string }

func (c *Ctx) Query(key string) string { return c.req[key] }
func (c *Ctx) Bind(dst *string)        { *dst = c.req["body"] }

type Router struct{}

func NewRouter() *Router { return &Router{} }

// GET registers h as the handler for path.
func (r *Router) GET(path string, h func(c *Ctx)) {}
