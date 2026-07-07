// Package webctx is the safe control for stdlib_wrap: same shape (a lowered
// framework dependency), but the accessor returns a constant and never reads the
// request, so no taint reaches the caller. This guards against the net/http+
// net/url request-accessor propagators over-tainting.
package webctx

import "net/http"

type Ctx struct{ Request *http.Request }

// Query ignores the request entirely and returns a constant — no untrusted data.
func (c *Ctx) Query(key string) string {
	_ = c.Request
	return "safe"
}

type Router struct{}

func NewRouter() *Router { return &Router{} }

// GET registers h as the handler for path.
func (r *Router) GET(path string, h func(c *Ctx)) {}
