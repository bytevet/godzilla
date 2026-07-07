// Package webctx stands in for a web framework Godzilla has NO rules for (like
// gin/echo/fiber). It is a separate module so its method bodies are lowered
// dependencies — exactly like a real third-party framework — and, critically, it
// reads the request through the STDLIB (c.Request.URL.Query()), which is NOT
// lowered. Taint therefore reaches the caller only if the stdlib request
// accessors (net/url.URL.Query, net/url.Values.Get) are modeled as propagators.
package webctx

import "net/http"

type Ctx struct{ Request *http.Request }

// Query mirrors gin's c.Query, which bottoms out in c.Request.URL.Query() and
// reads the resulting url.Values with a MAP INDEX (not the .Get accessor, which
// is already a source glob). Without the net/url request-accessor default
// propagators the taint on c.Request dies at .Query(), so the map read is clean
// and this is a false negative even though the body is lowered.
func (c *Ctx) Query(key string) string {
	vals := c.Request.URL.Query() // url.Values = map[string][]string, stdlib-parsed
	return vals[key][0]
}

type Router struct{}

func NewRouter() *Router { return &Router{} }

// GET registers h as the handler for path (a routing verb, so the frontend taints
// the handler's *Ctx parameter).
func (r *Router) GET(path string, h func(c *Ctx)) {}
