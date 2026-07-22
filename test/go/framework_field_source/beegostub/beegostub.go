// Package beegostub mimics beego/macaron: a Controller whose accessor reads the
// inbound *http.Request through an instance FIELD internally. The framework (not
// user code) populates Ctx.Request during dispatch, so from the analyzer's view
// the *http.Request field read inside Input is an inbound-request ORIGIN
// (converters/go addHTTPRequestSource plants a synthetic source there) and Input
// takes no tainted argument. Its bodies are lowered as a dependency.
package beegostub

import "net/http"

type Context struct{ Request *http.Request }

type Controller struct{ Ctx *Context }

// Input reads a query param off the framework-populated request. Untrusted.
func (c *Controller) Input(key string) string {
	return c.Ctx.Request.URL.Query().Get(key)
}

// SafeInput reads the request but returns a CONSTANT — used by the safe control
// to show the seeded body analysis is precise (no tainted return => no finding).
func (c *Controller) SafeInput(key string) string {
	_ = c.Ctx.Request.URL.Query().Get(key)
	return "default"
}

// Serve is the dispatch entry. It is deliberately NOT a routing verb, so the
// frontend does not seed the action's Controller param as a request object —
// the request taint must originate inside Input (the reqSourceHosts path).
func Serve(action func(*Controller)) {}
