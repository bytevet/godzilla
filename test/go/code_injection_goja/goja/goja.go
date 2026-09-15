// Package goja hermetically stands in for github.com/dop251/goja (an
// embedded JS interpreter), exactly like unknown_framework's miniweb: the
// sample's go.mod replaces the real import with this local module, so the
// canonical FQN the go-code-injection rule matches still comes from the real
// import path.
package goja

// Runtime is a JavaScript interpreter instance.
type Runtime struct{}

// New returns a new JS Runtime.
func New() *Runtime { return &Runtime{} }

// RunString compiles and executes s as JavaScript, returning its result.
func (r *Runtime) RunString(s string) (any, error) { return nil, nil }
