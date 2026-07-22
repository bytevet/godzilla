package main

import (
	"os"
	"path"
)

// Context is the framework context (pointer => the handler's context param).
type Context struct{ userID int64 }

// EditRepoForm is a bound form; the binding middleware fills it from the request.
// A route handler receives it BY VALUE, which is the low-FP signal the frontend
// keys on (a context/service is a pointer or interface, not a value struct).
type EditRepoForm struct {
	TreePath string
	Content  string
}

type Router struct{}

// bind is the binding-middleware marker (macaron/martini `binding.Bind`-style).
func bind(v interface{}) func() { return func() {} }

// Post registers a route handler: middleware(s) then the handler function.
func (r *Router) Post(pat string, mw func(), h func(c *Context, f EditRepoForm)) {}

// updateRepoFile reads the attacker-controlled tree path into a delete sink.
func updateRepoFile(treePath string) {
	// Vulnerable: a crafted "../" tree path escapes the repo dir (CWE-22).
	os.Remove(path.Join("/data/repos", treePath))
}

// EditFilePost is the route handler; f is the request-bound form.
func EditFilePost(c *Context, f EditRepoForm) {
	// f.TreePath is tainted because f is bound from the request by the middleware.
	updateRepoFile(f.TreePath)
}

func main() {
	r := &Router{}
	r.Post("/edit", bind(EditRepoForm{}), EditFilePost)
}
