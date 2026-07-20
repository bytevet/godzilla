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

// UpdateOptions mirrors a real options struct (e.g. gogs db.UpdateRepoFileOptions):
// the tainted form field is stored into it, then it is passed BY VALUE to a
// helper that reads the field back out at the sink.
type UpdateOptions struct {
	TreeName string
	Message  string
}

type Router struct{}

// bind is the binding-middleware marker (macaron/martini `binding.Bind`-style).
func bind(v interface{}) func() { return func() {} }

// Post registers a route handler: middleware(s) then the handler function.
func (r *Router) Post(pat string, mw func(), h func(c *Context, f EditRepoForm)) {}

// updateRepoFile reads opts.TreeName (a copied struct field) into a delete sink.
func updateRepoFile(opts UpdateOptions) {
	// Vulnerable: attacker-controlled tree path escapes the repo dir via "../".
	os.Remove(path.Join("/data/repos", opts.TreeName))
}

// EditFilePost is the route handler; f is the request-bound form.
func EditFilePost(c *Context, f EditRepoForm) {
	// f.TreePath (tainted) -> options struct field -> by-value call -> sink.
	updateRepoFile(UpdateOptions{TreeName: f.TreePath, Message: "edit"})
}

func main() {
	r := &Router{}
	r.Post("/edit", bind(EditRepoForm{}), EditFilePost)
}
