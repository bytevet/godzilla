package rules

import "testing"

func TestIsDefaultPropagator(t *testing.T) {
	shouldMatch := []string{
		"go:strings.TrimSpace",
		"go:strings.ToLower",
		"go:fmt.Sprintf",
		"go:net/url.QueryEscape",
		"py:request.args.get.strip", // py:*.strip
		"py:x.lower",
		"js:req.query.id.trim",  // js:*.trim
		"js:s.toLowerCase",      // js:*.toLowerCase
		"js:encodeURIComponent", // js:*encodeURIComponent
		"java:java/lang/String.trim",
		"java:java/lang/StringBuilder.append",
		"rust:*String::to_lowercase",
		"rust:str::trim",
		// Go net/http + net/url request accessors (canonical format is pkg-inside
		// parens, e.g. "go:(*net/url.URL).Query" — see rule.go / converter.go).
		// These carry request taint through a lowered framework's stdlib parsing.
		"go:(*net/url.URL).Query",          // *url.URL -> url.Values (the gin path)
		"go:net/url.ParseQuery",            // string -> url.Values
		"go:(net/url.Values).Get",          // url.Values -> string
		"go:(*net/http.Request).FormValue", // *http.Request -> string
		"go:(*net/http.Request).Cookie",    // *http.Request -> *http.Cookie
		"go:(net/http.Header).Get",         // http.Header -> string
		// The Go `append` builtin: appending tainted bytes yields a tainted slice,
		// which carries taint through character-level string reconstruction.
		"builtin.append",
	}
	for _, c := range shouldMatch {
		if !IsDefaultPropagator(c) {
			t.Errorf("expected %q to be a default propagator", c)
		}
	}

	shouldNotMatch := []string{
		"go:os/exec.Command",          // a sink, must not propagate by default
		"go:(*database/sql.DB).Query", // a sink — the net/url*.Query glob must not leak onto it
		"py:os.system",                // a sink
		"js:child_process.exec",       // a sink
		"go:strings.Contains",         // returns bool, not a taint carrier we list
	}
	for _, c := range shouldNotMatch {
		if IsDefaultPropagator(c) {
			t.Errorf("did not expect %q to be a default propagator", c)
		}
	}
}
