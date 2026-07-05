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
	}
	for _, c := range shouldMatch {
		if !IsDefaultPropagator(c) {
			t.Errorf("expected %q to be a default propagator", c)
		}
	}

	shouldNotMatch := []string{
		"go:os/exec.Command",               // a sink, must not propagate by default
		"go:database/sql.(*DB).Query",      // a sink
		"go:net/http.(*Request).FormValue", // a source
		"py:os.system",                     // a sink
		"js:child_process.exec",            // a sink
		"go:strings.Contains",              // returns bool, not a taint carrier we list
	}
	for _, c := range shouldNotMatch {
		if IsDefaultPropagator(c) {
			t.Errorf("did not expect %q to be a default propagator", c)
		}
	}
}
