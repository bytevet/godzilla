package analysis

import (
	"testing"

	"github.com/bytevet/godzilla/internal/rules"
	"github.com/bytevet/godzilla/internal/testsupport"
)

// ssrfRule is a minimal CWE-918 rule over net/http.Get for the ENG-8 tests.
func ssrfRule(t testing.TB) *rules.RuleSet {
	return testsupport.OneRuleSet(t, "GO-SSRF", "go", "CWE-918",
		[]string{"go:*net/url*.Get"}, nil,
		testsupport.Message("ssrf"),
		// Host-fixedness is a RULE policy, not engine behaviour keyed on CWE-918,
		// so this rule declares it the same way the shipped SSRF packs do. Without
		// the guard the fixed-host request is reported, which is the correct new
		// default: a rule that does not ask for the suppression does not get it.
		testsupport.Sinks(rules.Sink{Pattern: "go:*net/http.Get", When: "not hostFixed()"}),
		testsupport.Propagators("go:fmt.Sprintf", "go:fmt.Sprint"))
}

func ssrfFindings(t *testing.T, src string) int {
	t.Helper()
	n := 0
	for _, f := range scanSource(t, src, ssrfRule(t)) {
		if f.RuleID == "GO-SSRF" {
			n++
		}
	}
	return n
}

// TestSSRF_HostControllableFires confirms that after the ENG-8 reorder (mark
// reported only on emit) a genuinely host-controllable SSRF still fires: taint
// reaches the URL's authority, so the request can be redirected.
func TestSSRF_HostControllableFires(t *testing.T) {
	src := `package main

import (
	"net/http"
	"net/url"
)

func h(u url.Values) {
	target := "http://" + u.Get("host") + "/api"
	_, _ = http.Get(target)
}

func main() { h(nil) }
`
	if n := ssrfFindings(t, src); n == 0 {
		t.Errorf("expected a host-controllable SSRF to fire, got 0")
	}
}

// TestSSRF_HostFixedSuppressed confirms the suppression path still holds after
// the reorder: taint confined to the path of a constant host is not an SSRF, and
// crucially the suppressed flow must NOT consume the sink's report slot (ENG-8).
func TestSSRF_HostFixedSuppressed(t *testing.T) {
	src := `package main

import (
	"net/http"
	"net/url"
)

func h(u url.Values) {
	target := "http://api.example.com/" + u.Get("path")
	_, _ = http.Get(target)
}

func main() { h(nil) }
`
	if n := ssrfFindings(t, src); n != 0 {
		t.Errorf("expected the path-confined (fixed-host) request to be suppressed, got %d", n)
	}
}
