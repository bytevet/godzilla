package analysis

import (
	"testing"

	"godzilla/internal/rules"
)

// ssrfRule is a minimal CWE-918 rule over net/http.Get for the ENG-8 tests.
func ssrfRule() *rules.RuleSet {
	return &rules.RuleSet{Rules: []rules.Rule{{
		ID:        "GO-SSRF",
		Languages: []string{"go"},
		Severity:  rules.SeverityHigh,
		CWE:       "CWE-918",
		Message:   "ssrf",
		Sources:   []string{"go:*net/url*.Get"},
		Sinks:     []string{"go:*net/http.Get"},
		Propagators: []string{
			"go:fmt.Sprintf", "go:fmt.Sprint",
		},
	}}}
}

func ssrfFindings(t *testing.T, src string) int {
	t.Helper()
	n := 0
	for _, f := range scanSource(t, src, ssrfRule()) {
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
