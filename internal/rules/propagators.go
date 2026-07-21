package rules

// Default propagators: library calls that return a transformed copy of their
// input and therefore CARRY taint from an argument to the result, but which no
// rule treats as a sanitizer. Real code almost never passes a raw source
// straight into a sink — it trims, lower-cases, re-encodes, or reformats the
// value first — so without these a single intervening stdlib string call
// silently drops taint and the injection slips past the gate (the dominant
// false-negative class). They apply to EVERY rule in addition to that rule's own
// propagators; the engine consults them only in the propagator position, so a
// rule's explicit source/sink/sanitizer for the same callee still wins.
//
// Deliberately conservative: only pure, taint-preserving string/encoding
// transforms are listed. Nothing here neutralizes an injection (escaping is not
// sanitizing for command/path/SQL contexts), and nothing here is used as a
// sanitizer by a built-in rule (path helpers like filepath.Base are omitted for
// exactly that reason). Patterns are language-prefixed canonical-name globs, so
// matching the union against a language-tagged callee is naturally
// language-correct.
var defaultPropagatorGlobs = []string{
	// --- Go: strings / fmt / url ---
	"go:*strings.TrimSpace", "go:*strings.Trim", "go:*strings.TrimLeft", "go:*strings.TrimRight",
	"go:*strings.TrimPrefix", "go:*strings.TrimSuffix", "go:*strings.ToLower", "go:*strings.ToUpper",
	"go:*strings.ToTitle", "go:*strings.Title", "go:*strings.Replace", "go:*strings.ReplaceAll",
	"go:*strings.Repeat", "go:*strings.Map", "go:*strings.Clone",
	"go:*strings.Builder*.String", "go:*strings.Builder*.Write*",
	"go:*fmt.Sprintf", "go:*fmt.Sprint", "go:*fmt.Sprintln",
	"go:*net/url.QueryEscape", "go:*net/url.QueryUnescape", "go:*net/url.PathEscape", "go:*net/url.PathUnescape",
	// net/http + net/url request accessors: carry request taint through a lowered
	// framework's INTERNAL stdlib parsing. A framework wraps the request in its own
	// context type (gin.Context, echo.Context, …) and reads it via these stdlib
	// helpers — e.g. gin's c.Query bottoms out in c.Request.URL.Query() — but the
	// stdlib is not lowered, so without these the flow dies inside the library and
	// only frameworks with an explicit accessor source glob are covered. Modeled as
	// propagators (not sources): the receiver is Call.Value, already tainted only
	// when it derives from a request source, so ordinary code is untouched.
	"go:*net/url*.Query", "go:*net/url*.ParseQuery", "go:*net/url.Values*.Get",
	"go:*net/http.Request*.FormValue", "go:*net/http.Request*.PostFormValue",
	"go:*net/http.Request*.FormFile", "go:*net/http.Request*.Cookie",
	"go:*net/http.Request*.Referer", "go:*net/http.Request*.UserAgent",
	"go:*net/http.Header*.Get", "go:*net/http.Header*.Values",
	// html/template trusted-string conversions (synthesized as CALLs by the Go
	// frontend, see emitTemplateTrustedConv). They are XSS SINKS in go-xss, but
	// for every OTHER rule they must still forward taint arg->result exactly as
	// the plain type conversion did, so a flow that passes through one before
	// reaching a different sink is not lost. (The switch checks sink before
	// propagator, so the go-xss sink still wins for that rule.)
	"go:html/template.HTML", "go:html/template.HTMLAttr", "go:html/template.JS",
	"go:html/template.JSStr", "go:html/template.URL", "go:html/template.CSS",
	"go:html/template.Srcset",
	// NOTE: the Go `append` builtin is NOT a blanket propagator — append is called
	// on every slice in a program, so carrying taint through all of them explodes
	// the taint set in framework code (a large dep-heavy scan slowdown). It is
	// propagated ONLY when its result is a byte/rune slice — character-level string
	// reconstruction (the make([]byte); append(data, s[i]); string(data) idiom of a
	// non-sanitizing normalize helper) — gated by isByteOrRuneSlice in the engine's
	// handleCall, not here.

	// --- Python: str methods / builtins ---
	"py:*.strip", "py:*.lstrip", "py:*.rstrip", "py:*.lower", "py:*.upper", "py:*.title",
	"py:*.replace", "py:*.format", "py:*.encode", "py:*.decode", "py:*.casefold",
	// split/join carry taint through the extremely common "split on a delimiter,
	// keep some parts, re-join" idiom (e.g. Streamlit CVE-2022-35918:
	// path.split('/') -> '/'.join(parts[1:]) -> os.path.join -> open). str.split
	// yields a tainted list; sep.join re-joins a tainted list into a tainted str.
	"py:*.split", "py:*.rsplit", "py:*.splitlines", "py:*.partition", "py:*.rpartition", "py:*.join",
	"py:*str", "py:*repr",

	// --- JavaScript: String methods / URI encoders ---
	"js:*.trim", "js:*.trimStart", "js:*.trimEnd", "js:*.toLowerCase", "js:*.toUpperCase",
	"js:*.replace", "js:*.replaceAll", "js:*.substring", "js:*.substr", "js:*.slice",
	"js:*.concat", "js:*.padStart", "js:*.padEnd", "js:*.toString", "js:*.normalize",
	"js:*encodeURIComponent", "js:*encodeURI", "js:*decodeURIComponent", "js:*decodeURI",

	// --- Java: String / StringBuilder ---
	"java:*String.trim", "java:*String.strip", "java:*String.toLowerCase", "java:*String.toUpperCase",
	"java:*String.replace", "java:*String.replaceAll", "java:*String.substring", "java:*String.concat",
	"java:*String.format", "java:*String.valueOf", "java:*StringBuilder.append", "java:*StringBuilder.toString",

	// --- Rust: str/String transforms ---
	"rust:*to_string", "rust:*to_owned", "rust:*trim", "rust:*trim_start", "rust:*trim_end",
	"rust:*to_lowercase", "rust:*to_uppercase", "rust:*replace", "rust:*replacen",
	"rust:*to_str", "rust:*as_str", "rust:*into_string",
}

// defaultPropagatorMatchers is defaultPropagatorGlobs precompiled once at init.
// IsDefaultPropagator runs on the hot per-(call-site × rule) classification path
// inside the parallel per-rule goroutines, so matching precompiled shape-matchers
// (like rule-owned globs after Rule.Compile) avoids the ~48 mutexed globCache
// lookups a raw MatchAny would do on every invocation.
var defaultPropagatorMatchers = classifyAll(defaultPropagatorGlobs)

// IsDefaultPropagator reports whether callee is one of the built-in,
// taint-preserving library transforms that carry taint from argument to result
// regardless of the active rule. See defaultPropagatorGlobs.
func IsDefaultPropagator(callee string) bool {
	return matchAnyCompiled(defaultPropagatorMatchers, callee)
}
