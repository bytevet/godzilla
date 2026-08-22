package playground

import (
	"os"

	cpp_converter "github.com/bytevet/godzilla/converters/cpp"
	go_converter "github.com/bytevet/godzilla/converters/go"
	java_converter "github.com/bytevet/godzilla/converters/java"
	js_converter "github.com/bytevet/godzilla/converters/javascript"
	py_converter "github.com/bytevet/godzilla/converters/python"
	ruby_converter "github.com/bytevet/godzilla/converters/ruby"
	rust_converter "github.com/bytevet/godzilla/converters/rust"
)

// frontendExts asks each frontend's OWN extension predicate which language a
// file belongs to, in internal/scan's table order (first match wins). Reusing
// the predicates rather than restating a list of suffixes is what stops the
// tree's idea of "this file has a frontend" from drifting from the scan's.
var frontendExts = []struct {
	name    string
	matches func(string) bool
}{
	{"go", go_converter.IsGoFile},
	{"python", py_converter.IsPythonFile},
	{"javascript", js_converter.IsJSFamily},
	{"java", java_converter.IsJavaFile},
	{"cpp", cpp_converter.IsCppFile},
	{"rust", rust_converter.IsRustFile},
	{"ruby", ruby_converter.IsRubyFile},
}

// languageOf reports which frontend is responsible for path. ok is false when no
// frontend handles it — which is the difference between "this file was skipped"
// and "no rule could ever match it".
func languageOf(path string) (lang string, ok bool) {
	for _, fe := range frontendExts {
		if fe.matches(path) {
			return fe.name, true
		}
	}
	return "", false
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
