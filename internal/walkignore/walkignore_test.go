package walkignore

import "testing"

func TestSkipDir(t *testing.T) {
	skip := []string{"node_modules", ".git", ".venv", "venv", "site-packages", "target", "dist", "build", "vendor", "__pycache__", ".gradle", ".next"}
	for _, d := range skip {
		if !SkipDir(d) {
			t.Errorf("expected %q to be skipped", d)
		}
	}
	keep := []string{"src", "app", "internal", "handlers", "lib", "cmd", "converters"}
	for _, d := range keep {
		if SkipDir(d) {
			t.Errorf("did not expect real source dir %q to be skipped", d)
		}
	}
}

func TestSkipFile(t *testing.T) {
	skip := []string{"app.min.js", "vendor.bundle.js", "site.min.css", "app.js.map", "types.d.ts"}
	for _, f := range skip {
		if !SkipFile(f) {
			t.Errorf("expected generated file %q to be skipped", f)
		}
	}
	keep := []string{"app.js", "index.ts", "main.go", "server.mjs", "handler.py"}
	for _, f := range keep {
		if SkipFile(f) {
			t.Errorf("did not expect real source %q to be skipped", f)
		}
	}
}

func TestTooBig(t *testing.T) {
	if TooBig(1000) {
		t.Error("a 1 KB file must not be too big")
	}
	if !TooBig(MaxSourceBytes + 1) {
		t.Error("a file over the cap must be too big")
	}
}
