package js_converter

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzConvertJS fuzzes the full JS frontend (parse + the hand-written lowering)
// over untrusted source. A scanned repo's .js is attacker-influenced, so the
// lowering must never panic on any parseable-or-not input -- and the parser
// re-panics anything that is not a lexer panic, so hostile input reaches this
// package as a panic rather than an error.
func FuzzConvertJS(f *testing.F) {
	f.Add("const x = req.query.id; cp.exec(x);")
	f.Add("app.get('/', (req,res)=>{ res.send(req.query.x) })")
	f.Add("a.b.c(d).e(f).g")
	f.Add("class C { m(){ this.n() } }")
	f.Add("const {a,b} = require('x'); a(b)")
	f.Fuzz(func(t *testing.T, src string) {
		dir := t.TempDir()
		p := filepath.Join(dir, "f.js")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Skip()
		}
		_, _ = NewConverter().ConvertFile(p) // must not panic
	})
}
