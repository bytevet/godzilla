package corpus

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"godzilla/internal/rules/loader"
	"godzilla/internal/scan"
)

// TestMultiLanguageScan exercises Godzilla's headline promise — one scan of a
// mixed-language project, one engine, findings from every language — which the
// per-language corpus samples (each a single-language dir) never cover. A single
// directory holds a Go module plus a Python and a JavaScript handler, each with
// the same SQL-injection shape; scan.Scan must merge all three frontends'
// modules and report a finding from each. The fixture is built in a temp dir so
// its go.mod does not interfere with the isolated sample-module build checks.
func TestMultiLanguageScan(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module mixed\n\ngo 1.21\n")
	write("main.go", `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	_, _ = db.Query("SELECT * FROM users WHERE id = '" + id + "'")
	_ = w
}

func main() { http.HandleFunc("/u", handler); _ = http.ListenAndServe(":0", nil) }
`)
	write("app.py", `from flask import Flask, request

app = Flask(__name__)
_cursor = None


@app.route("/u")
def u():
    uid = request.args.get("id")
    _cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return "ok"
`)
	write("app.js", `var express = require("express");
var db = require("some-db");
var app = express();
app.get("/u", function (req, res) {
  var id = req.query.id;
  res.send(db.query("SELECT * FROM users WHERE id = " + id));
});
module.exports = app;
`)

	rs, err := loader.Builtin()
	if err != nil {
		t.Fatalf("load built-in rules: %v", err)
	}
	res, err := scan.Scan(dir, rs)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := countByRule(res.Findings)

	// Go and JavaScript frontends are pure-Go and always available.
	if got["go-sql-injection"] < 1 {
		t.Errorf("go-sql-injection: want >= 1 from the Go file, got %d", got["go-sql-injection"])
	}
	if got["js-sqli"] < 1 {
		t.Errorf("js-sqli: want >= 1 from the JS file, got %d", got["js-sqli"])
	}
	// The Python frontend shells out to python3; only assert it when present.
	if _, err := exec.LookPath("python3"); err == nil {
		if got["py-sql-injection"] < 1 {
			t.Errorf("py-sql-injection: want >= 1 from the Python file, got %d", got["py-sql-injection"])
		}
	} else {
		t.Log("python3 not on PATH; skipping the Python assertion of the mixed scan")
	}
}
