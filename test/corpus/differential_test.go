package corpus

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"godzilla/internal/rules/loader"
	"godzilla/internal/scan"
)

// TestDifferential_CommandInjection is a cross-language differential test for a
// SECOND vulnerability shape (command injection / CWE-78), complementing the
// SQL-injection differential in TestMultiLanguageScan. The same
// request-param -> shell-exec flow, written in Go, Python, and JavaScript, must
// be flagged by each language's command-injection rule from the one engine —
// the "write a rule once, it applies across every language" promise, verified
// for more than a single program shape (TRUST-8).
func TestDifferential_CommandInjection(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module diffcmdi\n\ngo 1.21\n")
	write("main.go", `package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	_ = exec.Command("sh", "-c", cmd).Run()
	_ = w
}

func main() { http.HandleFunc("/x", handler); _ = http.ListenAndServe(":0", nil) }
`)
	write("app.py", `from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/x")
def x():
    cmd = request.args.get("cmd")
    os.system("ping " + cmd)
    return "ok"
`)
	write("app.js", `var express = require("express");
var cp = require("child_process");
var app = express();
app.get("/x", function (req, res) {
  var cmd = req.query.cmd;
  cp.execSync(cmd);
  res.end("ok");
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

	if got["go-command-injection"] < 1 {
		t.Errorf("go-command-injection: want >= 1 from the Go file, got %d", got["go-command-injection"])
	}
	if got["js-command-injection"] < 1 {
		t.Errorf("js-command-injection: want >= 1 from the JS file, got %d", got["js-command-injection"])
	}
	if _, err := exec.LookPath("python3"); err == nil {
		if got["py-command-injection"] < 1 {
			t.Errorf("py-command-injection: want >= 1 from the Python file, got %d", got["py-command-injection"])
		}
	} else {
		t.Log("python3 not on PATH; skipping the Python assertion")
	}
}
