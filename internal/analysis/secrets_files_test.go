package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

// Secret-shaped test values are assembled from fragments at runtime so no
// complete credential literal appears in a committed file (which would trip
// GitHub secret-scanning push protection — the tool dogfoods it).
const (
	awsKey    = "AKIA" + "IOSFODNN7EXAMPLE"
	stripeKey = "sk_live_" + "0123456789abcdefABCDEFxy"
	ghToken   = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"
	gitlabPAT = "glpat-" + "abcdef012345ABCDEF67"
	openaiKey = "sk-ant-" + "api03-abcdefghij0123456789XY"
	npmToken  = "npm_" + "0123456789abcdefghijklmnopqrstuvwxyz"
	sgWebhook = "https://hooks.slack.com/services/" + "T00000000/B11111111/abcdefghij0123456789"
	dbConnURL = "postgres://admin:" + "supersecret123" + "@db.internal:5432/app"
	mysqlConn = "mysql://root:" + "hunter2xx" + "@10.0.0.1:3306/db"
)

func TestScanSecretsInFiles_FindsConfigSecrets(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".env", "AWS_ACCESS_KEY_ID="+awsKey+"\n")
	write("docker-compose.yml", "environment:\n  DB: "+dbConnURL+"\n")
	write("app.config.json", `{"stripe":"`+stripeKey+`"}`)
	// A source file with a secret in it must be SKIPPED here (ScanSecrets covers
	// source-literal secrets via gIR; scanning it again would double-report).
	write("main.go", "package main\nconst k = \""+awsKey+"\"\n")

	findings := ScanSecretsInFiles(dir)
	got := map[string]int{}
	for _, f := range findings {
		got[f.RuleID]++
		if f.SinkPos == nil || f.SinkPos.GetLine() == 0 {
			t.Errorf("finding %s missing file:line position", f.RuleID)
		}
	}

	for _, want := range []string{"secret-aws-access-key", "secret-db-connection", "secret-stripe-key"} {
		if got[want] == 0 {
			t.Errorf("expected %s to fire in a config file, got findings %v", want, got)
		}
	}
	// The AWS key appears once in .env and once in main.go; only the .env one
	// should be reported here (main.go is skipped).
	if got["secret-aws-access-key"] != 1 {
		t.Errorf("source file must be skipped: expected exactly 1 AWS key finding, got %d", got["secret-aws-access-key"])
	}
}

func TestSecretPatterns_VendorPrefixes(t *testing.T) {
	cases := []struct {
		id  string
		hit string
	}{
		{"secret-github-token", ghToken},
		{"secret-gitlab-pat", gitlabPAT},
		{"secret-stripe-key", stripeKey},
		{"secret-openai-anthropic-key", openaiKey},
		{"secret-npm-token", npmToken},
		{"secret-slack-webhook", sgWebhook},
		{"secret-db-connection", mysqlConn},
	}
	for _, tc := range cases {
		seen := map[string]bool{}
		var findings []Finding
		scanText(tc.hit, nil, "", "", seen, &findings)
		hitIDs := map[string]bool{}
		for _, f := range findings {
			hitIDs[f.RuleID] = true
		}
		if !hitIDs[tc.id] {
			t.Errorf("expected %q to match %s, matched %v", tc.hit, tc.id, hitIDs)
		}
	}
}

func TestSecretPathExcluded(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// Vendored/build/venv/cache dirs — covered by reusing walkignore.SkipDir,
		// so a new walkignore skip-dir is honored here without editing this file.
		{"web/node_modules/pkg/config.json", true},
		{"vendor/github.com/x/y/creds.yaml", true},
		{".venv/lib/site.cfg", true},
		{"app/site-packages/foo/bar.env", true},
		{"dist/bundle.env", true},       // build output (walkignore, not the old list)
		{"target/debug/app.conf", true}, // Rust/Java build output (walkignore)
		{"__pycache__/x.txt", true},
		// Extras walkignore doesn't prune.
		{"/home/u/go/pkg/mod/example.com/lib@v1/k.yaml", true},
		{"app/.bundle/config", true},
		{"api/testdata/fixture.env", true},
		{"i18n/locales/en.json", true},
		{"src/translations/messages.yaml", true},
		{"docs/swagger.json", true},
		{"docs/openapi.yaml", true},
		{"internal/foo.test.js", true},
		{"internal/foo_test.go", true},
		// First-party config that MUST still be scanned.
		{"config/production.yaml", false},
		{"app.env", false},
		{"deploy/docker-compose.yml", false},
		{"cmd/server/main.go", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := secretPathExcluded(tc.path); got != tc.want {
			t.Errorf("secretPathExcluded(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestSecretPatterns_NoFalsePositiveOnPlaceholders(t *testing.T) {
	benign := []string{
		"password = os.Getenv(\"DB_PASSWORD\")",
		"api_key: ${API_KEY}",
		"DATABASE_URL=postgres://localhost:5432/app", // no user:pass@
		"token = process.env.TOKEN",
		"# see docs for how to set the stripe key",
	}
	for _, line := range benign {
		seen := map[string]bool{}
		var findings []Finding
		scanText(line, nil, "", "", seen, &findings)
		if len(findings) != 0 {
			t.Errorf("benign line should not fire a secret rule: %q -> %v", line, findings)
		}
	}
}
