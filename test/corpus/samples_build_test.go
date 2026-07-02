package corpus

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSampleModulesBuild compile-checks each isolated Go sample module
// (test/go/*/go.mod), which the root module's `go test ./...` otherwise skips
// entirely — so a sample that stops compiling would go unnoticed. It runs
// `go build` (output discarded to a temp dir so no binary pollutes the sample
// directory) and `go vet ./...` inside each sample module.
//
// These are real (cgo-enabled) builds, so the test is skipped under -short for a
// fast inner loop: `go test -short ./...`.
func TestSampleModulesBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping isolated sample-module builds under -short")
	}

	gomods, err := filepath.Glob(filepath.Join("..", "go", "*", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if len(gomods) == 0 {
		t.Fatal("no isolated Go sample modules found under test/go/*")
	}

	for _, gomod := range gomods {
		dir := filepath.Dir(gomod)
		t.Run(filepath.ToSlash(filepath.Join("go", filepath.Base(dir))), func(t *testing.T) {
			// Build into a throwaway dir so no compiled binary is left behind in
			// the sample directory (which would show up as an untracked file).
			outDir := t.TempDir()
			steps := [][]string{
				{"build", "-o", outDir + string(os.PathSeparator), "./..."},
				{"vet", "./..."},
			}
			for _, args := range steps {
				cmd := exec.Command("go", args...)
				cmd.Dir = dir
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("`go %v` failed in %s: %v\n%s", args, dir, err, out)
				}
			}
		})
	}
}
