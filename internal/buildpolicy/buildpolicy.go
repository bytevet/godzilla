// Package buildpolicy centralizes one security-sensitive decision: whether
// Godzilla may execute a SCANNED project's own build tooling — Maven/Gradle for
// Java, Cargo for Rust. Running those executes arbitrary code from the scanned
// repository (build.gradle logic, Maven plugins, Cargo build.rs scripts, and
// proc-macros) with the scanning process's privileges. For a tool whose whole
// job is scanning untrusted code in CI — including fork pull requests, where the
// runner holds real credentials — doing that by default turns the SAST tool
// itself into a remote-code-execution vector.
//
// So build execution is OFF by default and must be explicitly opted into
// (CLI -allow-build, or GODZILLA_ALLOW_BUILD=1). When it is off, the frontends
// fall back to their no-build path (in-process javac for Java, per-file rustc
// for Rust): dependency-resolved framework calls are not recovered, but the
// scan is safe and still analyzes the project's own code.
package buildpolicy

import "os"

// EnvAllowBuild is the environment variable that opts into build execution.
const EnvAllowBuild = "GODZILLA_ALLOW_BUILD"

// Allowed reports whether executing a scanned project's build tool is permitted.
func Allowed() bool {
	switch os.Getenv(EnvAllowBuild) {
	case "1", "true", "TRUE", "yes", "on":
		return true
	}
	return false
}

// SetAllowed records the decision in the environment so it is visible to the
// frontends (and inherited by any build subprocess). The CLI's -allow-build flag
// calls this.
func SetAllowed(v bool) {
	if v {
		_ = os.Setenv(EnvAllowBuild, "1")
	} else {
		_ = os.Unsetenv(EnvAllowBuild)
	}
}
