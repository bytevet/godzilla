package cmdutil

import "os/exec"

// Run is a DEPENDENCY-side wrapper whose STRING parameter flows straight into a
// command-execution sink. A caller passing untrusted data here is vulnerable, so
// the engine summarizes this string-param sink flow (taintsParamSink) and the
// caller reports it at its own site.
func Run(cmd string) {
	_ = exec.Command("sh", "-c", cmd).Run()
}
