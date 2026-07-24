package cmdutil

import "os/exec"

// Run's string parameter flows into a command sink (innermost wrapper).
func Run(cmd string) {
	_ = exec.Command("sh", "-c", cmd).Run()
}
