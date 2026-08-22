package playground

import (
	"os/exec"
	"runtime"
)

// openURL asks the desktop to open url. It is advisory: the server is already
// listening and its address is printed, so a headless or unusual desktop just
// means the user clicks the printed line instead.
func openURL(url string) error {
	name, args := "xdg-open", []string(nil)
	switch runtime.GOOS {
	case "darwin":
		name = "open"
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	}
	// url is passed as its own argument and never through a shell: it carries the
	// resolved listen address, and quoting it into a command string is the bug.
	return exec.Command(name, append(args, url)...).Start()
}
