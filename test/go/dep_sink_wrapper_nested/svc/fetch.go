package svc

import "example.com/cmdutil"

// Fetch forwards its string parameter to the inner command wrapper (middle layer,
// no sink here). The summary must propagate through this forwarded string param.
func Fetch(cmd string) {
	cmdutil.Run(cmd)
}
