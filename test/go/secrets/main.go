package main

import "fmt"

func main() {
	// Vulnerable: hardcoded AWS access key ID (CWE-798)
	key := "AKIAIOSFODNN7EXAMPLE"
	fmt.Println(key)

	// Vulnerable: hardcoded JWT (CWE-798). This one is the regression guard for
	// the Go frontend's constant handling: at 84 characters it sits past the ~72
	// where go/constant's display Stringer used to truncate, and the JWT detector
	// needs all THREE dot-separated segments, so the truncated form matched
	// nothing. The identical literal in a .py file was reported — Go alone was
	// blind to it, and to every other long secret (SendGrid keys are 69 chars,
	// PEM bodies and DB connection URLs longer still).
	//
	// Payload decodes to {"sub":"1234567890","name":"John"} — a synthetic token.
	token := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.notarealsignature00"
	fmt.Println(token)
}
