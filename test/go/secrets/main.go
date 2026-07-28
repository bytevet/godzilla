package main

import "fmt"

func main() {
	// Vulnerable: hardcoded AWS access key ID (CWE-798)
	key := "AKIAIOSFODNN7EXAMPLE"
	fmt.Println(key)

	// Vulnerable: hardcoded JWT (CWE-798). At 84 chars it also guards the Go
	// frontend's constant rendering, which used to truncate past ~72 and hide
	// every long secret (see constantText). Synthetic token.
	token := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.notarealsignature00"
	fmt.Println(token)
}
