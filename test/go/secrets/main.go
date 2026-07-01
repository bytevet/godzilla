package main

import "fmt"

func main() {
	// Vulnerable: hardcoded AWS access key ID (CWE-798)
	key := "AKIAIOSFODNN7EXAMPLE"
	fmt.Println(key)
}
