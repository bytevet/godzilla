// Sample for the dangerous-call (non-dataflow) rule kind (COV-4): a weak hash
// and a weak cipher, each flagged at their call site with no taint tracking.
package main

import (
	"crypto/des"
	"crypto/md5"
	"fmt"
)

func main() {
	h := md5.New()          // go-weak-hash
	c, _ := des.NewCipher([]byte("8bytekey")) // go-weak-cipher
	fmt.Println(h, c)
}
