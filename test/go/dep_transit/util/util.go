// Package util stands in for a third-party helper library. Its body is analyzed
// only because dependency lowering is on; Transform passes its argument through
// (concatenation), which no rule models as a propagator — so taint reaches it
// ONLY by analyzing this function.
package util

func Transform(s string) string { return "echo " + s }

// Constant ignores its input, so taint must NOT flow through it.
func Constant(s string) string { return "echo safe" }
