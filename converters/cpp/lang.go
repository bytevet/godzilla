// Deliberately NOT build-tagged: internal/scan needs the C/C++ file predicate
// for language detection in the default (no-libLLVM) build too, so it lives
// outside the llvm-tagged converter and is the ONE definition both the scan
// layer and the tagged frontend share (the pattern IsJSFamily set).
package cpp_converter

import (
	"path/filepath"
	"strings"
)

var cppExts = map[string]bool{".c": true, ".cc": true, ".cpp": true, ".cxx": true, ".c++": true}

// IsCppFile reports whether path is a C or C++ translation unit this frontend
// compiles (not a header — clang can't compile one to a standalone module).
func IsCppFile(path string) bool { return cppExts[strings.ToLower(filepath.Ext(path))] }
