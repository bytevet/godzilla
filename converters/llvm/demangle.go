//go:build llvm

package llvm_converter

import (
	"strings"

	"github.com/ianlancetaylor/demangle"
)

// stripLLVM removes the LLVM "\01" literal-name marker (used to suppress the
// target's global symbol prefix, e.g. the header-declared `\01_system`).
func stripLLVM(sym string) string { return strings.TrimPrefix(sym, "\x01") }

// CDemangle normalizes a C symbol: drop the LLVM marker and the platform leading
// underscore (macOS prefixes `_`), so `\01_system`, `_system`, and `system` all
// canonicalize to `system`. C is not name-mangled otherwise.
func CDemangle(sym string) string {
	return strings.TrimPrefix(stripLLVM(sym), "_")
}

// CppDemangle demangles an Itanium C++ symbol (`_Z...`) to a readable name like
// `std::system` or `MyClass::run` (parameter/template args dropped for a stable,
// glob-friendly name). extern "C" / non-mangled symbols get the plain-C
// treatment.
func CppDemangle(sym string) string {
	name := stripLLVM(sym)
	if strings.HasPrefix(name, "_Z") || strings.HasPrefix(name, "_R") {
		return strings.TrimSpace(demangle.Filter(name, demangle.NoParams, demangle.NoTemplateParams))
	}
	return strings.TrimPrefix(name, "_")
}
