//go:build !llvm

package corpus

// llvmBuilt is false in the default pure-Go build; the C/C++/Rust frontends are
// stubs, so their samples are skipped.
const llvmBuilt = false
