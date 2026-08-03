//go:build !llvm

// Package cpp_converter's default-build stub: C/C++ analysis requires libLLVM,
// which is only linked under the `llvm` build tag. See converter.go.
package cpp_converter

import (
	"fmt"

	"godzilla/internal/walkignore"
	ir "godzilla/pkg/ir/v1"
)

type Converter struct{}

func NewConverter() *Converter { return &Converter{} }

func (c *Converter) ConvertFile(path string) (*ir.Program, error) {
	return nil, fmt.Errorf("C/C++ analysis requires building Godzilla with -tags llvm (libLLVM); rebuild to scan %s", path)
}

// ConvertInventory mirrors the llvm-tagged converter's inventory entry point so
// the scan pipeline can plumb its cached walk uniformly; like ConvertFile it
// only reports that this build lacks the C/C++ backend.
func (c *Converter) ConvertInventory(inv *walkignore.Inventory) (*ir.Program, error) {
	return c.ConvertFile(inv.Root())
}
