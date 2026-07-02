//go:build !llvm

// Package cpp_converter's default-build stub: C/C++ analysis requires libLLVM,
// which is only linked under the `llvm` build tag. See converter.go.
package cpp_converter

import (
	"fmt"

	ir "godzilla/pkg/ir/v1"
)

type Converter struct{}

func NewConverter() *Converter { return &Converter{} }

func (c *Converter) ConvertFile(path string) (*ir.Program, error) {
	return nil, fmt.Errorf("C/C++ analysis requires building Godzilla with -tags llvm (libLLVM); rebuild to scan %s", path)
}
