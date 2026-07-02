//go:build !llvm

// Package rust_converter's default-build stub: Rust analysis requires libLLVM,
// which is only linked under the `llvm` build tag. See converter.go.
package rust_converter

import (
	"fmt"

	ir "godzilla/pkg/ir/v1"
)

type Converter struct{}

func NewConverter() *Converter { return &Converter{} }

func (c *Converter) ConvertFile(path string) (*ir.Program, error) {
	return nil, fmt.Errorf("Rust analysis requires building Godzilla with -tags llvm (libLLVM); rebuild to scan %s", path)
}
