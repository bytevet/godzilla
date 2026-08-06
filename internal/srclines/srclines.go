// Package srclines is the shared source-file line cache used by every stage that
// re-reads scanned source to show or match lines: the HTML report's code
// snippets, the LLM reviewer's code context, and the inline godzilla:ignore
// sweep.
//
// A Cache is deliberately pass-scoped (one per report render / review pass /
// ignore sweep), never package-global, so a later scan of a changed file can
// never observe stale contents.
package srclines

import (
	"os"
	"strings"
)

// Cache memoizes source files split into lines. A nil entry records an
// unreadable file so it is not retried on later lookups. The zero value of the
// underlying map type is not usable; construct with Cache{}.
type Cache map[string][]string

// Lines returns filename's contents split on "\n", reading the file at most
// once per Cache. ok=false (with nil lines) when the file cannot be read; the
// failure is cached, so a missing file costs one failed read per pass, not one
// per lookup.
func (c Cache) Lines(filename string) ([]string, bool) {
	if lines, ok := c[filename]; ok {
		return lines, lines != nil
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		c[filename] = nil
		return nil, false
	}
	lines := strings.Split(string(data), "\n")
	c[filename] = lines
	return lines, true
}
