package go_converter

// SEAM STUB — the dependency-budget contract, landed ahead of its implementation
// so the pipeline and CLI can be built against it in parallel. selectRoots is
// deliberately a pass-through here: with no implementation, every candidate is
// kept and the frontend behaves exactly as it did before.

// rootCost is one candidate Phase-B syntax root and what it would cost to load:
// its package path, the byte size of its compiled Go files, and its import
// DEPTH from user code (0 = imported directly by a scanned package).
type rootCost struct {
	path  string
	bytes int64
	depth int
}

// selectRoots decides which third-party packages are promoted to Phase-B syntax
// roots under a source-byte budget. limit < 0 means unlimited.
func selectRoots(candidates []rootCost, limit int64) (keep, dropped []string) {
	for _, c := range candidates {
		keep = append(keep, c.path)
	}
	return keep, nil
}

// SetDepBudget caps the total source bytes of third-party dependency packages
// this converter will load as syntax roots. A negative limit (the zero value's
// meaning is set by NewConverter) is unlimited; anything the budget excludes is
// loaded as export data instead, giving it bodyless SSA — the same treatment the
// stdlib already gets. Returns c for chaining.
func (c *Converter) SetDepBudget(sourceBytes int64) *Converter {
	c.depBudget = sourceBytes
	return c
}

// Degraded reports whether the dependency budget forced part of the closure to
// be loaded as signatures only, plus a one-line note naming the counts for the
// scan's coverage record. False and "" for a scan that loaded its whole closure.
func (c *Converter) Degraded() (bool, string) {
	return c.degradedNote != "", c.degradedNote
}
