package go_converter

import "sort"

// rootCost is one candidate Phase-B syntax root and what it would cost to load:
// its package path, the byte size of its compiled Go files, and its import
// DEPTH from user code (0 = imported directly by a scanned package).
type rootCost struct {
	path  string
	bytes int64
	depth int
}

// selectRoots decides which third-party packages are promoted to Phase-B syntax
// roots under a source-byte budget. limit < 0 means unlimited; limit == 0 keeps
// nothing.
//
// Priority order is breadth-first by import depth from user code, ascending
// package size within a depth, package path to break ties (the whole scan is
// required to be byte-identical across runs). Depth alone cannot be the cut —
// on a large repo hop 1 is already several times the user's own source — but as
// a priority order under a byte budget it degrades toward "the libraries your
// code actually touches", and taking the small packages of a depth first buys
// the most packages per byte.
//
// The cut is hard: everything from the first candidate that does not fit is
// dropped, rather than skipping it to fit a later one. The order IS the
// priority, so letting a deeper package jump ahead of a nearer one it merely
// outbids on size would spend the budget on the closure's fringe.
func selectRoots(candidates []rootCost, limit int64) (keep, dropped []string) {
	// Unlimited: nothing is dropped and the priority order is never consulted, so
	// return before the copy and the sort. On a large closure that order is a few
	// thousand elements ranked for nothing. Phase-B roots must still be
	// deterministic, hence the sort by path.
	if limit < 0 {
		keep = make([]string, len(candidates))
		for i, c := range candidates {
			keep[i] = c.path
		}
		sort.Strings(keep)
		return keep, nil
	}

	order := make([]rootCost, len(candidates))
	copy(order, candidates)
	sort.Slice(order, func(i, j int) bool {
		a, b := order[i], order[j]
		switch {
		case a.depth != b.depth:
			return a.depth < b.depth
		case a.bytes != b.bytes:
			return a.bytes < b.bytes
		default:
			return a.path < b.path
		}
	})

	// A zero budget drops everything, and that is NOT derivable from the running
	// total below: a package whose files could not be stat'd measures zero bytes
	// and would otherwise fit inside a budget of zero.
	cut := 0
	if limit > 0 {
		cut = len(order)
		var total int64
		for i, c := range order {
			if total+c.bytes > limit {
				cut = i
				break
			}
			total += c.bytes
		}
	}

	for i, c := range order {
		if i < cut {
			keep = append(keep, c.path)
		} else {
			dropped = append(dropped, c.path)
		}
	}
	sort.Strings(keep) // deterministic Phase-B roots
	sort.Strings(dropped)
	return keep, dropped
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
