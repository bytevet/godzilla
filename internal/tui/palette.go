package tui

// applyPalette fills in the per-stage colours. Placeholder pending the palette
// design; the table is the only thing that changes.
func applyPalette(p *palette) {
	p.trueHex = map[string]string{
		"walk": "#8b929e", "go.list": "#4c8dd0", "go.load": "#2fbfa8",
		"go.ssa": "#d3982f", "go.lower": "#7bb661",
		"index": "#a678de", "ruleselect": "#e0703f", "taint": "#e0554a",
	}
	p.idx256 = map[string]int{
		"walk": 245, "go.list": 68, "go.load": 43, "go.ssa": 178, "go.lower": 107,
		"index": 140, "ruleselect": 173, "taint": 167,
	}
	p.ansi16 = map[string]int{
		"walk": 90, "go.list": 94, "go.load": 96, "go.ssa": 93, "go.lower": 92,
		"index": 95, "ruleselect": 91, "taint": 31,
	}
}
