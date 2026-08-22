// Package playground serves the gIR Playground: a local web UI that shows what
// a frontend lowered a project to, and what the loaded rules make of it.
//
// Its reason to exist is that both halves of a rule are invisible from source.
// A rule matches a canonical name and pins an injection point by LOGICAL
// argument index (`go:*gorm*.DB*.Raw#0`), where a statically-resolved method
// call carries its receiver as args[0] — so the index a rule pins is one less
// than the array index, and getting it wrong fails silently, selecting a real
// argument that is simply not the intended one.
//
// Two rules keep this tool honest, and both are structural:
//
//   - Nothing here re-implements matching. Sink/source classification and the
//     pattern tester both go through internal/rules, so what the UI draws is the
//     engine's verdict. A second matcher that agreed today would drift.
//   - One scan per invocation. The program is lowered once by internal/scan and
//     then only read, so what is on screen is what the command saw.
package playground

import (
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/bytevet/godzilla/internal/analysis"
	"github.com/bytevet/godzilla/internal/irwalk"
	"github.com/bytevet/godzilla/internal/rules"
	"github.com/bytevet/godzilla/internal/scan"
	"github.com/bytevet/godzilla/internal/srclines"
	"github.com/bytevet/godzilla/internal/walkignore"
	ir "github.com/bytevet/godzilla/pkg/ir/v1"
)

// Empty-state ids, the UI's own vocabulary. stateFailed carries the weight: a
// file with no gIR is invisible to EVERY rule, which reads as "clean" unless it
// is said out loud.
const (
	stateNoFunc = "empty-nofunc" // lowered, but declares no functions
	stateFailed = "empty-failed" // a frontend was responsible and produced nothing
)

// fileEntry is one row of the file tree, plus the gIR attributed to that file.
// The gIR view is built on demand: a large scan holds thousands of functions and
// only the file being looked at needs rendering.
type fileEntry struct {
	ID          string `json:"id"` // scan-root-relative, slash-separated
	Path        string `json:"path"`
	Lang        string `json:"lang,omitempty"`
	Findings    int    `json:"findings,omitempty"`
	State       string `json:"state,omitempty"`
	StateDetail string `json:"stateDetail,omitempty"`

	abs  string
	mod  *ir.Module
	fns  []*ir.Function
	glbs []*ir.Global
	typs []*ir.Type

	once sync.Once
	view *fileView
}

type fileView struct {
	ID       string     `json:"id"`
	Path     string     `json:"path"`
	Lang     string     `json:"lang"`
	Findings int        `json:"findings"`
	Src      []string   `json:"src"`
	Module   moduleView `json:"module"`

	// ords maps an instruction's emission ordinal to the instruction, so
	// /api/match can answer in the same coordinates the client rendered.
	ords []*ir.Instruction
}

type presetView struct {
	Sinks       []string `json:"sinks"`
	Sources     []string `json:"sources"`
	Propagators []string `json:"propagators"`
}

// Index is the whole served state: one lowered program, indexed by source file.
type Index struct {
	root    string // absolute scan root
	version string
	rs      *rules.RuleSet
	cls     *classifier

	files   []*fileEntry
	byID    map[string]*fileEntry
	presets presetView

	mu    sync.Mutex
	lines srclines.Cache
}

// NewIndex indexes a completed scan for serving. target is the path the user
// asked for; res.Program is the merged gIR, which internal/scan already retains.
func NewIndex(res scan.Result, target, version string, rs *rules.RuleSet) *Index {
	root := absOf(target)
	// A single-file target roots the tree at its directory, so the one row is not
	// drawn as a folderless orphan.
	if !isDir(target) {
		root = filepath.Dir(root)
	}

	idx := &Index{
		root:    root,
		version: version,
		rs:      rs,
		cls:     newClassifier(rs),
		byID:    map[string]*fileEntry{},
		lines:   srclines.Cache{},
	}
	idx.collectGIR(res.Program)
	idx.countFindings(res.Findings)
	idx.addMissingFiles(target, res.Coverage)
	idx.sortFiles()
	idx.presets = idx.cls.presets(idx.userCallees())
	return idx
}

// entryFor returns (creating if needed) the row for an absolute source path,
// or nil when the file sits outside the scan root. The Go frontend lowers
// dependency BODIES, so the program carries the whole module cache; dropping
// those here is what keeps the tree to user code, the same scoping decision
// internal/scan's scopeFindings makes for findings.
func (idx *Index) entryFor(abs string) *fileEntry {
	id, ok := idx.relID(abs)
	if !ok {
		return nil
	}
	if e, ok := idx.byID[id]; ok {
		return e
	}
	e := &fileEntry{ID: id, Path: id, abs: abs}
	idx.byID[id] = e
	idx.files = append(idx.files, e)
	return e
}

// collectGIR attributes every function, global and named type to the source file
// its Position names. gIR's unit is a module (one Go package spans many files);
// the UI's unit is a file, and a Position is the only thing that bridges them.
func (idx *Index) collectGIR(prog *ir.Program) {
	for mod, fn := range irwalk.Funcs(prog) {
		e := idx.entryFor(absOf(fnFile(fn)))
		if e == nil {
			continue
		}
		idx.adopt(e, mod)
		e.fns = append(e.fns, fn)
	}
	for _, mod := range prog.GetModules() {
		if mod == nil {
			continue
		}
		for _, g := range mod.GetGlobals() {
			if e := idx.entryFor(absOf(g.GetPos().GetFilename())); e != nil {
				idx.adopt(e, mod)
				e.glbs = append(e.glbs, g)
			}
		}
		for _, t := range mod.GetTypes() {
			if e := idx.entryFor(absOf(t.GetPos().GetFilename())); e != nil {
				idx.adopt(e, mod)
				e.typs = append(e.typs, t)
			}
		}
	}
}

// adopt records which module a file's gIR came from. A file is normally lowered
// by exactly one frontend; the first module wins if that ever stops holding, so
// the language label stays stable rather than flapping.
func (idx *Index) adopt(e *fileEntry, mod *ir.Module) {
	if e.mod == nil {
		e.mod = mod
		e.Lang = mod.GetLanguage()
	}
}

// fnFile is a function's source file: its own Position, or the first instruction
// that has one. A synthetic wrapper carries no Position of its own but its body
// still points at real source.
func fnFile(fn *ir.Function) string {
	if f := fn.GetPos().GetFilename(); f != "" {
		return f
	}
	for in := range irwalk.Instrs(fn) {
		if f := in.GetPos().GetFilename(); f != "" {
			return f
		}
	}
	return ""
}

// relID is a file's tree id: its path relative to the scan root, or ok=false
// when it lies outside. THE one place that decision is made — the Go frontend
// lowers dependency bodies, so "outside the root" is a large and load-bearing
// set, and a second spelling of this test would eventually disagree.
func (idx *Index) relID(abs string) (string, bool) {
	if abs == "" {
		return "", false
	}
	rel, err := filepath.Rel(idx.root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

func (idx *Index) countFindings(findings []analysis.Finding) {
	for _, f := range findings {
		id, ok := idx.relID(absOf(f.SinkPos.GetFilename()))
		if !ok {
			continue
		}
		if e, ok := idx.byID[id]; ok {
			e.Findings++
		}
	}
}

// addMissingFiles lists the source files the walk found that produced NO gIR,
// and says why. This is the point of showing them at all: a file with no gIR is
// invisible to every rule, which reads as "clean" unless it is surfaced.
func (idx *Index) addMissingFiles(target string, coverage []scan.LangCoverage) {
	covByLang := map[string]scan.LangCoverage{}
	for _, c := range coverage {
		covByLang[c.Language] = c
	}
	for _, p := range sourceCandidates(target) {
		abs := absOf(p)
		id, inRoot := idx.relID(abs)
		if !inRoot {
			continue
		}
		if _, ok := idx.byID[id]; ok {
			continue // it lowered; nothing to explain
		}
		lang, _ := languageOf(p)
		e := &fileEntry{ID: id, Path: id, abs: abs, Lang: lang, State: stateFailed}
		// The frontend's own error is the useful half — a C/C++ file in a build
		// without the llvm tag says exactly that, and a build failure names itself.
		if cov, seen := covByLang[lang]; seen && cov.Err != "" {
			e.StateDetail = "The " + lang + " frontend failed: " + cov.Err +
				" — this file's sinks are invisible to every rule."
		} else {
			e.StateDetail = "The " + lang + " frontend ran but produced no gIR for this file, " +
				"so its sinks are invisible to every rule."
		}
		idx.byID[id] = e
		idx.files = append(idx.files, e)
	}
	// A file that lowered but declares nothing callable is a different, milder
	// story than a failure, and worth telling apart.
	for _, e := range idx.files {
		if e.State == "" && len(e.fns) == 0 {
			e.State = stateNoFunc
			e.StateDetail = "The file parsed cleanly but declares no functions, so there is nothing to lower."
		}
	}
}

// sourceCandidates lists the SOURCE files a scan of target would consider, off
// the same pruned walk the scan itself used so the tree cannot disagree with it.
// Restricted to files some frontend claims: a file no frontend claims is not a
// gap in coverage, it is just not code.
func sourceCandidates(target string) []string {
	var all []string
	if isDir(target) {
		all = walkignore.NewInventory(target).Files()
	} else {
		all = []string{target}
	}
	out := make([]string, 0, len(all))
	for _, p := range all {
		if _, ok := languageOf(p); ok {
			out = append(out, p)
		}
	}
	return out
}

// userCallees is every distinct callee in the files the tree shows.
func (idx *Index) userCallees() map[string]bool {
	callees := map[string]bool{}
	for _, e := range idx.files {
		for _, fn := range e.fns {
			for in := range irwalk.Instrs(fn) {
				if n := in.GetCall().GetCallee(); n != "" {
					callees[n] = true
				}
			}
		}
	}
	return callees
}

func (idx *Index) sortFiles() {
	sort.Slice(idx.files, func(i, j int) bool { return idx.files[i].ID < idx.files[j].ID })
}

func absOf(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	a, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return a
}

// Files returns the tree rows.
func (idx *Index) Files() []*fileEntry { return idx.files }

// View renders (once) the gIR for one file.
func (idx *Index) View(id string) *fileView {
	e, ok := idx.byID[id]
	if !ok || e.State != "" {
		return nil
	}
	e.once.Do(func() { e.view = idx.build(e) })
	return e.view
}

func (idx *Index) build(e *fileEntry) *fileView {
	fv := &fileView{
		ID: e.ID, Path: e.Path, Lang: e.Lang, Findings: e.Findings,
		Src: idx.source(e.abs),
		Module: moduleView{
			Name:      e.mod.GetName(),
			Language:  e.mod.GetLanguage(),
			Imports:   append([]string{}, e.mod.GetImports()...),
			Globals:   []globalView{},
			Types:     []typeView{},
			Functions: []funcView{},
		},
	}
	for _, g := range e.glbs {
		fv.Module.Globals = append(fv.Module.Globals, globalViewOf(g))
	}
	for _, t := range e.typs {
		fv.Module.Types = append(fv.Module.Types, typeViewOf(t))
	}
	lang := e.mod.GetLanguage()
	ord := 0
	for _, fn := range e.fns {
		fv.Module.Functions = append(fv.Module.Functions, funcViewOf(fn, &ord, func(in *ir.Instruction) *flagView {
			return idx.cls.flag(lang, in)
		}))
		// Recorded in the same order funcViewOf numbered them, which is what makes
		// an ordinal round-trip to the instruction it names.
		fv.ords = append(fv.ords, instrsInOrder(fn)...)
	}
	return fv
}

// instrsInOrder mirrors funcViewOf's traversal (blocks in order, nils skipped),
// which is what makes an ordinal a stable name for an instruction.
func instrsInOrder(fn *ir.Function) []*ir.Instruction {
	var out []*ir.Instruction
	for _, b := range fn.GetBlocks() {
		if b == nil {
			continue
		}
		for _, in := range b.GetInstrs() {
			if in != nil {
				out = append(out, in)
			}
		}
	}
	return out
}

func (idx *Index) source(abs string) []string {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	lines, ok := idx.lines.Lines(abs)
	if !ok {
		return []string{}
	}
	return lines
}
