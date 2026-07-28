package js_converter

import "strings"

// Flow-typed JavaScript support, by BLANKING Flow-only syntax in place.
//
// Flow ships in plain `.js` files, so the loader ladder reaches them, but every
// rung fails: esbuild has no Flow loader (its api.Loader enum has no such entry
// and the package contains no Flow support at all), and Flow's type syntax is
// not valid TypeScript either. parse-server dropped 19 files this way, including
// PostgresStorageAdapter.js, which is where its SQL sinks live; it now converts
// all 196.
//
// # Why blanking, and why it may not rewrite
//
// Positions are mandatory on every instruction (CLAUDE.md), and remapPositions
// relies on the sourcemap esbuild emits for the buffer it was HANDED. If a
// stripper rewrote the source before esbuild, that map would resolve back to the
// stripped buffer rather than the original file, and there is no way to compose
// the two: go-sourcemap/sourcemap is consumer-only -- Parse and Consumer, no
// generator -- and nothing in this repo chains maps.
//
// So stripFlow is offset-preserving: every removed byte becomes a space, every
// newline survives. Stripped line/column then equal the original's, esbuild's own
// map is already correct, and remapPositions needs no change. sfc.go:extractSFCToJS
// uses the same trick one dimension down, padding with newlines so a <script>
// body lands on its true SFC line. It is also what Meta's flow-remove-types does,
// for the same stated reason.
//
// The corollary is that translating Flow to TypeScript is out of bounds:
// `{[string]: T}` -> `{[k: string]: T}` adds characters and would shift every
// position after it on the line.
//
// # Why blanking a whole annotation is safe
//
// The stripped buffer is handed to esbuild's TS loader, which ERASES types
// outright. So a blanked annotation never has to remain meaningful -- it only has
// to leave behind something that parses. That is what makes this tractable
// without implementing Flow's type grammar: rather than teach the scanner about
// maybe-types, unions, generics, variance and indexers one by one, it finds where
// an annotation STARTS and blanks through to its terminator.
//
// # Failure direction
//
// This rung only ever runs on a file that already failed every loader, so a strip
// that yields something unparseable costs nothing -- the file is dropped exactly
// as it is today. The outcome to avoid is blanking VALUE code, which would turn a
// dropped file into a silently mis-lowered one. Every decision below therefore
// prefers to leave text alone when the context is not certain, and stripFlow
// refuses the whole file rather than guess (see the `bail` returns).

// looksLikeFlow reports whether a file is worth attempting a Flow strip on.
//
// It is not a dialect prediction -- the frontend deliberately stopped predicting
// dialects (see needsTransform) -- but a blast-radius limit on the LAST rung: the
// scanner only runs on a file that has already failed every loader, and requiring
// a Flow marker keeps it away from files that failed for some unrelated reason.
func looksLikeFlow(src string) bool {
	if strings.Contains(src, "@flow") || strings.Contains(src, "opaque type ") {
		return true
	}
	// `: ?T` (maybe-type) and `{[string]:` / `{[number]:` (unnamed indexer) are
	// the two Flow-only shapes that appear in ordinary application code.
	return strings.Contains(src, ": ?") || strings.Contains(src, ":?") ||
		strings.Contains(src, "{[string]:") || strings.Contains(src, "{[number]:")
}

// stripFlow returns src with Flow-only syntax replaced by spaces, preserving
// every byte offset and line break. It returns src unchanged when it meets
// something it cannot classify confidently.
func stripFlow(src string) (string, bool) {
	if !looksLikeFlow(src) {
		return src, false
	}
	s := &flowScanner{src: src, out: []byte(src), memberStart: true}
	if !s.run() {
		return src, false
	}
	return string(s.out), true
}

type flowScanner struct {
	src string
	out []byte
	i   int

	// paren/bracket/brace nesting, used to find an annotation's terminator and to
	// tell a parameter list from an ordinary expression.
	paren, brack, brace int
	// parenGroups records, per open paren, the brace depth at which it opened. An
	// annotation may only appear directly inside the INNERMOST group and at that
	// group's own brace depth, which is what keeps a `:` inside an object literal
	// argument -- f({ a: 1 }) -- from being mistaken for one. It is a stack rather
	// than a single depth because Flow casts nest: `Object.keys((x: any))` puts one
	// annotation-capable group inside another.
	parenGroups []int
	// ternary counts unmatched `?` at the current nesting level. A ternary's `:`
	// binds to one of them, so it is not an annotation. Saved and restored across
	// every bracket, since a `?` cannot bind across one -- and an object literal in
	// a ternary branch, `fast ? c.deleteMany({}) : c.drop()`, must not lose the
	// pending `?` its own `{}` opens.
	ternary      int
	ternaryStack []int
	// prev is the last significant (non-space, non-comment) byte seen. It is what
	// distinguishes a return-type `)` `:` from a ternary's `:`.
	prev byte
	// prevWord is the last identifier/keyword, for `const x: T` and `opaque type`.
	prevWord string
	// classBody records, per open brace, whether it opened a CLASS body. A
	// `name: T` at class-body level is a property annotation; the identical shape
	// inside an object literal is a key and its value must not be touched. The
	// `class` keyword is the only thing that distinguishes them, so it is tracked
	// rather than guessed.
	classBody    []bool
	pendingClass bool
	// memberStart is true while the scanner sits where a class member may begin --
	// after `;`, `{` or `}`, through any modifier keyword. identStartsMember
	// records that state as of the last identifier consumed, which is what the `:`
	// immediately after it needs to know.
	//
	// Without it, a Flow generic BOUND in a method signature -- parse-server's
	// `paramsAreEquals<T: { [key: string]: any }>(…)` -- matches the class-property
	// shape (`ident :` at class-body brace depth, outside any paren).
	// blankAnnotation would then take the `{` as an object type, run past the
	// signature into the method BODY, and blank until the braces happened to
	// balance. That is the one outcome this file exists to avoid.
	memberStart, identStartsMember bool
}

// blank overwrites [from,to) with spaces, leaving newlines in place so line
// numbering is untouched.
func (s *flowScanner) blank(from, to int) {
	for j := from; j < to && j < len(s.out); j++ {
		if s.out[j] != '\n' && s.out[j] != '\r' {
			s.out[j] = ' '
		}
	}
}

func (s *flowScanner) run() bool {
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == '/' && s.peek(1) == '/':
			s.skipLineComment()
			continue
		case c == '/' && s.peek(1) == '*':
			if !s.skipBlockComment() {
				return false
			}
			continue
		case c == '"' || c == '\'':
			if !s.skipQuoted(c) {
				return false
			}
			continue
		case c == '`':
			if !s.skipTemplate() {
				return false
			}
			continue
		case c == '/' && s.regexCanStart():
			if !s.skipRegex() {
				return false
			}
			continue
		}

		if isSpaceByte(c) {
			s.i++
			continue
		}

		// `%checks` predicate suffix.
		if c == '%' && strings.HasPrefix(s.src[s.i:], "%checks") {
			s.blank(s.i, s.i+len("%checks"))
			s.i += len("%checks")
			s.prev = ' '
			continue
		}

		if isWordByte(c) {
			start := s.i
			for s.i < len(s.src) && isWordByte(s.src[s.i]) {
				s.i++
			}
			word := s.src[start:s.i]
			// `opaque type X = ...` -- blanking just the keyword leaves a plain TS
			// type alias behind, same length, no position shift.
			opaqueType := word == "opaque" && s.nextWordIs("type")
			if opaqueType {
				s.blank(start, s.i)
			}
			// The next `{` opens a class body, where `name: T` is a property
			// annotation rather than an object-literal key.
			if word == "class" {
				s.pendingClass = true
			}
			// A `type X = …` / `interface X { … }` declaration is erased wholesale
			// by the TS loader, so blanking the whole thing is always safe -- and it
			// is the only way to reach Flow-only types in the BODY (`{ a?: ?string }`),
			// which no amount of TS-compatible syntax around them rescues.
			//
			// Neither word is reserved, so all three conditions are needed before the
			// blank: it must STATEMENT-START (React names variables `type` constantly,
			// and `(type as ReactConsumerType<any>)` otherwise reads as `type Alias`
			// and blanks the rest of the function), be followed by an identifier, and
			// not be a member access.
			if (word == "type" || word == "interface") && s.memberStart && s.prev != '.' &&
				s.startsDeclaration() {
				if from, ok := s.declarationStart(start); ok {
					s.blankDeclaration(from)
					continue
				}
			}
			if declModifiers[word] || opaqueType {
				s.identStartsMember = false
			} else {
				s.identStartsMember, s.memberStart = s.memberStart, false
			}
			// A type-parameter list may follow a declaration's NAME, and Flow spells
			// its bound with `:` where TypeScript uses `extends` -- so
			// `paramsAreEquals<T: { [key: string]: any }>(…)` reaches no loader.
			inClass := len(s.classBody) > 0 && s.classBody[len(s.classBody)-1]
			if (inClass && s.identStartsMember) || s.prevWord == "function" {
				s.blankTypeParams()
			}
			s.prevWord, s.prev = word, word[len(word)-1]
			continue
		}

		switch c {
		case '(':
			s.paren++
			s.pushTernary()
			// A `(` opens a parameter list, a call, or a parenthesised expression.
			// All three are annotation-capable in Flow -- the last one because a cast
			// is written `(expr: T)` -- and the shapes that must NOT be read as
			// annotations are excluded by the ternary counter and the brace-depth
			// check rather than by refusing the group.
			s.parenGroups = append(s.parenGroups, s.brace)
		case ')':
			s.popTernary()
			if n := len(s.parenGroups); n > 0 {
				s.parenGroups = s.parenGroups[:n-1]
			}
			s.paren--
		case '[':
			s.brack++
			s.pushTernary()
		case ']':
			s.brack--
			s.popTernary()
		case '{':
			s.brace++
			s.pushTernary()
			s.classBody = append(s.classBody, s.pendingClass)
			s.pendingClass = false
		case '}':
			s.brace--
			s.popTernary()
			if n := len(s.classBody); n > 0 {
				s.classBody = s.classBody[:n-1]
			}
		case ';':
			s.ternary = 0
		case '?':
			// `?.` and `??` are not ternaries, and `x?: T` is an optional-parameter
			// marker whose `:` DOES start an annotation -- neither may leave a
			// pending ternary behind.
			if s.peek(1) == '.' || s.peek(1) == '?' {
				s.i++
			} else if !s.nextSignificantIs(':') {
				s.ternary++
			}
		case ':':
			if s.ternary > 0 {
				s.ternary-- // this `:` closes a pending ternary
				break
			}
			if s.annotationStarts() {
				if !s.blankAnnotation(s.prev == ')') {
					return false
				}
				continue
			}
		}
		switch c {
		case '{', '}', ';':
			s.memberStart = true
		case '+', '-', '#': // variance sigil or private-field name: still at the start
		default:
			s.memberStart = false
		}
		s.prev = c
		s.i++
	}
	return s.paren == 0 && s.brack == 0 && s.brace == 0
}

// inParenGroup reports whether the scanner sits directly inside the innermost
// parenthesised group, at the brace depth that group opened at.
func (s *flowScanner) inParenGroup() bool {
	n := len(s.parenGroups)
	return n > 0 && s.brace == s.parenGroups[n-1]
}

// pushTernary/popTernary save the pending-`?` count across a bracket. A ternary
// cannot bind across one, so the count restarts inside and the outer count is
// restored on the way out.
func (s *flowScanner) pushTernary() {
	s.ternaryStack = append(s.ternaryStack, s.ternary)
	s.ternary = 0
}

func (s *flowScanner) popTernary() {
	if n := len(s.ternaryStack); n > 0 {
		s.ternary = s.ternaryStack[n-1]
		s.ternaryStack = s.ternaryStack[:n-1]
		return
	}
	s.ternary = 0
}

// startsDeclaration reports whether the `type`/`interface` keyword just consumed
// introduces a declaration, i.e. the next significant token is an identifier.
func (s *flowScanner) startsDeclaration() bool {
	j := s.i
	for j < len(s.src) && isSpaceByte(s.src[j]) {
		j++
	}
	if j >= len(s.src) || !isWordByte(s.src[j]) {
		return false
	}
	return s.src[j] < '0' || s.src[j] > '9' // a digit means this is not an identifier
}

// declarationStart walks back from the `type`/`interface` keyword at kwStart over
// any `export`/`declare` modifiers, returning the offset the blank must begin at.
//
// Blanking the keyword alone leaves the modifier stranded — `export` followed by
// nothing is a syntax error, and `export type` is how parse-server writes nearly
// every one of these. It reports false when the keyword follows `import`, where
// `import type X from 'y'` is valid TypeScript that esbuild already erases: there
// the declaration is not ours to blank, and doing so would destroy the import.
func (s *flowScanner) declarationStart(kwStart int) (int, bool) {
	from := kwStart
	for {
		j := from - 1
		for j >= 0 && isSpaceByte(s.src[j]) {
			j--
		}
		end := j + 1
		for j >= 0 && isWordByte(s.src[j]) {
			j--
		}
		switch s.src[j+1 : end] {
		case "export", "declare":
			from = j + 1
		case "import":
			return 0, false
		default:
			return from, true
		}
	}
}

// blankDeclaration blanks a whole type/interface declaration, from `from` through
// its terminating `;` or the close of its brace body.
func (s *flowScanner) blankDeclaration(from int) {
	depth := 0
	lastSig := byte('=') // the declaration is incomplete until its body starts
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch c {
		case '{', '(', '[':
			depth++
		case '}', ')', ']':
			depth--
			if depth == 0 {
				s.i++
				// A brace body may still be followed by `;` (`export type X = {…};`),
				// which is harmless left behind but tidier consumed.
				for s.i < len(s.src) && isSpaceByte(s.src[s.i]) && s.src[s.i] != '\n' {
					s.i++
				}
				if s.i < len(s.src) && s.src[s.i] == ';' {
					s.i++
				}
				s.finishDeclaration(from)
				return
			}
		case ';':
			if depth == 0 {
				s.i++
				s.finishDeclaration(from)
				return
			}
		case '\n':
			// A newline ends the declaration only if it is actually complete. A
			// multi-line union — `type T =\n  | 'a'\n  | 'b';` — is the common Flow
			// shape, and stopping at its first newline would strand every remaining
			// branch as a syntax error. Continue while either side of the break shows
			// the expression is unfinished.
			if depth == 0 && !continuesType(lastSig) && !s.nextLineContinuesType() {
				s.blank(from, s.i)
				s.prev, s.prevWord = ' ', ""
				return
			}
		}
		if !isSpaceByte(c) {
			lastSig = c
		}
		s.i++
	}
	s.finishDeclaration(from)
}

// finishDeclaration blanks [from, s.i) and resets the token context, since the
// scanner resumes after a span that no longer exists.
func (s *flowScanner) finishDeclaration(from int) {
	s.blank(from, s.i)
	s.prev, s.prevWord = ' ', ""
}

// continuesType reports whether c, as the last significant byte before a line
// break, leaves a type expression open.
func continuesType(c byte) bool {
	switch c {
	case '=', '|', '&', ',', '<', '(', '[', '{', ':', '?', '.', '>', '+', '-':
		return true
	}
	return false
}

// nextLineContinuesType reports whether the first significant byte after the
// newline at s.i resumes the type expression rather than starting a statement.
func (s *flowScanner) nextLineContinuesType() bool {
	j := s.i
	for j < len(s.src) && isSpaceByte(s.src[j]) {
		j++
	}
	if j >= len(s.src) {
		return false
	}
	switch s.src[j] {
	case '|', '&', ',', '>', '=', ')', ']', '}', ':', '?', '.':
		return true
	}
	return false
}

// annotationStarts decides whether the `:` at s.i begins a TYPE annotation
// rather than an object-literal value, a ternary alternative, a label or a
// `case`. It answers yes only in the positions a declaration can carry one.
func (s *flowScanner) annotationStarts() bool {
	// A ternary's `:` is preceded by an expression and matched by an earlier `?`
	// on the same nesting level; the cheapest reliable discriminator is that a
	// type annotation follows an identifier, a `)` (return type) or a `?`
	// (optional parameter).
	switch {
	case s.prev == ')' || s.prev == '?' || isWordByte(s.prev):
		// prevWord only describes the token when the `:` follows a word; after a
		// bracket it is a stale leftover from inside that bracket.
		if isWordByte(s.prev) {
			switch s.prevWord {
			case "case", "default", "return", "typeof", "in", "of", "new", "delete", "void":
				return false
			}
		}
	case s.prev == '}' || s.prev == ']':
		// A cast may apply to a destructuring pattern or an object literal --
		// `({ type }: SchemaField)` -- where the `:` follows the closing bracket.
		// Only ever inside a parenthesised group: at statement level the same shape
		// is a block followed by a label.
		return s.inParenGroup()
	default:
		return false
	}
	// Directly inside a parenthesised group: a parameter list (`function f(x: T)`,
	// `(x: ?T) => …`) or a cast (`(x: any)`). The brace check is what excludes an
	// object literal argument, f({ a: 1 }), whose `:` sits one brace deeper than
	// the group that opened.
	if s.inParenGroup() {
		return true
	}
	// Return type: the `:` directly follows the `)` that closed a parameter list.
	if s.prev == ')' {
		return true
	}
	// Class property: `name: ?T;` directly in a class body, not nested in any
	// parenthesised group, and starting a member rather than sitting inside one.
	if n := len(s.classBody); n > 0 && s.classBody[n-1] && s.paren == 0 && isWordByte(s.prev) &&
		s.identStartsMember {
		return true
	}
	// Variable declarator: `const x: T = …`.
	if s.declaratorContext() {
		return true
	}
	return false
}

// typeParamScanLimit bounds the lookahead for a type-parameter list's closing
// `>`. A real one is short; anything longer is a sign the `<` was a comparison.
const typeParamScanLimit = 512

// blankTypeParams blanks a type-PARAMETER list at s.i, `<T: Bound, U>`, and
// reports whether it did.
//
// The whole list is blanked rather than just the bound, because the TS loader
// erases type parameters outright — so, as everywhere else here, the strip only
// has to leave something that parses.
//
// `<` is ambiguous with less-than, and getting that wrong would blank a real
// comparison, so three conditions must all hold: the caller has established that
// what precedes is a declaration NAME; a matching `>` is found within
// typeParamScanLimit with balanced nesting and no `;` or `=` (neither can appear
// in a type-parameter list, but both are common between two comparisons); and the
// list actually contains a `:`, without which there is no Flow syntax to remove
// and nothing to gain by touching it.
func (s *flowScanner) blankTypeParams() bool {
	if s.i >= len(s.src) || s.src[s.i] != '<' {
		return false
	}
	end := min(len(s.src), s.i+typeParamScanLimit)
	depth, colon := 0, false
	for j := s.i; j < end; j++ {
		switch s.src[j] {
		case '<', '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ':':
			colon = true
		case ';', '=':
			return false
		case '>':
			depth--
			if depth == 0 {
				if !colon {
					return false
				}
				s.blank(s.i, j+1)
				s.i = j + 1
				return true
			}
		}
		if depth < 0 {
			return false
		}
	}
	return false
}

// declModifiers are the words that may precede a declaration or class member's
// name without ending the statement-start position: the export/ambient markers, the
// property modifiers, and the accessor and async keywords that introduce a method.
var declModifiers = map[string]bool{
	"export": true, "declare": true, "static": true, "readonly": true,
	"get": true, "set": true, "async": true,
}

// declaratorContext reports whether the identifier just consumed was introduced
// by const/let/var on the same statement, which is the only other place this
// scanner will accept an annotation. It deliberately does NOT accept a bare
// `ident:` at brace depth (a class property), because that is indistinguishable
// from an object-literal key without tracking whether the enclosing `{` opened a
// class body or a value -- and mistaking a literal's key would blank its VALUE.
func (s *flowScanner) declaratorContext() bool {
	// Walk back over the identifier and whitespace to the previous word.
	j := s.i - 1
	for j >= 0 && isSpaceByte(s.src[j]) {
		j--
	}
	for j >= 0 && isWordByte(s.src[j]) {
		j--
	}
	for j >= 0 && isSpaceByte(s.src[j]) {
		j--
	}
	end := j + 1
	for j >= 0 && isWordByte(s.src[j]) {
		j--
	}
	switch s.src[j+1 : end] {
	case "const", "let", "var":
		return true
	}
	return false
}

// blankAnnotation blanks from s.i to the annotation's terminator, tracking its
// own nesting so `{[string]: mixed}`, `Array<{a: T}>` and `(A) => B` are consumed
// whole. Terminators at depth zero: `,` `)` `]` `}` `;` `=` `=>` or end of line
// for a class-property-style annotation.
func (s *flowScanner) blankAnnotation(isReturnType bool) bool {
	start := s.i // the `:` is blanked too: `x:  )` would not parse
	s.i++
	depth := 0
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch {
		case c == '/' && s.peek(1) == '/':
			s.blank(start, s.i)
			return true
		case c == '/' && s.peek(1) == '*':
			s.blank(start, s.i)
			return true
		case c == '"' || c == '\'':
			// A string literal type: skip it whole so its contents cannot be
			// mistaken for a terminator.
			if !s.skipQuoted(c) {
				return false
			}
			continue
		}
		if depth == 0 {
			if c == ',' || c == ')' || c == ']' || c == ';' || c == '}' {
				s.blank(start, s.i)
				return true
			}
			if c == '=' {
				// `=>` inside a PARAMETER annotation belongs to a function type
				// (`cb: (e: Error) => void`) and is consumed with it. In a RETURN
				// annotation the same token is the enclosing arrow function's own
				// arrow -- `const f = (x): T => {…}` -- and must survive, or the
				// arrow is destroyed and the file no longer parses.
				if s.peek(1) != '>' || isReturnType {
					s.blank(start, s.i)
					return true
				}
			}
			// `{` ends a RETURN-type annotation, where it opens the function body.
			// In a parameter or declarator annotation it opens an object TYPE --
			// `o: {[string]: mixed}` -- and must be consumed, not treated as a
			// terminator.
			if c == '{' && isReturnType {
				s.blank(start, s.i)
				return true
			}
			if c == '\n' {
				// An annotation may legitimately wrap, but a bare newline also ends a
				// class property (`x: T` with no semicolon). Stop here: blanking less
				// is always safe, and the remainder is left for the loaders to judge.
				s.blank(start, s.i)
				return true
			}
		}
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '=':
			if s.peek(1) == '>' { // arrow inside a function type
				s.i++
			}
		}
		s.i++
	}
	s.blank(start, s.i)
	return true
}

func (s *flowScanner) peek(n int) byte {
	if s.i+n < len(s.src) {
		return s.src[s.i+n]
	}
	return 0
}

// nextSignificantIs reports whether the next non-space byte is c.
func (s *flowScanner) nextSignificantIs(c byte) bool {
	j := s.i + 1
	for j < len(s.src) && isSpaceByte(s.src[j]) {
		j++
	}
	return j < len(s.src) && s.src[j] == c
}

// nextWordIs reports whether the next significant word equals w, without
// consuming it.
func (s *flowScanner) nextWordIs(w string) bool {
	j := s.i
	for j < len(s.src) && isSpaceByte(s.src[j]) {
		j++
	}
	return strings.HasPrefix(s.src[j:], w)
}

// regexCanStart reports whether a `/` at s.i begins a regex literal rather than
// a division. The standard discriminator: division can only follow something
// that ends a value, so anything else means regex.
//
// Getting this wrong desynchronises the scanner -- a regex body may contain
// quotes, braces and parens -- but not silently: the run ends with unbalanced
// depth and stripFlow refuses the file, which drops it exactly as before.
func (s *flowScanner) regexCanStart() bool {
	switch s.prev {
	case ')', ']', '}':
		return false
	}
	if isWordByte(s.prev) {
		// A value-ending identifier or number means division -- except for the
		// keywords after which an expression (and so a regex) may begin.
		switch s.prevWord {
		case "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
			"case", "do", "else", "yield", "await", "throw":
			return true
		}
		return false
	}
	return true
}

// skipRegex consumes a regex literal, including its character classes (where `/`
// is not a terminator) and flags.
func (s *flowScanner) skipRegex() bool {
	s.i++ // opening /
	inClass := false
	for s.i < len(s.src) {
		switch s.src[s.i] {
		case '\\':
			s.i += 2
			continue
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if !inClass {
				s.i++
				for s.i < len(s.src) && isWordByte(s.src[s.i]) { // flags
					s.i++
				}
				s.prev = '/'
				return true
			}
		case '\n':
			return false // a regex cannot span lines: we mis-classified a division
		}
		s.i++
	}
	return false
}

func (s *flowScanner) skipLineComment() {
	for s.i < len(s.src) && s.src[s.i] != '\n' {
		s.i++
	}
}

func (s *flowScanner) skipBlockComment() bool {
	s.i += 2
	for s.i < len(s.src) {
		if s.src[s.i] == '*' && s.peek(1) == '/' {
			s.i += 2
			return true
		}
		s.i++
	}
	return false // unterminated: refuse the file
}

func (s *flowScanner) skipQuoted(q byte) bool {
	s.i++
	for s.i < len(s.src) {
		switch s.src[s.i] {
		case '\\':
			s.i += 2
			continue
		case q:
			s.i++
			s.prev = q
			return true
		case '\n':
			return false // unterminated string: refuse the file
		}
		s.i++
	}
	return false
}

// skipTemplate skips a template literal including nested ${...} expressions,
// which may themselves contain strings, templates and braces.
func (s *flowScanner) skipTemplate() bool {
	s.i++
	for s.i < len(s.src) {
		switch s.src[s.i] {
		case '\\':
			s.i += 2
			continue
		case '`':
			s.i++
			s.prev = '`'
			return true
		case '$':
			if s.peek(1) == '{' {
				s.i += 2
				// A substitution is arbitrary JS, so it needs the same lexing the
				// main loop does -- including REGEX literals. `` `"${x.replace(/"/g,
				// \'""\')}"` `` is real parse-server code: without regex handling the
				// quote inside /"/g reads as a string opener and swallows the rest of
				// the file. prev is tracked locally so regexCanStart can tell a regex
				// from a division here too.
				depth, prev := 1, byte(0)
				for s.i < len(s.src) && depth > 0 {
					c := s.src[s.i]
					switch {
					case c == '/' && s.peek(1) == '/':
						s.skipLineComment()
						continue
					case c == '/' && s.peek(1) == '*':
						if !s.skipBlockComment() {
							return false
						}
						continue
					case c == '/':
						saved := s.prev
						s.prev = prev
						canStart := s.regexCanStart()
						s.prev = saved
						if canStart {
							if !s.skipRegex() {
								return false
							}
							prev = '/'
							continue
						}
					case c == '`':
						if !s.skipTemplate() {
							return false
						}
						prev = '`'
						continue
					case c == '"' || c == '\'':
						if !s.skipQuoted(c) {
							return false
						}
						prev = c
						continue
					case c == '{':
						depth++
					case c == '}':
						depth--
					}
					if !isSpaceByte(c) {
						prev = c
					}
					s.i++
				}
				continue
			}
		}
		s.i++
	}
	return false
}

func isWordByte(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
