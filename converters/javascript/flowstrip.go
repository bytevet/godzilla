package js_converter

import "strings"

// Flow-typed JavaScript support, by BLANKING Flow-only syntax in place.
//
// Flow ships in plain `.js` files, so the loader ladder reaches them, but every
// rung fails: esbuild has no Flow loader, and Flow's type syntax is not valid
// TypeScript either. Without this rung such a file is dropped whole, taking its
// sinks with it.
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
// uses the same trick one dimension down. (Meta's flow-remove-types does the same,
// for the same reason.)
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
// without implementing Flow's type grammar: the scanner finds where an annotation
// STARTS and blanks through to its terminator.
//
// # Failure direction
//
// This rung only ever runs on a file that already failed every loader, so a strip
// yielding something unparseable costs nothing -- the file is dropped either way.
// The outcome to avoid is blanking VALUE code, which turns a dropped file into a
// silently mis-lowered one. Every decision below therefore prefers to leave text
// alone when the context is not certain, and stripFlow refuses the whole file
// rather than guess.

// looksLikeFlow reports whether a file is worth attempting a Flow strip on.
//
// It is not a dialect prediction -- the frontend does not predict dialects, see
// needsTransform -- but a blast-radius limit on the LAST rung: requiring a Flow
// marker keeps the scanner away from files that failed for an unrelated reason.
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
	// The bottom frame stands for top level, which IS a declaration position, and
	// makes every frame lookup total — no accessor has to handle an empty stack.
	s := &flowScanner{src: src, out: []byte(src), memberStart: true,
		frames: []frame{{declPos: true}}}
	if !s.run() {
		return src, false
	}
	return string(s.out), true
}

// frame is one open bracket. All per-bracket state lives here rather than in
// parallel stacks, so "what is directly inside this bracket" is one lookup.
type frame struct {
	open byte // '(', '[' or '{'
	// isClass marks a `{` that opened a CLASS body. A `name: T` there is a
	// property annotation; the identical shape inside an object literal is a key
	// whose value must not be touched. Only the `class` keyword distinguishes
	// them, so it is tracked rather than guessed.
	isClass bool
	// declPos marks a frame a declaration or class member may begin directly
	// inside: a block or a class body, never an object literal, a destructuring
	// pattern or an import/export specifier list. Decided by opensBlock.
	declPos bool
	// ternary is the ENCLOSING frame's count of unmatched `?`, restored when this
	// bracket closes. A ternary's `:` binds to one of them, so it is not an
	// annotation -- and it cannot bind across a bracket, so an object literal in a
	// ternary branch, `fast ? c.deleteMany({}) : c.drop()`, must not consume the
	// pending `?` that its own `{}` sits inside.
	ternary int
}

type flowScanner struct {
	src string
	out []byte
	i   int

	// frames is the open-bracket stack; over-closing sets unbalanced, which makes
	// stripFlow refuse the file rather than blank against a skewed depth.
	frames     []frame
	unbalanced bool
	// ternary counts unmatched `?` in the CURRENT frame.
	ternary int
	// prev is the last significant (non-space, non-comment) byte seen. It is what
	// distinguishes a return-type `)` `:` from a ternary's `:`.
	prev byte
	// prevWord is the last identifier/keyword, for `const x: T` and `opaque type`.
	prevWord string
	// pendingClassDepth is the frame depth at which a `class` keyword is waiting for
	// its body, or 0 for none. The depth stamp matters: an unstamped flag is
	// consumed by the NEXT `{` anywhere, so `class X extends mix({ a: 1 })` would
	// mark the MIXIN's literal as the class body -- blanking `: 1` to leave `{ a }`,
	// valid shorthand that parses mis-lowered, while the real body lost its isClass.
	pendingClassDepth int
	// memberStart is true where a declaration or class member may begin: at a
	// statement boundary (`;`, `{`, `}`) inside a frame whose declPos allows one,
	// and through any isDeclModifier word. identStartsMember records that state as
	// of the last identifier consumed, which is what the `:` after it needs.
	//
	// The invariant both serve: a `:` is an annotation only where a declaration can
	// carry one, and `type`/`interface` are keywords only where one can begin.
	memberStart, identStartsMember bool
}

// top returns the innermost frame; the bottom frame makes it always defined.
func (s *flowScanner) top() frame {
	return s.frames[len(s.frames)-1]
}

// opensBlock reports whether the `{` at s.i opens a BLOCK -- a statement list a
// declaration may begin in -- as opposed to an object literal, a destructuring
// pattern, or an import/export specifier list.
//
// It answers from the preceding token (statement position versus expression
// position) and is DEFAULT-DENY. Saying false about a real block only costs a
// `type` alias declared inside it -- the file is left unparseable and dropped.
// Saying true about a specifier list runs a declaration blank through
// `import { type Config } from './config'`, blanking the import and whatever
// follows until the braces happen to rebalance, and that result can PARSE.
func (s *flowScanner) opensBlock() bool {
	switch s.prev {
	case 0, // start of file
		')',      // `if (…) {`, `for (…) {`, `function f(…) {`, `catch (e) {`
		';', '}', // a statement boundary
		'>': // an arrow body, `=> {`
		// `>` also ends a JSX tag and a relational compare, so this is true for
		// `<div>{…}` and `a > {}` as well. Both are harmless: a wrong declPos outside
		// a class body can only mis-fire the `type`/`interface` blank, and neither
		// shape can contain `type <ident>`.
		return true
	case '{':
		// A bare nested block, but only where the enclosing frame was itself a
		// statement list -- `{` inside an object literal opens another one.
		return s.top().declPos
	}
	// prevWord only describes the token when prev is a word byte; after a bracket or
	// operator it is a stale leftover from inside it.
	if isWordByte(s.prev) {
		switch s.prevWord {
		case "else", "do", "try", "finally":
			return true
		}
	}
	return false
}

func (s *flowScanner) inClassBody() bool {
	return s.top().isClass
}

// introducesName reports whether word is a keyword after which the next
// identifier is a BINDING NAME, and so may carry a type-parameter list.
func introducesName(word string) bool {
	return word == "function" || word == "class"
}

// push opens a bracket frame, saving the enclosing ternary count into it.
func (s *flowScanner) push(open byte, isClass, declPos bool) {
	s.frames = append(s.frames, frame{open: open, isClass: isClass, declPos: declPos, ternary: s.ternary})
	s.ternary = 0
}

// pop closes a bracket frame and restores the enclosing ternary count. Closing
// one that was never opened means the source is not balanced the way the scanner
// read it — a refusal, not something to recover from.
func (s *flowScanner) pop(open byte) {
	n := len(s.frames)
	if n == 1 || s.frames[n-1].open != open {
		s.unbalanced = true
		return
	}
	s.ternary = s.frames[n-1].ternary
	s.frames = s.frames[:n-1]
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
			// `class` is not reserved as a property name, so it only introduces a body
			// when it is neither an object key (`{ class: 'btn' }`) nor a member read
			// (`o.class`).
			if word == "class" && s.prev != '.' && !s.nextSignificantIs(':') {
				s.pendingClassDepth = len(s.frames)
			}
			// The whole declaration goes, not just its Flow-only parts: that is the
			// only way to reach the types in its BODY (`{ a?: ?string }`), which no
			// amount of TS-compatible syntax around them rescues.
			if (word == "type" || word == "interface") && s.startsDeclaration() {
				s.blankDeclaration(s.declarationStart(start))
				continue
			}
			// `opaque` is treated as a modifier so it does not consume the declaration
			// position that its own following `type` keyword needs.
			if isDeclModifier(word) || opaqueType {
				s.identStartsMember = false
			} else {
				s.identStartsMember, s.memberStart = s.memberStart, false
			}
			// Flow spells a type-parameter bound with `:` where TypeScript uses
			// `extends`, so a generic declaration reaches no loader. Such a list can
			// only follow a BINDING NAME -- an identifier introduced by `function` or
			// `class`, or a class member's own name. A bare identifier starting a
			// statement is an expression, not a binding, and must not qualify:
			// `a<b ? c : d>e` is a pair of comparisons around a ternary and would
			// otherwise be read as a bound and blanked.
			if introducesName(s.prevWord) || (s.identStartsMember && s.inClassBody()) {
				s.blankTypeParams()
			}
			s.prevWord, s.prev = word, word[len(word)-1]
			continue
		}

		switch c {
		case '(':
			// A parameter list, a call, or a parenthesised expression: all three are
			// annotation-capable in Flow (the last because a cast is `(expr: T)`).
			// Shapes that must NOT be read as annotations are excluded by the ternary
			// counter and by the frame the `:` is found in, not by refusing the group.
			s.push('(', false, false)
		case ')':
			s.pop('(')
		case '[':
			s.push('[', false, false)
		case ']':
			s.pop('[')
		case '{':
			// Only the `{` at the depth the keyword was seen at opens that class body.
			isClass := s.pendingClassDepth == len(s.frames)
			if isClass {
				s.pendingClassDepth = 0
			}
			// opensBlock reads the ENCLOSING frame, so it must run before the push.
			s.push('{', isClass, isClass || s.opensBlock())
		case '}':
			s.pop('{')
		case ';':
			s.ternary = 0
			s.pendingClassDepth = 0 // a statement ended; no body is coming
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
		// A declaration may begin after a statement boundary -- but only in a frame
		// that permits one. For `{` this runs after the push and for `}` after the
		// pop, so both read the frame the next token is actually in.
		switch c {
		case '{', '}', ';':
			s.memberStart = s.top().declPos
		case '+', '-', '#': // variance sigil or private-field name: still at the start
		default:
			s.memberStart = false
		}
		s.prev = c
		s.i++
	}
	return !s.unbalanced && len(s.frames) == 1 // only the bottom frame left
}

// inParenGroup reports whether the scanner sits directly inside a parenthesised
// group -- a parameter list or a cast. Any `{` or `[` between would have pushed
// its own frame, so this is exactly the innermost frame's kind: the `:` in
// `f({ a: 1 })` is found in the `{` frame, not the `(` one, and is left alone.
func (s *flowScanner) inParenGroup() bool {
	return s.top().open == '('
}

// startsDeclaration reports whether the `type`/`interface` keyword just consumed
// actually introduces a declaration.
//
// Neither word is reserved, so both conditions matter. It must sit where a
// declaration can begin -- React code names variables `type` constantly, and
// `(type as ReactConsumerType<any>)` otherwise reads as `type Alias` and blanks
// the rest of the function while staying brace-balanced, so the result parses and
// is silently wrong. And the next significant token must be the name being
// declared. (A member access needs no test: `.` is not a statement boundary, so
// memberStart is already false after one.)
func (s *flowScanner) startsDeclaration() bool {
	if !s.memberStart {
		return false
	}
	j := s.skipSpaceFrom(s.i)
	if j >= len(s.src) || !isWordByte(s.src[j]) {
		return false
	}
	return s.src[j] < '0' || s.src[j] > '9' // a digit means this is not an identifier
}

// declarationStart walks back from the `type`/`interface` keyword at kwStart over
// any `export`/`declare` modifiers, returning the offset the blank must begin at.
//
// Blanking the keyword alone leaves the modifier stranded -- `export` followed by
// nothing is a syntax error, and `export type` is the common spelling.
//
// `import` needs no special case: it is not an isDeclModifier word, so it consumes
// the declaration position and the caller's memberStart test already rejects
// `import type X from 'y'` -- valid TypeScript that esbuild erases on its own, and
// which blanking would destroy.
func (s *flowScanner) declarationStart(kwStart int) int {
	from := kwStart
	for {
		word, start := s.wordBefore(from)
		if word != "export" && word != "declare" {
			return from
		}
		from = start
	}
}

// wordBefore returns the identifier immediately preceding pos (skipping
// whitespace) and the offset it starts at. An empty word means the preceding
// significant byte is not part of an identifier.
func (s *flowScanner) wordBefore(pos int) (string, int) {
	j := pos - 1
	for j >= 0 && isSpaceByte(s.src[j]) {
		j--
	}
	end := j + 1
	for j >= 0 && isWordByte(s.src[j]) {
		j--
	}
	return s.src[j+1 : end], j + 1
}

// blankDeclaration blanks a whole type/interface declaration, from `from` through
// its terminating `;` or the close of its brace body.
func (s *flowScanner) blankDeclaration(from int) {
	depth := 0
	// the declaration is incomplete until its body starts
	lastSig, lastSigPos := byte('='), -1
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch c {
		case '{', '(', '[':
			depth++
		case '}', ')', ']':
			depth--
			if depth == 0 {
				s.i++
				// A brace body may still be followed by `;` (`export type X = {…};`).
				// Bounded to the SAME line: a `;` opening the next one is a
				// leading-semicolon statement (`;[1, 2].forEach(…)`), not a terminator.
				if j := s.skipInlineSpace(s.i); j < len(s.src) && s.src[j] == ';' {
					s.i = j + 1
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
			// A newline ends the declaration only if it is complete. A multi-line
			// union -- `type T =\n  | 'a'\n  | 'b';` -- is the common Flow shape, and
			// stopping at its first newline strands every remaining branch as a syntax
			// error. Continue while either side of the break shows it unfinished.
			if depth == 0 && !s.typeOpenBefore(lastSig, lastSigPos) &&
				!typeOpenAfter(s.nextSignificantByte(s.i)) {
				s.finishDeclaration(from)
				return
			}
		}
		if !isSpaceByte(c) {
			lastSig, lastSigPos = c, s.i
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

// typeOpenBefore and typeOpenAfter report whether a type expression is still open
// across a line break, asked of the last significant byte before the break and
// the first one after it.
//
// The two sets differ on purpose: Flow style breaks AFTER `=` and BEFORE `|`, so
// an opener can end a line and a continuation can begin the next. Hence openers
// (`< ( [ { + -`) only in the first, closers (`) ] }`) only in the second.
func (s *flowScanner) typeOpenBefore(c byte, pos int) bool {
	switch c {
	case '=', '|', '&', ',', '<', '(', '[', '{', ':', '?', '.', '+', '-':
		return true
	case '>':
		// `>` is open only as the tail of `=>` (a function type broken after its
		// arrow). On its own it CLOSES a type argument list, and `type P =
		// Array<string>` with no semicolon is a complete declaration -- continuing
		// there runs the blank into the next statement and deletes it.
		return pos > 0 && s.src[pos-1] == '='
	}
	return false
}

func typeOpenAfter(c byte) bool {
	switch c {
	case '|', '&', ',', '>', '=', ')', ']', '}', ':', '?', '.':
		return true
	}
	return false
}

// skipSpaceFrom returns the offset of the first non-space byte at or after j.
// isSpaceByte counts '\n', so this crosses line breaks.
func (s *flowScanner) skipSpaceFrom(j int) int {
	for j < len(s.src) && isSpaceByte(s.src[j]) {
		j++
	}
	return j
}

// skipInlineSpace is skipSpaceFrom bounded to the current line.
func (s *flowScanner) skipInlineSpace(j int) int {
	for j < len(s.src) && isSpaceByte(s.src[j]) && s.src[j] != '\n' && s.src[j] != '\r' {
		j++
	}
	return j
}

// nextSignificantByte returns the first non-space byte at or after j, or 0 at end
// of input.
func (s *flowScanner) nextSignificantByte(j int) byte {
	if k := s.skipSpaceFrom(j); k < len(s.src) {
		return s.src[k]
	}
	return 0
}

// annotationStarts decides whether the `:` at s.i begins a TYPE annotation
// rather than an object-literal value, a ternary alternative, a label or a
// `case`. It answers yes only in the positions a declaration can carry one.
func (s *flowScanner) annotationStarts() bool {
	// The discriminator is what the `:` follows. The cases are disjoint, so
	// prevWord -- meaningful only in the identifier case, stale otherwise -- is
	// read in that case alone.
	switch {
	case isWordByte(s.prev):
		switch s.prevWord {
		case "case", "default", "return", "typeof", "in", "of", "new", "delete", "void":
			return false
		}
	case s.prev == ')' || s.prev == '?': // return type, optional parameter
	case s.prev == '}' || s.prev == ']':
		// A cast may apply to a destructuring pattern or an object literal --
		// `({ type }: SchemaField)` -- where the `:` follows the closing bracket.
		// Only ever inside a parenthesised group: at statement level the same shape
		// is a block followed by a label.
		return s.inParenGroup()
	default:
		return false
	}
	// A parameter list (`function f(x: T)`, `(x: ?T) => …`) or a cast (`(x: any)`).
	if s.inParenGroup() {
		return true
	}
	// Return type: the `:` directly follows the `)` that closed a parameter list.
	if s.prev == ')' {
		return true
	}
	// Class property: `name: ?T;` on a member's own name. identStartsMember is what
	// keeps a generic BOUND out -- in `paramsAreEquals<T: {…}>(…)` the `T` is at
	// class-body nesting too, and blanking from there would take the `{` for an
	// object type and run through the method body until the braces rebalanced.
	if s.identStartsMember && isWordByte(s.prev) && s.inClassBody() {
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

// blankTypeParams blanks a type-PARAMETER list at s.i, `<T: Bound, U>`. The whole
// list goes, not just the bound.
//
// `<` is ambiguous with less-than, and getting that wrong blanks a real
// comparison, so three conditions must all hold: the caller has established that
// what precedes is a declaration NAME; a matching `>` is found within
// typeParamScanLimit with balanced nesting and no `;` or `=` (neither can appear
// in a type-parameter list, both are common between two comparisons); and the list
// actually contains a `:`, without which there is no Flow syntax to remove.
//
// The bracket kinds share ONE counter, so a `<` closed by a `)` drives depth
// negative and bails -- which is exactly the shape a pair of comparisons makes.
func (s *flowScanner) blankTypeParams() {
	if s.i >= len(s.src) || s.src[s.i] != '<' {
		return
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
			return
		case '>':
			depth--
			if depth == 0 {
				if colon {
					s.blank(s.i, j+1)
					s.i = j + 1
				}
				return
			}
		}
		if depth < 0 {
			return
		}
	}
}

// isDeclModifier reports whether word may precede a declaration or class member's
// name without ending the statement-start position: the export/ambient markers,
// the property modifiers, and the accessor and async keywords that introduce a
// method. The cost of accepting the accessor words is that a class property named
// literally `get`/`set`/`async`/`static` keeps its annotation -- the safe
// direction, since the file is then dropped rather than mis-blanked.
func isDeclModifier(word string) bool {
	switch word {
	case "export", "declare", "static", "readonly", "get", "set", "async":
		return true
	}
	return false
}

// declaratorContext reports whether the identifier just consumed was introduced
// by const/let/var on the same statement: `const x: T = …`. The class-property
// case, which looks identical, is decided above by the enclosing frame.
func (s *flowScanner) declaratorContext() bool {
	_, identStart := s.wordBefore(s.i) // the name the `:` follows
	switch word, _ := s.wordBefore(identStart); word {
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
				// file no longer parses.
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
				// An annotation may wrap, but a bare newline also ends a class
				// property (`x: T` with no semicolon). Stop: blanking less is safe.
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
	return s.nextSignificantByte(s.i+1) == c
}

// nextWordIs reports whether the next significant word equals w, without
// consuming it.
func (s *flowScanner) nextWordIs(w string) bool {
	return strings.HasPrefix(s.src[s.skipSpaceFrom(s.i):], w)
}

// regexCanStart reports whether a `/` at s.i begins a regex literal rather than a
// division: division can only follow something that ends a value, so anything
// else means regex.
//
// Getting this wrong desynchronises the scanner -- a regex body may contain
// quotes, braces and parens -- but not silently: the run ends with unbalanced
// depth and stripFlow refuses the file.
func (s *flowScanner) regexCanStart() bool {
	switch s.prev {
	case ')', ']', '}':
		return false
	}
	if isWordByte(s.prev) {
		// An identifier or number ends a value, so division -- except after these
		// keywords, where an expression (and so a regex) may begin.
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
				// A substitution is arbitrary JS and needs the same lexing the main
				// loop does -- including REGEX literals: in `` `"${x.replace(/"/g,
				// '""')}"` `` the quote inside /"/g would otherwise read as a string
				// opener and swallow the rest of the file. prev is tracked locally so
				// regexCanStart can tell a regex from a division here too.
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
