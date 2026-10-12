// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package redact

// Literal locators (P4 in Go) and the Python-parity boundary.
//
// Go's regexp has no DFA: an unanchored scan of a 300 KB document with a
// `(?i)` prefix pattern runs the NFA over every byte, two to three times
// slower than the reference module's `re`. Every row of the table can only
// match at a position carrying a literal needle (`AKIA`, `sk-`, a family
// word, `"`, `-`, `:`…), so each pass locates the needles (one monotonic
// cursor per needle: O(n) per needle per pass) and runs the row's regex
// ANCHORED at the candidate — or, for a prefix row whose match START
// precedes the needle (a separator, a key quote), in a window bounded by the
// pattern's maximal tail from the needle. The regexes stay the specification:
// the locator scans reproduce exactly the matches re.search / re.sub would
// find, left to right (contract §Contract, group semantics).
//
// Two locator kinds share one cursor structure: the literal kind searches an
// ASCII-lowered copy with strings.Index; the regex kind (chosen when the
// document carries a letter Python's `(?i)` folds into the needles' alphabet
// — U+212A KELVIN SIGN, U+017F LONG S, U+0131 DOTLESS I, U+0130 DOTTED I —
// or under forceRegexPath) searches with one folded regex per needle. The
// equivalence of the two kinds is tested on the corpus and on the exotic
// alphabet (TestLocatorEquivalence).
//
// `\b` is evaluated in code, never by Go's regexp: Go's `\b` is ASCII,
// Python's is Unicode (`\w` = letters, numbers, `_`), and the two differ in
// both directions next to a non-ASCII letter. A row's
// leading `\b` is the pyBoundary check before the candidate; a trailing `\b`
// is the backtracking search of the longest candidate end carrying a
// pyBoundary, memoised per maximal end so a run is walked back once per pass.

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// forceRegexPath makes every scanner take the regex locator; the equivalence
// test compares the two locator kinds.
var forceRegexPath = false

// pyWord is Python's `\w` on str (str.isalnum() or `_`), looked up in the
// table pinned to the reference runtime's Unicode data (pyword_table.go):
// Go's unicode package is one Unicode version behind CPython 3.14 and would
// miss the newer letters.
func pyWord(r rune) bool {
	lo, hi := 0, len(pyWordRanges)
	for lo < hi {
		mid := (lo + hi) / 2
		if r < pyWordRanges[mid][0] {
			hi = mid
		} else if r > pyWordRanges[mid][1] {
			lo = mid + 1
		} else {
			return true
		}
	}
	return false
}

func pyWordBefore(s string, i int) bool {
	if i <= 0 {
		return false
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return pyWord(r)
}

func pyWordAt(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return pyWord(r)
}

// pyBoundaryAt is Python's `\b` at position e.
func pyBoundaryAt(s string, e int) bool { return pyWordBefore(s, e) != pyWordAt(s, e) }

// asciiLower is a same-length lowercase copy (bytes >= 0x80 untouched).
func asciiLower(s string) string {
	hasUpper := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// hasExoticFold reports whether s contains a letter the `(?i)` patterns fold
// into the needles' ASCII alphabet (K→k, ſ→s natively; ı/İ→i through
// pyFoldI): the literal locator cannot see such a needle, the regex one can.
func hasExoticFold(s string) bool {
	return strings.Contains(s, "K") || strings.Contains(s, "ſ") ||
		strings.Contains(s, "ı") || strings.Contains(s, "İ")
}

// locator yields the occurrences of a needle set in ascending order. Each
// needle keeps its own cursor (next occurrence at or after the last query),
// so a pass over a document costs O(len) per needle however many queries it
// makes.
type locator struct {
	n       int
	search  func(i, from int) (pos, end int) // the next occurrence of needle i at or after from; pos < 0 when none
	next    []int                            // -2 unknown, -1 none left, else the next occurrence
	nextEnd []int
}

func newLocator(n int, search func(i, from int) (int, int)) *locator {
	l := &locator{n: n, search: search, next: make([]int, n), nextEnd: make([]int, n)}
	for i := range l.next {
		l.next[i] = -2
	}
	return l
}

func literalLocator(hay string, needles []string) *locator {
	return newLocator(len(needles), func(i, from int) (int, int) {
		if from > len(hay) {
			return -1, -1
		}
		j := strings.Index(hay[from:], needles[i])
		if j < 0 {
			return -1, -1
		}
		return from + j, from + j + len(needles[i])
	})
}

func regexLocator(s string, res []*regexp.Regexp) *locator {
	return newLocator(len(res), func(i, from int) (int, int) {
		if from > len(s) {
			return -1, -1
		}
		m := res[i].FindStringIndex(s[from:])
		if m == nil {
			return -1, -1
		}
		return from + m[0], from + m[1]
	})
}

// find returns the first occurrence at or after from (its start, end and
// needle index; the longest needle wins a tie), or -1s. Queries must not go
// backwards.
func (l *locator) find(from int) (int, int, int) {
	best, bestEnd, which := -1, -1, -1
	for i := 0; i < l.n; i++ {
		if l.next[i] == -1 {
			continue
		}
		if l.next[i] < from {
			l.next[i], l.nextEnd[i] = l.search(i, from)
			if l.next[i] < 0 {
				l.next[i] = -1
				continue
			}
		}
		if best < 0 || l.next[i] < best || (l.next[i] == best && l.nextEnd[i] > bestEnd) {
			best, bestEnd, which = l.next[i], l.nextEnd[i], i
		}
	}
	return best, bestEnd, which
}

// skip advances one needle's cursor past its current occurrence, so a query
// from the same position yields the next needle (another needle may start at
// the same position).
func (l *locator) skip(which int) {
	if which < 0 || l.next[which] < 0 {
		return
	}
	l.next[which], l.nextEnd[which] = l.search(which, l.next[which]+1)
	if l.next[which] < 0 {
		l.next[which] = -1
	}
}

// needleRegexes compiles one folded, case-insensitive regex per needle for
// the regex locator.
func needleRegexes(needles []string, ci bool) []*regexp.Regexp {
	res := make([]*regexp.Regexp, len(needles))
	for i, n := range needles {
		p := regexp.QuoteMeta(n)
		if ci {
			p = pyFoldI(`(?i)` + p)
		}
		res[i] = regexp.MustCompile(p)
	}
	return res
}

// ------------------------------------------------------------------ candidate rows

// candidateScan is a row whose every match STARTS at a needle: the anchored
// regex (the row's pattern without its leading and trailing `\b`) is matched
// at each candidate, then the boundaries are checked in code — exactly
// re.sub's non-overlapping left-to-right walk under Python's `\b`.
type candidateScan struct {
	anchored  *regexp.Regexp // `^(?:` + body + `)`; a trailing-`\b` row wraps its final variable run in group tailGroup
	needles   []string       // lowercase when ci
	needleRes []*regexp.Regexp
	ci        bool
	wordStart bool // the pattern starts with `\b`
	wordEnd   bool // the pattern ends with `\b`
	tailGroup int  // the group of the final variable run (wordEnd rows): candidate ends run from the match end down to that group's start plus tailMin characters
	tailMin   int
	ends      func(s string, m []int) []int // irregular rows: explicit candidate ends, longest first (overrides tailGroup)
}

type candidateSpec struct {
	body      string // the row's pattern without its leading/trailing `\b` (flags included)
	needles   []string
	ci        bool
	wordStart bool
	wordEnd   bool
	tailGroup int
	tailMin   int
	ends      func(s string, m []int) []int
}

func newCandidateScan(sp candidateSpec) *candidateScan {
	body := sp.body
	if sp.ci {
		body = pyFoldI(body)
	}
	return &candidateScan{
		anchored:  regexp.MustCompile(`^(?:` + body + `)`),
		needles:   sp.needles,
		needleRes: needleRegexes(sp.needles, sp.ci),
		ci:        sp.ci,
		wordStart: sp.wordStart,
		wordEnd:   sp.wordEnd,
		tailGroup: sp.tailGroup,
		tailMin:   sp.tailMin,
		ends:      sp.ends,
	}
}

// candidateScanner walks one document.
type candidateScanner struct {
	spec     *candidateScan
	s        string
	loc      *locator
	boundary map[int]int // maximal end -> nearest pyBoundary at or below it (-1 none): a run is walked back once per pass
}

func (c *candidateScan) scanner(s string) *candidateScanner {
	sc := &candidateScanner{spec: c, s: s}
	if forceRegexPath || (c.ci && hasExoticFold(s)) {
		sc.loc = regexLocator(s, c.needleRes)
		return sc
	}
	hay := s
	if c.ci {
		hay = asciiLower(s)
	}
	sc.loc = literalLocator(hay, c.needles)
	return sc
}

// next returns the next candidate start at or after pos that passes the
// leading-`\b` check, with its needle index, or -1.
func (sc *candidateScanner) next(pos int) (int, int) {
	for {
		f, _, which := sc.loc.find(pos)
		if f < 0 {
			return -1, -1
		}
		if sc.spec.wordStart && pyWordBefore(sc.s, f) {
			sc.loc.skip(which)
			continue
		}
		return f, which
	}
}

// try matches the row at candidate c: absolute submatch indices (the end
// adjusted to the chosen trailing boundary), or nil.
func (sc *candidateScanner) try(c int) []int {
	m := matchAt(sc.spec.anchored, sc.s, c)
	if m == nil {
		return nil
	}
	if !sc.spec.wordEnd {
		return m
	}
	e := sc.trailingEnd(m)
	if e < 0 {
		return nil
	}
	m[1] = e
	return m
}

// trailingEnd is the longest candidate end of m carrying a Python `\b`, or -1.
func (sc *candidateScanner) trailingEnd(m []int) int {
	s := sc.s
	if sc.spec.ends != nil {
		for _, e := range sc.spec.ends(s, m) {
			if pyBoundaryAt(s, e) {
				return e
			}
		}
		return -1
	}
	eMax := m[1]
	minEnd := eMax
	if sc.spec.tailGroup > 0 {
		minEnd = advanceRunes(s, m[2*sc.spec.tailGroup], sc.spec.tailMin)
	}
	if sc.boundary == nil {
		sc.boundary = map[int]int{}
	}
	b, ok := sc.boundary[eMax]
	if !ok {
		// Walk back from the maximal end to the nearest boundary; any
		// candidate sharing this maximal end shares the answer.
		b = -1
		for e := eMax; ; {
			if pyBoundaryAt(s, e) {
				b = e
				break
			}
			if e == 0 {
				break
			}
			_, n := utf8.DecodeLastRuneInString(s[:e])
			e -= n
		}
		sc.boundary[eMax] = b
	}
	if b >= minEnd {
		return b
	}
	return -1
}

// advanceRunes returns the byte position n runes after pos (clamped).
func advanceRunes(s string, pos, n int) int {
	for i := 0; i < n && pos < len(s); i++ {
		_, w := utf8.DecodeRuneInString(s[pos:])
		pos += w
	}
	return pos
}

// search is re.search(s, pos): the leftmost match starting at or after pos.
func (sc *candidateScanner) search(pos int) []int {
	for {
		c, which := sc.next(pos)
		if c < 0 {
			return nil
		}
		if m := sc.try(c); m != nil {
			return m
		}
		sc.loc.skip(which)
	}
}

// skipCandidate drops the current candidate's needle (the caller moves on).
func (sc *candidateScanner) skipCandidate(which int) { sc.loc.skip(which) }

// findAll is re.finditer / re.sub's match list over the whole document.
func (c *candidateScan) findAll(s string) [][]int {
	sc := c.scanner(s)
	var out [][]int
	pos := 0
	for pos <= len(s) {
		m := sc.search(pos)
		if m == nil {
			break
		}
		out = append(out, m)
		if m[1] > m[0] {
			pos = m[1]
		} else {
			pos = m[1] + 1
		}
	}
	return out
}

// ------------------------------------------------------------------ prefix rows

// prefixScan is a row whose match CONTAINS a needle (a family word) but
// starts before it (at a separator, a `^`, a key quote): the search runs the
// regex in a window from the search position to the maximal extent of a
// match from the needle's end (the tail). Every match's needle lies in one
// contiguous identifier run with its tail, so a window that holds the
// needle's tail holds every match through that needle, and the leftmost
// match of the window is the leftmost match of re.search. The prefix regexes
// carry no `\b`.
type prefixScan struct {
	re        *regexp.Regexp // the table's prefix regex (folded)
	tail      tail
	start     windowStart // the earliest position a match through a needle can start
	needles   []string    // lowercase (every prefix row is `(?i)`)
	needleRes []*regexp.Regexp
}

// windowStart bounds a window on the left: every match through a needle at f
// starts inside the identifier run containing f or a bounded distance before
// it, so the regex never re-reads the text before that run. Memoised per run.
type windowStart interface {
	start(s string, f int, memo *tailMemo) int
}

// runAround returns the extent [r, e) of the maximal class run containing
// position f (walking back and forward), so every needle of the run shares
// one memo entry.
func runAround(s string, f int, class func(rune) bool) (int, int) {
	r := f
	for r > 0 {
		c, w := utf8.DecodeLastRuneInString(s[:r])
		if !class(c) {
			break
		}
		r -= w
	}
	e := f
	for e < len(s) {
		c, w := utf8.DecodeRuneInString(s[e:])
		if !class(c) {
			break
		}
		e += w
	}
	return r, e
}

// keyRunRune is `(?i)[A-Za-z0-9_-]` (the JSON key run) under Python's folding.
func keyRunRune(r rune) bool { return r == '-' || identRune(r) }

// assignRunRune is `(?i)[A-Za-z0-9_.]` (the assignment identifier run).
func assignRunRune(r rune) bool { return r == '.' || identRune(r) }

// jsonKeyStart: a match starts at the quote right before the key run.
type jsonKeyStart struct{}

func (jsonKeyStart) start(s string, f int, memo *tailMemo) int {
	if memo.winValid && f >= memo.winRunStart && f < memo.winRunEnd {
		return memo.winStart
	}
	r, e := runAround(s, f, keyRunRune)
	st := r - 1
	if st < 0 {
		st = 0
	}
	memo.winValid, memo.winRunStart, memo.winRunEnd, memo.winStart = true, r, e, st
	return st
}

// assignStart: a match starts at the separator before the identifier run,
// or before an optional keyword (`export`, `const`, …) and the whitespace run
// that precedes the identifier.
type assignStart struct{}

var assignKeywords = []string{"export", "const", "let", "var", "local", "readonly", "set"}

// foldEqualASCII compares s to an ASCII lowercase word under the `(?i)`
// equivalences of this table (ASCII case, ſ~s, K~k, ı/İ~i).
func foldEqualASCII(s, word string) bool {
	i := 0
	for _, w := range word {
		if i >= len(s) {
			return false
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		lr := r
		if r >= 'A' && r <= 'Z' {
			lr = r + ('a' - 'A')
		}
		switch r {
		case 'ſ':
			lr = 's'
		case 'K':
			lr = 'k'
		case 'ı', 'İ':
			lr = 'i'
		}
		if lr != w {
			return false
		}
	}
	return i == len(s)
}

func (assignStart) start(s string, f int, memo *tailMemo) int {
	if memo.winValid && f >= memo.winRunStart && f < memo.winRunEnd {
		return memo.winStart
	}
	r, e := runAround(s, f, assignRunRune)
	st := runeBefore(s, r) // the separator (or `^`)
	// optional keyword + whitespace run right before the identifier
	w := r
	for w > 0 {
		c, n := utf8.DecodeLastRuneInString(s[:w])
		if !isPySpace(c) {
			break
		}
		w -= n
	}
	if w < r {
		for _, kw := range assignKeywords {
			// The keyword's folded spelling may be longer in bytes than its
			// ASCII form (`conſt`, `ſet`), so step back by runes.
			k0 := w
			for i := 0; i < len(kw) && k0 > 0; i++ {
				_, n := utf8.DecodeLastRuneInString(s[:k0])
				k0 -= n
			}
			if foldEqualASCII(s[k0:w], kw) {
				st = runeBefore(s, k0)
				break
			}
		}
	}
	memo.winValid, memo.winRunStart, memo.winRunEnd, memo.winStart = true, r, e, st
	return st
}

// runeBefore returns the byte offset of the rune that ends at pos (0 at the
// document start): a window start on a rune boundary, never inside one.
func runeBefore(s string, pos int) int {
	if pos <= 0 {
		return 0
	}
	_, n := utf8.DecodeLastRuneInString(s[:pos])
	return pos - n
}

// tail bounds a window: the maximal extent of a match from a needle end.
type tail interface {
	// end returns the window limit for a needle ending at fEnd, or -1 when
	// no match can complete through that needle. memo is per-document state.
	end(s string, fEnd int, memo *tailMemo) int
}

type tailMemo struct {
	valid                     bool
	runFrom, runEnd, runLimit int // the identifier run containing the last needle, and its tail result
	winValid                  bool
	winRunStart, winRunEnd    int // the identifier run of the last window-start query
	winStart                  int
}

// regexTail is an anchored tail pattern (bounded cost per needle).
type regexTail struct{ re *regexp.Regexp }

func (t regexTail) end(s string, fEnd int, _ *tailMemo) int {
	if m := matchAt(t.re, s, fEnd); m != nil {
		return m[1]
	}
	return -1
}

// runTail is the assignment row's tail `[A-Za-z0-9_]*[ \t]*[=:][ \t]*`: the
// identifier run after the family word is measured once per run (every
// needle inside the same run shares its end and its result), so a long run
// of family words with no delimiter costs O(n), not O(n²).
type runTail struct{ after *regexp.Regexp }

// identRune is `(?i)[A-Za-z0-9_]` under Python's folding: ASCII
// alphanumerics, `_`, and the four letters the class folds to (ı İ ſ K).
func identRune(r rune) bool {
	return r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		r == 'ı' || r == 'İ' || r == 'ſ' || r == 'K'
}

func (t runTail) end(s string, fEnd int, memo *tailMemo) int {
	if memo.valid && fEnd >= memo.runFrom && fEnd <= memo.runEnd {
		return memo.runLimit
	}
	e := fEnd
	for e < len(s) {
		r, w := utf8.DecodeRuneInString(s[e:])
		if !identRune(r) {
			break
		}
		e += w
	}
	limit := -1
	if m := matchAt(t.after, s, e); m != nil {
		limit = m[1]
	}
	*memo = tailMemo{valid: true, runFrom: fEnd, runEnd: e, runLimit: limit}
	return limit
}

func newPrefixScan(pattern string, t tail, st windowStart, needles ...string) *prefixScan {
	return &prefixScan{re: regexp.MustCompile(pyFoldI(pattern)), tail: t, start: st, needles: needles, needleRes: needleRegexes(needles, true)}
}

func newRegexTail(pattern string) tail {
	return regexTail{regexp.MustCompile(`^(?i)(?:` + pyFoldI(pattern) + `)`)}
}

type prefixScanner struct {
	spec *prefixScan
	s    string
	loc  *locator
	memo tailMemo
	// The last failed window: a later window inside it cannot match either
	// (every needle of one identifier run shares the run's window, so the
	// run's regex search runs once; successive runs have disjoint windows).
	failedFrom, failedLimit int
}

func (p *prefixScan) scanner(s string) *prefixScanner {
	sc := &prefixScanner{spec: p, s: s, failedFrom: -1, failedLimit: -1}
	if forceRegexPath || hasExoticFold(s) {
		sc.loc = regexLocator(s, p.needleRes)
		return sc
	}
	sc.loc = literalLocator(asciiLower(s), p.needles)
	return sc
}

// search is re.search(s, pos) for the prefix pattern: for each needle in
// order, the window [max(pos, start), limit] holds every match through that
// needle (a match through an earlier needle lay inside an earlier window and
// was not found), so the leftmost match of the first non-empty window is the
// leftmost match overall. Windows of successive runs are disjoint up to the
// bounded keyword prefix: the pass is linear.
func (sc *prefixScanner) search(pos int) []int {
	for {
		f, fEnd, which := sc.loc.find(pos)
		if f < 0 {
			return nil
		}
		if limit := sc.spec.tail.end(sc.s, fEnd, &sc.memo); limit >= 0 {
			from := sc.spec.start.start(sc.s, f, &sc.memo)
			if from < pos {
				from = pos
			}
			if !(sc.failedFrom >= 0 && from >= sc.failedFrom && limit <= sc.failedLimit) {
				if m := findFromWindow(sc.spec.re, sc.s, from, limit); m != nil {
					return m
				}
				sc.failedFrom, sc.failedLimit = from, limit
			}
		}
		sc.loc.skip(which)
	}
}

// findFromWindow is findFrom bounded to s[:limit].
func findFromWindow(re *regexp.Regexp, s string, pos, limit int) []int {
	if limit > len(s) {
		limit = len(s)
	}
	if pos > limit {
		return nil
	}
	return findFrom(re, s[:limit], pos)
}

// v6 keeps the P4 locators and adds anchored, linear key/value decisions.
// These patterns are the published reference grammar, not heuristic parsers.
var (
	assignFamily      = regexp.MustCompile(pyFoldI(`(?i)` + envFamily))
	assignHead        = regexp.MustCompile(pyFoldI(`(?i)^(?:[A-Za-z0-9_]*` + envFamily + `(?:_?(?:KEY(?:_?BASE)?|ACCESS_?KEY|VALUE|STR(?:ING)?|B64|BASE64|HEX|PEM|JSON))?(?:_?(?:PROD(?:UCTION)?|DEV|STAG(?:E|ING)|TEST|LIVE|OLD|NEW|PREV(?:IOUS)?|NEXT|CURRENT|CONFIRM(?:ATION)?|RAW|PLAIN|ENC(?:RYPTED)?))?(?:_?V?[0-9]+)?)$`))
	assignCodeOpen    = regexp.MustCompile(`^(?:[(\[{]|[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*[(\[<])`)
	assignCodeCallEnd = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\)$`)
	assignCodeRef     = regexp.MustCompile(`^(?:[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*(?:\(\)?|\[)[;,]?|\$\([^` + wsChars + `]*)$`)
	assignRefLed      = regexp.MustCompile(`^(?:[A-Za-z_$][A-Za-z0-9_$]*\()*(?:os|process|settings|config|conf|cfg|env|ENV|environ|getenv|import\.meta|app|current_app|self|this|Deno|Bun|System|Environment)(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*|[(\[<])[^` + wsChars + `'"\\]*$`)
	headerProse       = regexp.MustCompile(`^[A-Za-z]+(?:-[A-Za-z]+)*[,.;:!?]?(?:[ \t]+[A-Za-z]+(?:-[A-Za-z]+)*[,.;:!?]?){2,}[ \t]*$`)
	cliHead           = regexp.MustCompile(`^--?(?:[A-Za-z0-9]+[_-])*$`)
	cliNames          = newCandidateScan(candidateSpec{body: `(?i)(?:password|passwd|token|api[_-]?key|secret|access[_-]?key)(?:=|[ \t]+)`, needles: []string{"password", "passwd", "token", "api", "secret", "access"}, ci: true})
)

func assignPrefixFinder(s string) func(int) []int {
	scanner := scanAssignPrefix.scanner(s)
	return func(pos int) []int {
		for {
			m := scanner.search(pos)
			if m == nil {
				return nil
			}
			// Walk back from the delimiter to the key. Accepted/rejected runs
			// are disjoint because the next search starts after this prefix.
			e := m[1]
			for e > m[0] && (s[e-1] == ' ' || s[e-1] == '\t') {
				e--
			}
			e-- // ':' or '='
			op := e
			if s[op] == ':' && op+1 < len(s) && s[op+1] == ':' {
				pos = m[1]
				continue
			}
			for e > m[0] && (s[e-1] == ' ' || s[e-1] == '\t') {
				e--
			}
			start := e
			for start > m[0] {
				r, width := utf8.DecodeLastRuneInString(s[:start])
				if !assignRunRune(r) {
					break
				}
				start -= width
			}
			k0 := start
			if k0 > 0 && s[k0-1] == '\\' && k0 < e && strings.ContainsRune("nrtbf", rune(s[k0])) {
				k0++
			}
			segment := start + strings.LastIndexByte(s[start:e], '.') + 1
			family := assignFamily.FindStringIndex(s[segment:e])
			if family == nil {
				pos = m[1]
				continue
			}
			f, fe := segment+family[0], segment+family[1]
			codeCased := false
			for i := k0; i < fe; i++ {
				if s[i] >= 'a' && s[i] <= 'z' {
					codeCased = true
					break
				}
			}
			if codeCased && !(fe == e && k0 <= f) && !assignHead.MatchString(s[max(f, k0):e]) {
				pos = m[1]
				continue
			}
			code := 0
			if codeCased {
				code = 1
			}
			anchor := k0
			// A keyword prefix anchors the statement at its keyword, not its key.
			head := m[0]
			if head < len(s) {
				r, w := utf8.DecodeRuneInString(s[head:])
				if !assignRunRune(r) {
					head += w
				}
			}
			if head < start {
				anchor = head
			}
			return []int{m[0], m[1], code, anchor, op}
		}
	}
}

var (
	assignOpaque       = regexp.MustCompile(`^[A-Za-z0-9+/=_~.!@#%^&*-][A-Za-z0-9+/=_~.!@#%^&*$-]*$`)
	assignOpaqueSignal = regexp.MustCompile(`[0-9+=!@#%^&*~$]`)
	assignNumeric      = regexp.MustCompile(`^(?:[-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?|[-+]?[0-9]+[eE][-+]?[0-9]+|v?[0-9]+(?:\.[0-9]+){2,})$`)
	assignPath         = regexp.MustCompile(`^(?:~|\.{1,2})?/[A-Za-z0-9._@-]*(?:/[A-Za-z0-9._@-]*)*$`)
	assignDotted       = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\??\.|->)[A-Za-z_$][A-Za-z0-9_$]*)+$`)
)

func lineStartsAt(s string, i int) bool {
	j := i
	dash := false
	for j > 0 {
		c := s[j-1]
		if c == ' ' || c == '\t' {
			j--
		} else if c == 't' && j > 1 && s[j-2] == '\\' {
			j -= 2
		} else if c == '-' && !dash && j < i && s[j] == ' ' {
			dash = true
			j--
		} else {
			break
		}
	}
	if j == 0 {
		return true
	}
	c := s[j-1]
	return strings.ContainsRune("\n\r\"'", rune(c)) || ((c == 'n' || c == 'r') && j > 1 && s[j-2] == '\\')
}
func lineEndsAt(s string, i int) bool {
	j := i
	for j < len(s) {
		if s[j] == ' ' || s[j] == '\t' {
			j++
			continue
		}
		b := j
		for b < len(s) && s[b] == '\\' && b-j < MaxEscapeBackslashes {
			b++
		}
		if b > j && b < len(s) && s[b] == 't' {
			j = b + 1
			continue
		}
		break
	}
	if j >= len(s) || strings.ContainsRune("\r\n\"'", rune(s[j])) {
		return true
	}
	if s[j] == '#' && j > i {
		return true
	}
	if s[j] != '\\' {
		return false
	}
	for j < len(s) && s[j] == '\\' {
		j++
	}
	return j < len(s) && strings.ContainsRune("nr\"'", rune(s[j]))
}
func opaqueAssignment(value string) bool {
	return assignOpaque.MatchString(value) && assignOpaqueSignal.MatchString(value) && !assignNumeric.MatchString(value)
}
func assignBareKept(s string, match []int, vs, ve int, value string) bool {
	if assignCodeRef.MatchString(value) || assignRefLed.MatchString(value) {
		return true
	}
	core := value
	if len(value) > 1 && strings.ContainsRune(",;", rune(value[len(value)-1])) {
		core = value[:len(value)-1]
	}
	if match[2] == 0 {
		if s[match[4]] == ':' && match[4]+1 == vs {
			return !opaqueAssignment(core)
		}
		return false
	}
	if (strings.ContainsRune("()[]{}<>,;:", rune(value[len(value)-1])) && assignCodeOpen.MatchString(value)) || assignCodeCallEnd.MatchString(value) {
		return true
	}
	if opaqueAssignment(core) {
		return false
	}
	if !strings.ContainsRune(",;", rune(value[len(value)-1])) && !strings.Contains(value, "::") && !strings.Contains(value, ":/") && !assignNumeric.MatchString(value) && !(assignPath.MatchString(value) && strings.Contains(value, ".")) && !assignDotted.MatchString(value) && lineStartsAt(s, match[3]) && lineEndsAt(s, ve) {
		return false
	}
	return true
}

func cliGlue(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func cliPrefixFinder(s string) func(int) []int {
	names := cliNames.scanner(s)
	lo := 0
	return func(pos int) []int {
		lo = max(lo, pos)
		for {
			m := names.search(pos)
			if m == nil {
				return nil
			}
			f, end := m[0], m[1]
			r := f
			for r > lo && cliGlue(s[r-1]) {
				r--
			}
			oldLo := lo
			lo, pos = end, end
			if r == oldLo && r > 0 && cliGlue(s[r-1]) {
				continue
			}
			if r > 0 && s[r-1] == '\\' && r < f && strings.ContainsRune("nrtbf", rune(s[r])) && r+1 < f {
				r++
			}
			if r < f && s[r] == '-' && cliHead.MatchString(s[r:f]) {
				return []int{r, end}
			}
		}
	}
}
