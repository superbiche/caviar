// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

// Package redact implements the redact-v7 secret-filter contract.
// Detection uses explicit patterns and bounded capture procedures, without
// entropy guessing or language-model calls. The hash-pinned corpus and Python
// reference are reproducible conformance inputs (see docs/DEVELOPMENT.md).
//
// A match is replaced by "[REDACTED:<rule>:<hash8>]" where hash8 is the first
// 8 hex chars of HMAC-SHA256(key, secret) (plain SHA-256 without a key) —
// occurrences of the same secret correlate across events without revealing
// the value.
//
// Port notes (contract §Reference implementation, Go notes; the Python module
// is the executable statement of every procedure, this file mirrors its
// structure helper for helper so a reviewer can diff the two):
//
//   - P0 (marker ownership) is one marker scan per distinct rule-input text,
//     skipped when the document carries no "[REDACTED:"; an ownership query
//     is a bisect.
//   - P1 captures through capture_value: the line end comes from a LineEnds
//     index built once per pass, never from a search per capture.
//   - Rows 21–23 measure the COMPLETE backslash run before the key quote in
//     code (escapeDepth) and reject a run longer than 63; an unanchored
//     `(\\{0,63})"` would accept the last 63 of a longer run.
//   - P3 (PEM) is four bounded searches per BEGIN, the next BEGIN located
//     first.
//   - Rows 2, 24 and 26 keep the locator scans of the reference module so the
//     two implementations stay diffable (Go RE2 would also accept the table's
//     regexes directly); every pattern is RE2-clean except row 8, ported in
//     its greedy form: `\blbx1_[A-Za-z0-9_-]{20,}` without the lookahead —
//     the greedy class already takes the maximal run, so no run character can
//     follow the match (equivalence tested).
//   - Floors and MinMatchChars count code points (utf8.RuneCountInString).
//   - Python's re.search(s, pos) is emulated by findFrom: the search runs on
//     s[pos-1:] so `^` (multiline) and `\b` see the character before pos; a
//     match starting at pos-1 is not one Python would report and is retried
//     from pos. Row 27 can reach the retry after rejecting a code-cased key;
//     its preceding delimiter also admits Python's start at pos-1, yielding
//     the same key/value span.
//   - No Go engine semantics leak into the result: Python's `\s` class,
//     `(?i)` equivalences (ı/İ, ſ, K) and Unicode `\b` (pyWord, pinned to
//     the reference runtime's Unicode table) are spelled into the patterns or
//     evaluated in code (locate.go), Python's str.lower() drives the policy
//     comparisons (pyLower) and json.dumps drives numbers under secret keys
//     (pyNumberText). The Go-vs-Python differential is the oracle.
package redact

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// RulesVersion identifies the rule set used for audit metadata.
// Bump on any rule change so audit metadata identifies the applied rules.
const RulesVersion = "redact-v7"

const (
	// Floor is the minimum value length (code points) of the assignment,
	// header, CLI and JSON secret-field rules.
	Floor = 8
	// MinKeyBytes is the shortest HMAC key New accepts.
	MinKeyBytes = 16
	// MaxNesting bounds the text P2 walk (enclosing secret-named objects) and
	// the structured walk (container levels, root = 1); beyond it the scrub
	// fails closed with ErrDepth.
	MaxNesting = 512
	// MaxEscapeBackslashes bounds a quote opener's backslash run (escape
	// depth 6); a longer run is not a quote (P4).
	MaxEscapeBackslashes = 63
	// MaxURLScheme bounds a URL scheme (letter + 31 of [A-Za-z0-9+.-]).
	MaxURLScheme = 32
	// MinMatchChars is the shortest document any rule can change
	// (`a://:p@`, url-credentials, no floor).
	MinMatchChars = 7
)

// ErrDepth is the fail-closed nesting error (the contract's RedactDepthError):
// callers must fail closed rather than write unredacted content.
var ErrDepth = errors.New("redact: nesting deeper than 512")

// Hit reports one rule's matches within a redacted document.
type Hit struct {
	Rule  string `json:"rule"`
	Count int    `json:"count"`
}

const (
	keyFamily   = `(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|private[_-]?key|credentials?|authorization|auth|cookie)`
	envFamily   = `(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS?)`
	headerNames = `(?:proxy-authorization|authorization|set-cookie|cookie|x-api-key|api-key|x-auth-token|x-goog-api-key|x-amz-security-token|private-token|x-csrf-token|x-xsrf-token)`
	esc         = `\\{0,63}` // the backslash run of a quote at escape depth <= 6 (MaxEscapeBackslashes)
)

var (
	schemaScalarKeys = map[string]bool{"default": true, "example": true, "const": true}
	schemaListKeys   = map[string]bool{"examples": true, "enum": true}
	// safeObjectKeys: direct children of an object under a secret-named key
	// that are NOT credential material (JSON Schema vocabulary, identifiers,
	// locators); their string values still pass through the string rules.
	safeObjectKeys = map[string]bool{
		"type": true, "description": true, "title": true, "format": true, "pattern": true,
		"$ref": true, "$schema": true, "$id": true, "$comment": true,
		"contentencoding": true, "contentmediatype": true,
		"name": true, "username": true, "user": true, "id": true, "kind": true, "method": true,
		"scheme": true, "realm": true, "url": true, "host": true, "path": true, "file": true, "mode": true,
	}
)

// Python-parity classes (contract: the Python reference module is the
// executable statement of the procedures; Go's `\s` is ASCII [\t\n\f\r ],
// Python's `\s` on str is every character with str.isspace() — \v, the
// C1/Unicode separators, NBSP… — and Python's `(?i)` also folds i to the
// Turkish ı/İ, which Go's simple folding does not). Every `\s` of the table
// is spelled with wsChars, every literal i of a `(?i)` pattern with [iıİ],
// so the Go port never matches LESS than the reference on these classes.
// The remaining engine difference is `\b`: Go's is ASCII, Python's Unicode,
// so next to a non-ASCII letter Go sees a boundary Python does not — Go
// then matches MORE (a shape token glued to é is still redacted), never
// less (TestDifferentialDump evidence, port record L0004).
const wsChars = `\t\n\v\f\r \x1c-\x1f\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}`
const ws = `[` + wsChars + `]`

// isPySpace is str.isspace() (the `\s` class above).
func isPySpace(r rune) bool {
	switch {
	case r >= 0x9 && r <= 0xd, r >= 0x1c && r <= 0x20, r == 0x85, r == 0xa0, r == 0x1680,
		r >= 0x2000 && r <= 0x200a, r == 0x2028, r == 0x2029, r == 0x202f, r == 0x205f, r == 0x3000:
		return true
	}
	return false
}

// isSpaceAt reports whether the character starting at s[i] is a `\s`.
func isSpaceAt(s string, i int) bool {
	if s[i] < utf8.RuneSelf {
		return isPySpace(rune(s[i]))
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return isPySpace(r)
}

// pyStrip is str.strip(): both ends trimmed of isspace() characters.
func pyStrip(s string) string {
	for len(s) > 0 && isSpaceAt(s, 0) {
		_, n := utf8.DecodeRuneInString(s)
		s = s[n:]
	}
	for len(s) > 0 {
		r, n := utf8.DecodeLastRuneInString(s)
		if !isPySpace(r) {
			break
		}
		s = s[:len(s)-n]
	}
	return s
}

// pyFoldI rewrites a `(?i)` pattern for Python's case-insensitive
// equivalences, which Go's simple folding lacks: every literal i or I
// (outside character classes, flag groups and escapes) becomes [iıİ]
// (i ~ ı U+0131; İ U+0130 lowercases to i), and every character class
// carrying an A-Z or a-z range gains ıİ (Python widens [A-Za-z] under
// IGNORECASE to İ, ı, ſ and K; Go already folds the last two).
func pyFoldI(pattern string) string {
	var b strings.Builder
	inClass, inFlags := false, false
	classStart, classWiden := 0, false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '\\' && i+1 < len(pattern):
			b.WriteByte(c)
			b.WriteByte(pattern[i+1])
			i++
			continue
		case inClass:
			if c == ']' {
				inClass = false
				if classWiden {
					// insert right after `[` or `[^`, where no range can absorb it
					cur := b.String()
					at := classStart + 1
					if at < len(cur) && cur[at] == '^' {
						at++
					}
					cur = cur[:at] + "ıİ" + cur[at:]
					b.Reset()
					b.WriteString(cur)
				}
			} else if (c == 'Z' || c == 'z') && i >= 2 && pattern[i-1] == '-' && (pattern[i-2] == 'A' || pattern[i-2] == 'a') {
				classWiden = true
			}
		case inFlags:
			if c == ')' || c == ':' {
				inFlags = false
			}
		case c == '[':
			inClass, classWiden, classStart = true, false, b.Len()
		case c == '(' && i+1 < len(pattern) && pattern[i+1] == '?':
			inFlags = true
		case c == 'i' || c == 'I':
			b.WriteString(`[iıİ]`)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func pyRe(pattern string) *regexp.Regexp { return regexp.MustCompile(pyFoldI(pattern)) }

var (
	markerRe   = regexp.MustCompile(`\[REDACTED:[a-z0-9-]+:[0-9a-f]{8}\]`)   // P0: the marker grammar as it appears in a document
	pemBegin   = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`) // P3 locator
	pemEnd     = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	pemBlank   = regexp.MustCompile(`\n[ \t\r]*\n`) // a blank line: the bound of a truncated block
	pemHeaders = regexp.MustCompile(`^(?:\r?\n[A-Za-z][A-Za-z0-9-]*:[^\r\n]*)+\r?\n[ \t\r]*\n`)

	// Prefix patterns: everything before the value; the value itself is captured by P1.
	mysqlScan = regexp.MustCompile(ws + `-p|\\{0,15}["']|[;|&` + "`" + `]|\\[nr]`)
	// The key locators start at the key's opening quote; its backslash run
	// (the escape depth) is measured in code by escapeDepth.
	secretKeyRe = pyRe(`(?i)^[A-Za-z0-9_-]*` + keyFamily + `$`)
	quoteOpen   = regexp.MustCompile(`^(` + esc + `)"`)
	quoteOrCtrl = regexp.MustCompile(`["\x00-\x1f]`) // P1 closer scan at depth 0: the next quote or control character
	// P2 skip: the next token of a JSON container — a complete depth-0 string
	// without control characters (same extent as P1), else one delimiter.
	containerToken = regexp.MustCompile(`"(?:[^"\\\x00-\x1f]|\\[^\x00-\x1f])*"|["\\{}\[\]]`)
	// P4: the depth-0 string scan in one match — group 1 is the closing quote
	// (the first quote preceded by an even number of backslashes), group 2 the
	// control character that leaves the value unclosed; neither when the body
	// stops at a backslash before a control character or at the end.
	stringScan = regexp.MustCompile(`^"(?:[^"\\\x00-\x1f]|\\[^\x00-\x1f])*(?:(")|([\x00-\x1f]))?`)
	// url-credentials: the table's regex is the specification (RE2-clean,
	// group 2 the password); the module scans from its `://` locator.
	urlCredentialsRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]{0,31}:(?:\\?/){2}[^:@/?#` + wsChars + `\\]*:)([^@` + wsChars + `?#/"'\\]+)@`)
	urlUserinfoEnd   = regexp.MustCompile(`[:@/?#` + wsChars + `\\]`)
	urlPasswordEnd   = regexp.MustCompile(`[@` + wsChars + `?#/"'\\]`)
	// jwt: the table's regex (group 0) and the locator the module scans from.
	b64URLRun  = regexp.MustCompile(`^[A-Za-z0-9_-]+`)
	numberRe   = regexp.MustCompile(`^-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?`)
	bareRe     = regexp.MustCompile(`^[^` + wsChars + `'"\\]+`)
	bareLineRe = regexp.MustCompile(`^[^\r\n"'\\]+`)
	wsRe       = regexp.MustCompile(`^` + ws + `*`)
	wsCommaRe  = regexp.MustCompile(`^[` + wsChars + `,]*`)
	colonRe    = regexp.MustCompile(`^` + ws + `*:` + ws + `*`)
	scalarRe   = regexp.MustCompile(`^[^,}\]` + wsChars + `]+`)

	completeReference = regexp.MustCompile(`^(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$\{\{[^{}]*\}\}|\$\([^()]*\)|\{\{[^{}]*\}\}|\{env:[^{}]+\}|<[^<>]+>|%[A-Za-z_][A-Za-z0-9_]*%|op://[^` + wsChars + `]+)$`)
	asterisks         = regexp.MustCompile(`^\*{3,}$`)
)

var placeholderPrefixes = []string{"changeme", "change-me", "placeholder", "example", "xxxxx", "dummy", "your-", "your_"}

// placeholderWords: whole-value placeholder words (case-insensitive) a config
// or a log prints instead of a value.
var placeholderWords = map[string]bool{
	"required": true, "optional": true, "undefined": true, "redacted": true,
	"[redacted]": true, "[filtered]": true, "[masked]": true, "[hidden]": true,
}

// marked reports whether v carries a [REDACTED: marker (P0 containment check:
// a truncated marker is still never re-wrapped).
func marked(v string) bool { return strings.Contains(v, "[REDACTED:") }

// exempt reports reference/placeholder shapes that look like secret values but
// are safe by design (§Exemption list): prefix and whole-value checks only.
func exempt(value string) bool {
	v := pyStrip(value)
	if utf8.RuneCountInString(v) < 2 { // the shortest exempt value is a 2-character reference ($a)
		return false
	}
	c := v[0]
	if c == '[' && strings.HasPrefix(v, "[REDACTED:") {
		return true
	}
	if strings.IndexByte("${<%o", c) >= 0 && completeReference.MatchString(v) {
		return true
	}
	if c == '*' && asterisks.MatchString(v) {
		return true
	}
	lower := pyLower(v)
	if placeholderWords[lower] {
		return true
	}
	for _, p := range placeholderPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func runeLen(s string) int { return utf8.RuneCountInString(s) }

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isURLSchemeChar(c byte) bool {
	return isASCIILetter(c) || (c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-'
}

// findFrom emulates Python's re.search(s, pos): the leftmost match starting at
// or after pos, with `^` and `\b` seeing the character before pos. Returns
// absolute submatch indices or nil.
func findFrom(re *regexp.Regexp, s string, pos int) []int {
	if pos > len(s) {
		return nil
	}
	base := pos
	if pos > 0 {
		base = pos - 1 // one character of context for `^` (multiline) and `\b`
	}
	loc := re.FindStringSubmatchIndex(s[base:])
	if loc == nil {
		return nil
	}
	if loc[0] == 0 && base < pos {
		// A match at pos-1 is not one Python would report (unreachable for
		// this table's locators, see the package note); retry from pos.
		loc = re.FindStringSubmatchIndex(s[pos:])
		if loc == nil {
			return nil
		}
		base = pos
	}
	for i := range loc {
		if loc[i] >= 0 {
			loc[i] += base
		}
	}
	return loc
}

// findBounded is re.search(s, pos, endpos) for patterns without start-context
// sensitivity (none of the bounded searches of this table starts with `^` or `\b`).
func findBounded(re *regexp.Regexp, s string, pos, limit int) []int {
	if limit > len(s) {
		limit = len(s)
	}
	if pos > limit {
		return nil
	}
	loc := re.FindStringIndex(s[pos:limit])
	if loc == nil {
		return nil
	}
	return []int{loc[0] + pos, loc[1] + pos}
}

// matchAt is re.match(s, pos) for a `^`-anchored pattern: absolute indices.
func matchAt(re *regexp.Regexp, s string, pos int) []int {
	if pos > len(s) {
		return nil
	}
	loc := re.FindStringSubmatchIndex(s[pos:])
	if loc == nil {
		return nil
	}
	for i := range loc {
		if loc[i] >= 0 {
			loc[i] += pos
		}
	}
	return loc
}

// lineEnds is P4's line index: every newline located once per pass; a query
// is a bisect, so a line with many captures is never rescanned per capture.
type lineEnds struct {
	newlines []int
	n        int
}

func newLineEnds(s string) *lineEnds {
	le := &lineEnds{n: len(s)}
	off := 0
	for {
		i := strings.IndexByte(s[off:], '\n')
		if i < 0 {
			break
		}
		le.newlines = append(le.newlines, off+i)
		off += i + 1
	}
	return le
}

func (le *lineEnds) at(pos int) int {
	i := sort.SearchInts(le.newlines, pos)
	if i < len(le.newlines) {
		return le.newlines[i]
	}
	return le.n
}

// escapeDepth is the number of backslashes immediately before s[i] (the escape
// depth of a quote there), or -1 when the run is longer than
// MaxEscapeBackslashes (not a quote at a supported depth).
func escapeDepth(s string, i int) int {
	j := i - 1
	for j >= 0 && s[j] == '\\' {
		j--
	}
	k := i - 1 - j
	if k > MaxEscapeBackslashes {
		return -1
	}
	return k
}

// findJSONValueClose is the v2 closer scan bounded to s[start:limit]: the value
// between start and the closing quote at escape depth n. A quote preceded by k
// backslashes closes iff k >= n and (k-n) % 2(n+1) == 0.
// quoteDepth counts the trailing one bits of an escape run (P1).
func quoteDepth(k int) int {
	d := 0
	for k%2 == 1 {
		d++
		k = (k - 1) / 2
	}
	return d
}

func findJSONValueClose(s string, start, n, limit int, shallowStop bool) (string, int, bool) {
	u := 2 * (n + 1)
	dn := 0
	if shallowStop {
		dn = quoteDepth(n)
	}
	i := start
	for i < limit {
		if n == 0 { // P4: jump to the next quote or control character
			m := findBounded(quoteOrCtrl, s, i, limit)
			if m == nil {
				return "", -1, false
			}
			i = m[0]
			if s[i] != '"' {
				return "", -1, false
			}
		} else {
			j := strings.IndexByte(s[i:limit], '"')
			if j < 0 {
				return "", -1, false
			}
			i += j
		}
		k := 0
		for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
			k++
		}
		if k >= n && (k-n)%u == 0 {
			return s[start : i-n], i + 1, true
		}
		if dn > 0 && quoteDepth(k) < dn {
			e := max(start, i-k)
			return s[start:e], e, false
		}
		i++
	}
	return "", -1, false
}

// capture reports a P1 capture: value_start, value_end, the value and the
// closer (the closing quote with its backslash run, or "" for a bare or
// unclosed value).
type capture struct {
	vs, ve int
	value  string
	closer string
}

// captureDepth0 is P1 for a value that opens with a quote at escape depth 0
// (s[pos] == '"'): one stringScan match. The P2 walks call it directly for
// their depth-0 strings; captureValue dispatches to it.
func captureDepth0(s string, pos int, lines *lineEnds, lineEnd int) capture {
	openEnd := pos + 1
	if openEnd < len(s) && s[openEnd] == '\n' { // a quote right before a newline: unclosed, empty
		return capture{openEnd, openEnd, "", ""}
	}
	sm := matchAt(stringScan, s, pos) // never nil: the body may be empty
	e := sm[1]
	if sm[2] >= 0 { // group 1: closed
		return capture{openEnd, e - 1, s[openEnd : e-1], `"`}
	}
	if lineEnd < 0 {
		if sm[4] >= 0 && s[e-1] == '\n' { // the newline met IS the line end
			lineEnd = e - 1
		} else {
			lineEnd = lines.at(pos)
		}
	}
	return capture{openEnd, lineEnd, s[openEnd:lineEnd], ""}
}

// captureValue is P1: the value starting at pos, never past the end of the
// current line. lineEnd < 0 means "not known yet" (queried only when needed).
func captureValue(s string, pos int, bare *regexp.Regexp, lines *lineEnds, lineEnd int) (capture, bool) {
	if pos >= len(s) {
		return capture{}, false
	}
	c := s[pos]
	if c == '"' || c == '\\' {
		n, openEnd := 0, pos+1
		if c == '\\' {
			if m := matchAt(quoteOpen, s, pos); m != nil { // a backslash run of at most 63 then a quote
				n, openEnd = m[3]-m[2], m[1]
			} else {
				n = -1
			}
		}
		if n == 0 {
			return captureDepth0(s, pos, lines, lineEnd), true
		}
		if n > 0 {
			if lineEnd < 0 {
				lineEnd = lines.at(pos)
			}
			value, closeEnd, ok := findJSONValueClose(s, openEnd, n, lineEnd, true)
			if ok {
				return capture{openEnd, openEnd + len(value), value, s[openEnd+len(value) : closeEnd]}, true
			}
			if closeEnd >= 0 {
				return capture{openEnd, closeEnd, value, ""}, true
			}
			return capture{openEnd, lineEnd, s[openEnd:lineEnd], ""}, true
		}
		// a backslash run longer than 63 is not an opener: a bare value is tried below (and fails on the backslash)
	}
	if c == '\'' {
		if lineEnd < 0 {
			lineEnd = lines.at(pos)
		}
		openEnd := pos + 1
		if j := strings.IndexByte(s[openEnd:lineEnd], '\''); j >= 0 {
			return capture{openEnd, openEnd + j, s[openEnd : openEnd+j], "'"}, true
		}
		return capture{openEnd, lineEnd, s[openEnd:lineEnd], ""}, true
	}
	if m := matchAt(bare, s, pos); m != nil && m[1] > m[0] { // the bare alphabets exclude the newline
		return capture{m[0], m[1], s[m[0]:m[1]], ""}, true
	}
	return capture{}, false
}

// owned is P0: the marker spans already present in a document, for overlap tests.
type owned struct {
	starts, ends []int
}

func newOwned(s string) *owned {
	o := &owned{}
	if strings.Contains(s, "[REDACTED:") {
		for _, m := range markerRe.FindAllStringIndex(s, -1) {
			o.starts = append(o.starts, m[0])
			o.ends = append(o.ends, m[1])
		}
	}
	return o
}

// overlaps is true iff [a, b) intersects a marker span.
func (o *owned) overlaps(a, b int) bool {
	if len(o.starts) == 0 {
		return false
	}
	i := sort.SearchInts(o.starts, b) // first marker starting at or after b
	return i > 0 && o.ends[i-1] > a
}

// span is one replacement (start, end, replacement, rule) a pass collected.
type span struct {
	a, b int
	rep  string
	rule string
}

// applySpans rewrites s with the spans that do not overlap an earlier one or
// an owned marker span; the hit count is the number of spans ACTUALLY applied.
func applySpans(s string, spans []span, o *owned) (string, map[string]int) {
	sort.SliceStable(spans, func(i, j int) bool {
		if spans[i].a != spans[j].a {
			return spans[i].a < spans[j].a
		}
		if spans[i].b != spans[j].b {
			return spans[i].b < spans[j].b
		}
		if spans[i].rep != spans[j].rep {
			return spans[i].rep < spans[j].rep
		}
		return spans[i].rule < spans[j].rule
	})
	var out strings.Builder
	out.Grow(len(s))
	last := 0
	applied := map[string]int{}
	testOwned := len(o.starts) > 0
	for _, sp := range spans {
		if sp.a < last || (testOwned && o.overlaps(sp.a, sp.b)) {
			continue
		}
		out.WriteString(s[last:sp.a])
		out.WriteString(sp.rep)
		last = sp.b
		applied[sp.rule]++
	}
	out.WriteString(s[last:])
	return out.String(), applied
}

func merge(counts, applied map[string]int) {
	for k, v := range applied {
		counts[k] += v
	}
}

var noOwned = &owned{}

// Redactor applies the rule set with an optional HMAC key for markers. A keyed
// Redactor produces markers an offline attacker cannot dictionary-attack; the
// key lives locally (LoadOrCreateKey) and never enters the store. A nil key
// selects plain SHA-256 — correlation still works, tolerated only where the
// document never leaves the trust domain.
type Redactor struct {
	hmacKey []byte
	ipad    []byte // HMAC inner/outer padded key blocks, derived once (P4: ~3 µs per marker on the 30 000-marker seeds)
	opad    []byte
	table   []rule // built once per Redactor (the regexes are package-level)
}

// New returns a Redactor. key may be nil (plain-hash fallback); a supplied key
// shorter than MinKeyBytes is a programming error and panics; it never silently downgrades.
func New(key []byte) *Redactor {
	if key != nil && len(key) < MinKeyBytes {
		panic(fmt.Sprintf("redact: key must be at least %d bytes or nil", MinKeyBytes))
	}
	r := &Redactor{hmacKey: key}
	if len(key) > 0 {
		k := key
		if len(k) > sha256.BlockSize {
			sum := sha256.Sum256(k)
			k = sum[:]
		}
		r.ipad = make([]byte, sha256.BlockSize)
		r.opad = make([]byte, sha256.BlockSize)
		copy(r.ipad, k)
		copy(r.opad, k)
		for i := range r.ipad {
			r.ipad[i] ^= 0x36
			r.opad[i] ^= 0x5c
		}
	}
	r.table = r.rules()
	return r
}

// LoadOrCreateKey reads the local redaction key, creating it (32 random bytes,
// mode 0600) on first use. The key is machine-local secret material: losing it
// only breaks cross-event marker correlation, never data.
func LoadOrCreateKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) >= MinKeyBytes {
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func (r *Redactor) marker(ruleID, secret string) string {
	var digest [sha256.Size]byte
	if len(r.hmacKey) > 0 {
		// HMAC-SHA256(key, secret) = H(opad || H(ipad || secret)); identical
		// bytes to crypto/hmac (TestMarkerMatchesCryptoHMAC).
		inner := sha256.New()
		inner.Write(r.ipad)
		inner.Write([]byte(secret))
		outer := sha256.New()
		outer.Write(r.opad)
		outer.Write(inner.Sum(nil))
		outer.Sum(digest[:0])
	} else {
		digest = sha256.Sum256([]byte(secret))
	}
	return "[REDACTED:" + ruleID + ":" + hex.EncodeToString(digest[:4]) + "]"
}

func (r *Redactor) eligible(value string, floor int) bool {
	return runeLen(value) >= floor && !exempt(value) && !marked(value)
}

// ------------------------------------------------------------------ P3 PEM block

// pemApply is P3: from each BEGIN line, the block ends at its END line when
// no second BEGIN comes first (blank lines inside are allowed); otherwise the
// block is truncated and ends at the first blank line after the header block,
// else at the next BEGIN, else at the end of the document. Group-0 semantics:
// the whole block is replaced, ownership is not tested.
func (r *Redactor) pemApply(s string, counts map[string]int, _ *owned) (string, error) {
	var spans []span
	begin := scanPemBegin.scanner(s)
	pos := 0
	for pos < len(s) {
		b := begin.search(pos)
		if b == nil {
			break
		}
		limit := len(s)
		if b2 := begin.search(b[1]); b2 != nil {
			limit = b2[0]
		}
		var end int
		if e := findBounded(pemEnd, s, b[1], limit); e != nil {
			end = e[1]
		} else {
			body := b[1]
			if hm := matchAt(pemHeaders, s[:limit], body); hm != nil {
				body = hm[1] // the header/body separator is not the truncation bound
			}
			if blank := findBounded(pemBlank, s, body, limit); blank != nil {
				end = blank[0]
			} else {
				end = limit
			}
		}
		block := s[b[0]:end]
		if !exempt(block) {
			spans = append(spans, span{b[0], end, r.marker("pem-block", block), "pem-block"})
		}
		pos = end
	}
	out, applied := applySpans(s, spans, noOwned)
	merge(counts, applied)
	return out, nil
}

// ------------------------------------------------------------------ P1-based apply passes

type applyFunc func(s string, counts map[string]int, o *owned) (string, error)

// valueApply is the P1 pass of a prefix row: each prefix match captures the
// value after it (captureValue); search is re.search(s, pos) of the prefix.
func (r *Redactor) valueApply(ruleID string, floor int, bare *regexp.Regexp, scanner func(string) func(int) []int, bareKept func(string, []int, int, int, string) bool) applyFunc {
	return func(s string, counts map[string]int, o *owned) (string, error) {
		var spans []span
		lines := newLineEnds(s)
		search := scanner(s)
		pos := 0
		for pos < len(s) {
			m := search(pos)
			if m == nil {
				break
			}
			cap, ok := captureValue(s, m[1], bare, lines, -1)
			if !ok {
				pos = m[1]
				continue
			}
			if r.eligible(cap.value, floor) && !o.overlaps(m[0], cap.ve) {
				isBare := !strings.ContainsRune("\"'\\", rune(s[m[1]]))
				if bareKept == nil || !isBare || !bareKept(s, m, cap.vs, cap.ve, cap.value) {
					spans = append(spans, span{cap.vs, cap.ve, r.marker(ruleID, cap.value), ruleID})
				}
			}
			pos = max(cap.ve, m[1])
		}
		out, applied := applySpans(s, spans, o)
		merge(counts, applied)
		return out, nil
	}
}

// escapedLineBreak distinguishes escaped newlines from shell continuations.
func escapedLineBreak(r int) bool {
	for r%2 == 0 {
		r /= 2
	}
	return ((r-1)/2)%2 == 0
}

func argumentQuote(s string, i int) bool {
	if i == 0 {
		return true
	}
	_, w := utf8.DecodeLastRuneInString(s[:i])
	if isSpaceAt(s, i-w) {
		return true
	}
	j := i
	count := 0
	for j > 0 && count < 64 {
		_, w = utf8.DecodeLastRuneInString(s[:j])
		if isSpaceAt(s, j-w) {
			break
		}
		j -= w
		count++
	}
	if j > 0 {
		_, w = utf8.DecodeLastRuneInString(s[:j])
		if !isSpaceAt(s, j-w) {
			return false
		}
	}
	return s[j] == '-'
}
func regionIsCommand(s string, start, end int) bool {
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	// Anchored matching is bounded by a command word, not a new document scan.
	m := matchAt(scanMysqlWord.anchored, s[:end], start)
	return m != nil && pyBoundaryAt(s, start) && pyBoundaryAt(s, m[1])
}
func quotePartner(s string, start, limit int, qc byte, k int) int {
	for j := start; j < limit; {
		off := strings.IndexByte(s[j:limit], qc)
		if off < 0 {
			break
		}
		j += off
		b := j
		for b > start && s[b-1] == '\\' && j-b <= MaxEscapeBackslashes {
			b--
		}
		if j-b == k {
			return j
		}
		j++
	}
	return -1
}

// mysqlApply scans only this command, skipping balanced argument quotes.
// Failed partner searches are memoized by quote/run/line to preserve P4.
func (r *Redactor) mysqlApply(s string, counts map[string]int, o *owned) (string, error) {
	var spans []span
	lines := newLineEnds(s)
	words := scanMysqlWord.scanner(s)
	unmatched := map[[3]int]bool{}
	pos := 0
	for pos < len(s) {
		m := words.search(pos)
		if m == nil {
			break
		}
		lineEnd := lines.at(m[1])
		limit := min(len(s), lineEnd+3)
		q, pend, stop := m[1], -1, lineEnd
		for {
			h := findBounded(mysqlScan, s, q, limit)
			if h == nil || h[0] > lineEnd {
				break
			}
			c := s[h[0]]
			last := s[h[1]-1]
			if last == '"' || last == '\'' {
				if (h[0] > 0 && s[h[0]-1] == '\\') || !argumentQuote(s, h[0]) {
					q = h[1]
					continue
				}
				if strings.HasPrefix(s[h[1]:], "-p") {
					pend = h[1] + 2
					break
				}
				k := h[1] - 1 - h[0]
				key := [3]int{int(last), k, lineEnd}
				if (k == 0 || k == 1 || k == 3 || k == 7 || k == 15) && !unmatched[key] {
					partner := quotePartner(s, h[1], lineEnd, last, k)
					if partner >= 0 && !regionIsCommand(s, h[1], partner) {
						q = partner + 1
						continue
					}
					if partner < 0 {
						unmatched[key] = true
					}
				}
				q = h[1]
				continue
			}
			if c == '\\' {
				j := h[0]
				for j > 0 && s[j-1] == '\\' && h[0]-j < MaxEscapeBackslashes {
					j--
				}
				if escapedLineBreak(h[0] + 1 - j) {
					stop = h[0]
					break
				}
				q = h[1]
				continue
			}
			if strings.ContainsRune(";|&`", rune(c)) {
				stop = h[0]
				break
			}
			pend = h[1]
			break
		}
		if pend < 0 {
			pos = max(stop, m[1])
			continue
		}
		known := -1
		if pend <= lineEnd {
			known = lineEnd
		}
		cap, ok := captureValue(s, pend, bareRe, lines, known)
		if !ok || cap.vs != pend || strings.ContainsRune("-;|&`", rune(cap.value[0])) {
			pos = pend
			continue
		}
		if r.eligible(cap.value, 1) && !o.overlaps(m[0], cap.ve) {
			spans = append(spans, span{cap.vs, cap.ve, r.marker("mysql-p-flag", cap.value), "mysql-p-flag"})
		}
		pos = max(cap.ve, pend)
	}
	out, applied := applySpans(s, spans, o)
	merge(counts, applied)
	return out, nil
}

// urlCredentialsApply scans url-credentials from each `://` (urlCredentialsRe
// is the specification; the match it finds is unique per `://`).
func (r *Redactor) urlCredentialsApply(s string, counts map[string]int, o *owned) (string, error) {
	var spans []span
	locate := scanURLLocate.scanner(s)
	pos := 0
	for pos < len(s) {
		lm := locate.search(pos)
		if lm == nil {
			break
		}
		c := lm[0]
		w := c
		for w > 0 && c-w < MaxURLScheme && isURLSchemeChar(s[w-1]) {
			w--
		}
		start := -1
		for p := w; p < c; p++ { // leftmost letter of the (bounded) scheme run
			if isASCIILetter(s[p]) {
				start = p
				break
			}
		}
		pos = lm[1]
		if start < 0 {
			continue
		}
		um := findBounded(urlUserinfoEnd, s, lm[1], len(s))
		if um == nil || s[um[0]] != ':' {
			continue
		}
		ps := um[1]
		pm := findBounded(urlPasswordEnd, s, ps, len(s))
		if pm == nil || s[pm[0]] != '@' || pm[0] == ps {
			continue
		}
		pe := pm[0]
		secret := s[ps:pe]
		if !exempt(secret) && !marked(secret) && !o.overlaps(start, pm[1]) {
			spans = append(spans, span{ps, pe, r.marker("url-credentials", secret), "url-credentials"})
		}
		pos = pm[1]
	}
	out, applied := applySpans(s, spans, o)
	merge(counts, applied)
	return out, nil
}

// jwtApply (group 0) scans from each word-boundary `eyJ`; after a failed
// attempt the base64url run containing the start is skipped.
func (r *Redactor) jwtApply(s string, counts map[string]int, _ *owned) (string, error) {
	var spans []span
	sc := scanJwt.scanner(s)
	pos := 0
	for pos < len(s) {
		c, which := sc.next(pos)
		if c < 0 {
			break
		}
		if m := sc.try(c); m != nil {
			whole := s[m[0]:m[1]]
			if !exempt(whole) {
				spans = append(spans, span{m[0], m[1], r.marker("jwt", whole), "jwt"})
			}
			pos = m[1]
			continue
		}
		sc.skipCandidate(which)
		if run := matchAt(b64URLRun, s, c); run != nil {
			pos = run[1] // P4: every later start inside the run fails the same way
		} else {
			pos = c + 1
		}
	}
	out, applied := applySpans(s, spans, noOwned)
	merge(counts, applied)
	return out, nil
}

func (r *Redactor) jsonSecretFieldApply(s string, counts map[string]int, o *owned) (string, error) {
	var spans []span
	lines := newLineEnds(s)
	locate := scanJSONLocate.scanner(s)
	pos := 0
	for pos < len(s) {
		m := locate.search(pos)
		if m == nil {
			break
		}
		depth := escapeDepth(s, m[0])
		if depth < 0 {
			pos = m[1]
			continue
		}
		if matchAt(quoteOpen, s, m[1]) != nil {
			cap, ok := captureValue(s, m[1], bareRe, lines, -1)
			if !ok {
				pos = m[1]
				continue
			}
			if r.eligible(cap.value, Floor) && !o.overlaps(m[0], cap.ve) {
				spans = append(spans, span{cap.vs, cap.ve, r.marker("json-secret-field", cap.value), "json-secret-field"})
			}
			pos = max(cap.ve, m[1])
			continue
		}
		if nm := matchAt(numberRe, s, m[1]); nm != nil && nm[1]-nm[0] >= Floor && !o.overlaps(m[0], nm[1]) {
			q := strings.Repeat(`\`, depth) + `"` // the key's escape depth, so the text stays JSON at that depth
			num := s[nm[0]:nm[1]]
			spans = append(spans, span{nm[0], nm[1], q + r.marker("json-secret-field", num) + q, "json-secret-field"})
			pos = nm[1]
			continue
		}
		pos = m[1]
	}
	out, applied := applySpans(s, spans, o)
	merge(counts, applied)
	return out, nil
}

// ------------------------------------------------------------------ P2 schema walk (text form)

type p2state struct {
	r         *Redactor
	s         string
	spans     []span
	skipCache map[int]int // start -> end of containers already skipped
	lines     *lineEnds
}

func (r *Redactor) jsonSchemaDefaultApply(s string, counts map[string]int, o *owned) (string, error) {
	st := &p2state{r: r, s: s, skipCache: map[int]int{}, lines: newLineEnds(s)}
	var openEnds []int // extents of the located secret-named objects that enclose pos
	locate := scanJSONSchemaObj.scanner(s)
	pos := 0
	for pos < len(s) {
		m := locate.search(pos)
		if m == nil {
			break
		}
		depth := escapeDepth(s, m[0])
		if depth < 0 {
			pos = m[1]
			continue
		}
		for len(openEnds) > 0 && openEnds[len(openEnds)-1] <= m[0] {
			openEnds = openEnds[:len(openEnds)-1]
		}
		if len(openEnds) >= MaxNesting {
			return "", fmt.Errorf("%w: more than %d enclosing secret-named objects", ErrDepth, MaxNesting)
		}
		end := st.collectSchemaSpans(m[1], depth)
		openEnds = append(openEnds, end)
		pos = m[1] // continue INSIDE the object: nested secret-named properties are located too
	}
	out, applied := applySpans(s, st.spans, o)
	merge(counts, applied)
	return out, nil
}

// collectSchemaSpans walks the direct children of one object body at escape
// depth n from pos (after '{'); returns the index just past the closing
// brace, or len(s) at end of input or at the first malformed token.
func (st *p2state) collectSchemaSpans(pos, n int) int {
	s := st.s
	i := pos
	for {
		if i < len(s) && isSpaceAt(s, i) {
			i = matchAt(wsRe, s, i)[1]
		}
		if i >= len(s) {
			return len(s)
		}
		if s[i] == '}' {
			return i + 1
		}
		if s[i] == ',' {
			i++
			continue
		}
		var key string
		kend := -1
		if n == 0 && s[i] == '"' {
			if m := matchAt(stringScan, s, i); m != nil && m[2] >= 0 { // a closed plain key in one match
				key, kend = s[i+1:m[1]-1], m[1]
			}
		}
		if kend < 0 {
			key, kend = st.keyAtDepth(i, n)
			if kend < 0 {
				return len(s)
			}
		}
		cm := matchAt(colonRe, s, kend)
		if cm == nil || cm[1] >= len(s) {
			return len(s)
		}
		vpos := cm[1]
		lkey := pyLower(key)
		var nxt int
		switch {
		case schemaScalarKeys[lkey] && matchAt(quoteOpen, s, vpos) != nil:
			cap, ok := captureValue(s, vpos, bareRe, st.lines, -1)
			if !ok {
				return len(s)
			}
			if st.r.eligible(cap.value, Floor) {
				st.spans = append(st.spans, span{cap.vs, cap.ve, st.r.marker("json-schema-default", cap.value), "json-schema-default"})
			}
			nxt = cap.ve + len(cap.closer)
		case schemaListKeys[lkey] && s[vpos] == '[':
			nxt = st.collectListSpans(vpos+1, n)
		case !safeObjectKeys[lkey] && matchAt(quoteOpen, s, vpos) != nil:
			cap, ok := captureValue(s, vpos, bareRe, st.lines, -1)
			if !ok {
				return len(s)
			}
			if st.r.eligible(cap.value, Floor) {
				st.spans = append(st.spans, span{cap.vs, cap.ve, st.r.marker("json-secret-object", cap.value), "json-secret-object"})
			}
			nxt = cap.ve + len(cap.closer)
		default:
			nxt = st.skipValue(vpos)
		}
		if nxt <= i {
			return len(s)
		}
		i = nxt
	}
}

// keyAtDepth reads a quoted key at escape depth n starting at i; kend < 0 on
// a malformed key.
func (st *p2state) keyAtDepth(i, n int) (string, int) {
	km := matchAt(quoteOpen, st.s, i)
	if km == nil || km[3]-km[2] != n {
		return "", -1
	}
	key, kend, ok := findJSONValueClose(st.s, km[1], n, st.lines.at(km[1]), false)
	if !ok {
		return "", -1
	}
	return key, kend
}

// collectListSpans collects the string elements of a list at escape depth n;
// returns the index after ']' (or -1 on a malformed element).
func (st *p2state) collectListSpans(pos, n int) int {
	s := st.s
	j := pos
	for {
		if j < len(s) && (s[j] == ',' || isSpaceAt(s, j)) {
			nj := j + 1
			if s[j] >= utf8.RuneSelf { // a multi-byte separator advances by its width
				_, w := utf8.DecodeRuneInString(s[j:])
				nj = j + w
			}
			if nj < len(s) && (s[nj] == ',' || isSpaceAt(s, nj)) {
				nj = matchAt(wsCommaRe, s, j)[1]
			}
			j = nj
		}
		if j >= len(s) {
			return -1
		}
		if s[j] == ']' {
			return j + 1
		}
		var nxt int
		if n == 0 && s[j] == '"' { // a depth-0 string: the one-match capture directly
			cap := captureDepth0(s, j, st.lines, -1)
			if st.r.eligible(cap.value, Floor) {
				st.spans = append(st.spans, span{cap.vs, cap.ve, st.r.marker("json-schema-default", cap.value), "json-schema-default"})
			}
			nxt = cap.ve + len(cap.closer)
		} else if matchAt(quoteOpen, s, j) != nil {
			cap, ok := captureValue(s, j, bareRe, st.lines, -1)
			if !ok {
				return -1
			}
			if st.r.eligible(cap.value, Floor) {
				st.spans = append(st.spans, span{cap.vs, cap.ve, st.r.marker("json-schema-default", cap.value), "json-schema-default"})
			}
			nxt = cap.ve + len(cap.closer)
		} else {
			nxt = st.skipValue(j)
		}
		if nxt <= j {
			return -1
		}
		j = nxt
	}
}

// skipValue returns the index just past the JSON value at pos (a string at
// any escape depth, object, array or scalar); -1 when nothing can be consumed.
// Container extents are memoised per document.
func (st *p2state) skipValue(pos int) int {
	s := st.s
	if pos >= len(s) {
		return -1
	}
	if matchAt(quoteOpen, s, pos) != nil {
		cap, ok := captureValue(s, pos, bareRe, st.lines, -1)
		if !ok {
			return -1
		}
		return cap.ve + len(cap.closer)
	}
	if s[pos] == '{' || s[pos] == '[' {
		if hit, ok := st.skipCache[pos]; ok {
			return hit
		}
		var starts []int
		i := pos
		for i < len(s) {
			tm := findBounded(containerToken, s, i, len(s))
			if tm == nil {
				break
			}
			i = tm[0]
			if tm[1]-i > 1 { // a complete depth-0 string: skipped as one token
				i = tm[1]
				continue
			}
			c := s[i]
			switch {
			case c == '\\': // a backslash run: a quote opener only when a quote follows it
				j := i + 1
				for j < len(s) && s[j] == '\\' {
					j++
				}
				if j < len(s) && s[j] == '"' && j-i <= MaxEscapeBackslashes {
					if cap, ok := captureValue(s, i, bareRe, st.lines, -1); ok {
						i = cap.ve + len(cap.closer)
					} else {
						i++
					}
				} else {
					i = j
				}
				continue
			case c == '"':
				if cap, ok := captureValue(s, i, bareRe, st.lines, -1); ok {
					i = cap.ve + len(cap.closer)
				} else {
					i++
				}
				continue
			case c == '{' || c == '[':
				starts = append(starts, i)
			case c == '}' || c == ']':
				if len(starts) == 0 { // unreachable: the first token is the opener at pos
					i++
					continue
				}
				start := starts[len(starts)-1]
				starts = starts[:len(starts)-1]
				st.skipCache[start] = i + 1
				if len(starts) == 0 {
					return i + 1
				}
			}
			i++
		}
		for _, start := range starts {
			st.skipCache[start] = len(s)
		}
		return len(s)
	}
	if m := matchAt(scalarRe, s, pos); m != nil {
		return m[1]
	}
	return -1
}

// ------------------------------------------------------------------ rule table

// The regex rows of the table, each with its literal locator (locate.go).
// The bodies are the table's patterns without their leading/trailing `\b`
// (evaluated in code under Python's boundary); a trailing-`\b` row wraps its
// final variable run in group 1 so the backtracking search knows the
// shortest admissible end.
var (
	scanAwsAccessKey          = newCandidateScan(candidateSpec{body: `(?:AKIA|ASIA)([0-9A-Z]{16})`, needles: []string{"AKIA", "ASIA"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 16})
	scanOpenaiKey             = newCandidateScan(candidateSpec{body: `sk-([A-Za-z0-9_-]{20,})`, needles: []string{"sk-"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 20})
	scanGithubToken           = newCandidateScan(candidateSpec{body: `(?:ghp|gho|ghu|ghs|ghr)_([A-Za-z0-9]{36,})`, needles: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 36})
	scanGithubFineGrainedPat  = newCandidateScan(candidateSpec{body: `github_pat_([A-Za-z0-9_]{20,})`, needles: []string{"github_pat_"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 20})
	scanGitlabToken           = newCandidateScan(candidateSpec{body: `glpat-([A-Za-z0-9_-]{20,})`, needles: []string{"glpat-"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 20})
	scanLiaisonLetterboxToken = newCandidateScan(candidateSpec{body: `lbx1_[A-Za-z0-9_-]{20,}`, needles: []string{"lbx1_"}, wordStart: true}) // row 8: greedy form of the lookahead pattern, no trailing boundary
	scanSlackToken            = newCandidateScan(candidateSpec{body: `xox[baprs]-([A-Za-z0-9-]{10,})`, needles: []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 10})
	scanGoogleAPIKey          = newCandidateScan(candidateSpec{body: `AIza([0-9A-Za-z_-]{35})`, needles: []string{"AIza"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 35})
	scanStripeKey             = newCandidateScan(candidateSpec{body: `[sr]k_(?:live|test)_([A-Za-z0-9]{16,})`, needles: []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 16})
	scanHuggingfaceToken      = newCandidateScan(candidateSpec{body: `hf_([A-Za-z0-9]{30,})`, needles: []string{"hf_"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 30})
	scanNpmToken              = newCandidateScan(candidateSpec{body: `npm_([A-Za-z0-9]{36,})`, needles: []string{"npm_"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 36})
	scanPypiToken             = newCandidateScan(candidateSpec{body: `pypi-([A-Za-z0-9_-]{50,})`, needles: []string{"pypi-"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 50})
	scanTailscaleKey          = newCandidateScan(candidateSpec{body: `tskey-([A-Za-z0-9_-]{20,})`, needles: []string{"tskey-"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 20})
	scanAgeSecretKey          = newCandidateScan(candidateSpec{body: `AGE-SECRET-KEY-1([A-Z0-9]{58})`, needles: []string{"AGE-SECRET-KEY-1"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 58})
	scanGrafanaToken          = newCandidateScan(candidateSpec{body: `glsa_[A-Za-z0-9]{32}(_[0-9a-f]{8})?`, needles: []string{"glsa_"}, wordStart: true, wordEnd: true,
		ends: func(s string, m []int) []int { // with the optional suffix, then without
			if m[2] >= 0 {
				return []int{m[1], m[2]}
			}
			return []int{m[1]}
		}})
	scanSignedURLParam  = newCandidateScan(candidateSpec{body: `(?i)((?:[?&#]|&amp;?|&#0*38;?|&#x0*26;?|\\u0026)(?:X-Amz-Signature|X-Amz-Credential|X-Amz-Security-Token|X-Goog-Signature|signature|sig|code|pwd|auth|key)=)([^&` + wsChars + `"'\\<>]+)`, needles: []string{"?", "&", "#", `\`}, ci: true})
	scanBearerHeader    = newCandidateScan(candidateSpec{body: `(?i)(authorization` + ws + `*[:=]` + ws + `*"?bearer` + ws + `+)([A-Za-z0-9._~+/-]{8,}=*)`, needles: []string{"authorization"}, ci: true, wordStart: true})
	scanBareBearerToken = newCandidateScan(candidateSpec{body: `(?i)(?:bearer[ \t]+([A-Za-z0-9._~+/-]{16,}=*)|token[ \t]+([A-Za-z0-9._~+/-]{20,}=*))`, needles: []string{"bearer", "token"}, ci: true, wordStart: true})
	scanHeaderPrefix    = newCandidateScan(candidateSpec{body: `(?im)` + headerNames + ws + `*:[ \t]*(?:(?:basic|bearer|token|digest)[ \t]+)?`, needles: headerNeedles, ci: true, wordStart: true})
	// Locators of the apply passes.
	scanPemBegin  = newCandidateScan(candidateSpec{body: `-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`, needles: []string{"-----BEGIN "}})
	scanURLLocate = newCandidateScan(candidateSpec{body: `:(?:\\?/){2}`, needles: []string{":"}})
	scanJwt       = newCandidateScan(candidateSpec{body: `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.([A-Za-z0-9_-]{5,})`, needles: []string{"eyJ"}, wordStart: true, wordEnd: true, tailGroup: 1, tailMin: 5})
	scanMysqlWord = newCandidateScan(candidateSpec{body: `(?im)(?:mysqldump|mysqladmin|mysql|mariadb)`, needles: []string{"mysql", "mariadb"}, ci: true, wordStart: true, wordEnd: true}) // longest alternatives first: one candidate end
	// Prefix rows: the match starts before the family word; the tail is the
	// maximal extent of the pattern after the word.
	scanAssignPrefix = newPrefixScan(
		`(?im)(?:^|[^A-Za-z0-9_.-])(?:(?:export|const|let|var|local|readonly|set)`+ws+`+)?[A-Za-z0-9_.]*`+envFamily+`[A-Za-z0-9_]*[ \t]*[=:][ \t]*`,
		runTail{regexp.MustCompile(`^[ \t]*[=:][ \t]*`)}, assignStart{}, envFamilyNeedles...)
	scanJSONLocate    = newPrefixScan(`(?i)("[A-Za-z0-9_-]*`+keyFamily+esc+`"`+ws+`*:`+ws+`*)`, newRegexTail(esc+`"`+ws+`*:`+ws+`*`), jsonKeyStart{}, keyFamilyNeedles...)
	scanJSONSchemaObj = newPrefixScan(`(?i)"[A-Za-z0-9_-]*`+keyFamily+esc+`"`+ws+`*:`+ws+`*\{`, newRegexTail(esc+`"`+ws+`*:`+ws+`*\{`), jsonKeyStart{}, keyFamilyNeedles...)
)

// The literal needles of the `(?i)` families, lowercase: every match of the
// pattern contains one of them (`api[_-]?key` is three needles,
// `credentials?` is `credential`).
var (
	envFamilyNeedles = []string{"secret", "token", "password", "passwd", "api_key", "apikey", "private_key", "access_key", "credentials", "credential"}
	keyFamilyNeedles = []string{"api_key", "api-key", "apikey", "secret", "token", "password", "passwd", "access_key", "access-key", "accesskey",
		"private_key", "private-key", "privatekey", "credentials", "credential", "authorization", "auth", "cookie"}
	headerNeedles = []string{"proxy-authorization", "authorization", "set-cookie", "cookie", "x-api-key", "api-key", "x-auth-token",
		"x-goog-api-key", "x-amz-security-token", "private-token", "x-csrf-token", "x-xsrf-token"}
)

type rule struct {
	id            string
	scan          *candidateScan // a regex row: the table's regex and its locator
	group         int            // the capture group holding the secret; 0 redacts the whole match
	fallbackGroup int            // alternative capture when group did not participate
	floor         int
	apply         applyFunc
}

// rules is the table in contract order (§Order is law): shapes (rows 1–17) →
// signed-url-param → bearer-header → header-credential → json-secret-field →
// json-schema-default + json-secret-object (one P2 scan) → url-credentials →
// cli-flag-secret → mysql-p-flag → env-secret-assignment → bare-bearer-token.
func (r *Redactor) rules() []rule {
	return []rule{
		{id: "pem-block", apply: r.pemApply},
		{id: "jwt", apply: r.jwtApply},
		{id: "aws-access-key", scan: scanAwsAccessKey},
		{id: "openai-key", scan: scanOpenaiKey},
		{id: "github-token", scan: scanGithubToken},
		{id: "github-fine-grained-pat", scan: scanGithubFineGrainedPat},
		{id: "gitlab-token", scan: scanGitlabToken},
		{id: "liaison-letterbox-token", scan: scanLiaisonLetterboxToken},
		{id: "slack-token", scan: scanSlackToken},
		{id: "google-api-key", scan: scanGoogleAPIKey},
		{id: "stripe-key", scan: scanStripeKey},
		{id: "huggingface-token", scan: scanHuggingfaceToken},
		{id: "npm-token", scan: scanNpmToken},
		{id: "pypi-token", scan: scanPypiToken},
		{id: "tailscale-key", scan: scanTailscaleKey},
		{id: "age-secret-key", scan: scanAgeSecretKey},
		{id: "grafana-token", scan: scanGrafanaToken},
		{id: "signed-url-param", scan: scanSignedURLParam, group: 2, floor: Floor},
		{id: "bearer-header", scan: scanBearerHeader, group: 2},
		{id: "header-credential", apply: r.valueApply("header-credential", Floor, bareLineRe, func(s string) func(int) []int { return scanHeaderPrefix.scanner(s).search }, func(_ string, _ []int, _, _ int, value string) bool { return headerProse.MatchString(value) })},
		{id: "json-secret-field", apply: r.jsonSecretFieldApply},
		{id: "json-schema-default", apply: r.jsonSchemaDefaultApply}, // also emits json-secret-object spans (P2)
		{id: "url-credentials", apply: r.urlCredentialsApply},
		{id: "cli-flag-secret", apply: r.valueApply("cli-flag-secret", Floor, bareRe, cliPrefixFinder, nil)},
		{id: "mysql-p-flag", apply: r.mysqlApply},
		{id: "env-secret-assignment", apply: r.valueApply("env-secret-assignment", Floor, bareRe, assignPrefixFinder, assignBareKept)},
		{id: "bare-bearer-token", scan: scanBareBearerToken, group: 1, fallbackGroup: 2},
	}
}

// ------------------------------------------------------------------ entry points

// String redacts one plain-text document and reports per-rule hit counts. The
// error is ErrDepth (fail-closed): the caller must not write the document.
func (r *Redactor) String(s string) (string, []Hit, error) {
	if runeLen(s) < MinMatchChars { // no rule can change a shorter document
		return s, nil, nil
	}
	counts := map[string]int{}
	// P0: markers present before this rule runs. The index depends only on
	// the text, so it is rebuilt only after a rule changed the text.
	var o *owned
	ownedOf := ""
	for _, ru := range r.table {
		if o == nil || s != ownedOf {
			o = newOwned(s)
			ownedOf = s
		}
		if ru.apply != nil {
			var err error
			s, err = ru.apply(s, counts, o)
			if err != nil {
				return "", nil, err
			}
			continue
		}
		s = r.applyRegex(ru, s, counts, o)
	}
	return s, hitsFromCounts(counts), nil
}

// applyRegex is the re.sub pass of a regex row (group 0 or a capture group).
func (r *Redactor) applyRegex(ru rule, s string, counts map[string]int, o *owned) string {
	locs := ru.scan.findAll(s)
	if len(locs) == 0 {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	last := 0
	for _, loc := range locs {
		if ru.group > 0 {
			gs, ge := loc[2*ru.group], loc[2*ru.group+1]
			if gs < 0 && ru.fallbackGroup > 0 {
				gs, ge = loc[2*ru.fallbackGroup], loc[2*ru.fallbackGroup+1]
			}
			if gs < 0 {
				continue
			}
			secret := s[gs:ge]
			if runeLen(secret) < ru.floor || exempt(secret) || marked(secret) || o.overlaps(loc[0], loc[1]) {
				continue
			}
			counts[ru.id]++
			out.WriteString(s[last:gs])
			out.WriteString(r.marker(ru.id, secret))
			last = ge
			continue
		}
		whole := s[loc[0]:loc[1]]
		if exempt(whole) {
			continue
		}
		counts[ru.id]++
		out.WriteString(s[last:loc[0]])
		out.WriteString(r.marker(ru.id, whole))
		last = loc[1]
	}
	out.WriteString(s[last:])
	return out.String()
}

// JSON redacts every string value AND every string key (recursively) in a JSON
// document — a secret used as a map key must not reach the store either.
// Numbers are decoded with UseNumber so large integers survive the round-trip
// bit-exact. A document that fails to parse is treated as one opaque string.
// The error is ErrDepth (fail-closed).
func (r *Redactor) JSON(raw json.RawMessage) (json.RawMessage, []Hit, error) {
	if len(raw) == 0 {
		return raw, nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		s, hits, err := r.String(string(raw))
		return json.RawMessage(s), hits, err
	}
	// Preserve invalid trailing content while redacting it as text.
	if _, terr := dec.Token(); terr != io.EOF {
		s, hits, err := r.String(string(raw))
		return json.RawMessage(s), hits, err
	}
	counts := map[string]int{}
	v, err := r.walk(v, counts, false, 1)
	if err != nil {
		return nil, nil, err
	}
	if len(counts) == 0 {
		return raw, nil, nil // untouched input stays byte-identical
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil, nil, fmt.Errorf("redact: marshal redacted document: %w", err) // unreachable for walk's output; fail closed anyway
	}
	return out, hitsFromCounts(counts), nil
}

// Value redacts an already-decoded JSON value (the structured walk of the
// contract: maps, slices, strings, json.Number, bool, nil); the caller owns
// the decoding and the marshaling.
func (r *Redactor) Value(v any) (any, []Hit, error) {
	counts := map[string]int{}
	out, err := r.walk(v, counts, false, 1)
	if err != nil {
		return nil, nil, err
	}
	return out, hitsFromCounts(counts), nil
}

func (r *Redactor) stringInto(v string, counts map[string]int) (string, error) {
	s, hits, err := r.String(v)
	if err != nil {
		return "", err
	}
	for _, h := range hits {
		counts[h.Rule] += h.Count
	}
	return s, nil
}

// whole redacts a value under a secret-named key (or a schema child) whole as
// `rule` when eligible, else through the string rules.
func (r *Redactor) whole(val, ruleID string, counts map[string]int) (string, error) {
	if r.eligible(val, Floor) {
		counts[ruleID]++
		return r.marker(ruleID, val), nil
	}
	return r.stringInto(val, counts)
}

// walk is the structured walk (§Contract): depth counts the containers on the
// path, root = 1; underSecretKey is true for the direct children of a map
// under a secret-named key.
func (r *Redactor) walk(v any, counts map[string]int, underSecretKey bool, depth int) (any, error) {
	switch t := v.(type) {
	case string:
		return r.stringInto(t, counts)
	case map[string]any:
		if depth > MaxNesting {
			return nil, fmt.Errorf("%w: container nesting deeper than %d", ErrDepth, MaxNesting)
		}
		out := make(map[string]any, len(t))
		for k, val := range t {
			nk, err := r.stringInto(k, counts)
			if err != nil {
				return nil, err
			}
			secretKey := secretKeyRe.MatchString(k)
			lk := pyLower(k)
			if sv, ok := val.(string); ok && secretKey {
				w, err := r.whole(sv, "json-secret-field", counts)
				if err != nil {
					return nil, err
				}
				out[nk] = w
				continue
			}
			if num, ok := val.(json.Number); ok && secretKey {
				if text := pyNumberText(string(num)); runeLen(text) >= Floor { // a number under a secret-named key, 8+ characters of its json.dumps text: redacted whole
					counts["json-secret-field"]++
					out[nk] = r.marker("json-secret-field", text)
					continue
				}
			}
			if sv, ok := val.(string); ok && underSecretKey && schemaScalarKeys[lk] {
				w, err := r.whole(sv, "json-schema-default", counts)
				if err != nil {
					return nil, err
				}
				out[nk] = w
				continue
			}
			if list, ok := val.([]any); ok && underSecretKey && schemaListKeys[lk] {
				if depth+1 > MaxNesting { // the list is a container level of its own
					return nil, fmt.Errorf("%w: container nesting deeper than %d", ErrDepth, MaxNesting)
				}
				res := make([]any, len(list))
				for i, x := range list {
					if xs, ok := x.(string); ok {
						w, err := r.whole(xs, "json-schema-default", counts)
						if err != nil {
							return nil, err
						}
						res[i] = w
						continue
					}
					w, err := r.walk(x, counts, false, depth+2)
					if err != nil {
						return nil, err
					}
					res[i] = w
				}
				out[nk] = res
				continue
			}
			if sv, ok := val.(string); ok && underSecretKey && !safeObjectKeys[lk] {
				w, err := r.whole(sv, "json-secret-object", counts)
				if err != nil {
					return nil, err
				}
				out[nk] = w
				continue
			}
			_, isMap := val.(map[string]any)
			w, err := r.walk(val, counts, secretKey && isMap, depth+1)
			if err != nil {
				return nil, err
			}
			out[nk] = w
		}
		return out, nil
	case []any:
		if depth > MaxNesting {
			return nil, fmt.Errorf("%w: container nesting deeper than %d", ErrDepth, MaxNesting)
		}
		for i, val := range t {
			w, err := r.walk(val, counts, false, depth+1)
			if err != nil {
				return nil, err
			}
			t[i] = w
		}
		return t, nil
	default:
		return v, nil // includes json.Number, bool, nil — pass through bit-exact
	}
}

// pyLower is Python's str.lower() where it can reach an ASCII policy word —
// the only use this package makes of it (placeholder words and prefixes,
// schema and safe-object keys): U+0130 İ lowercases to
// "i\u0307" (two code points — Go maps it to a bare i, which made `requİred`
// exempt and `tİtle` a safe key); every other code point takes Go's simple
// mapping. Contextual casing (Final_Sigma) and the Unicode-version gap of
// newer letters never produce ASCII, so they cannot change a comparison
func pyLower(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToLower(s)
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0x130 {
			b.WriteString("i\u0307")
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// pyNumberText is json.dumps(json.loads(literal)) for a JSON number literal
// (the reference module's structured walk hashes and measures that text, not
// the literal): an integer literal stays itself (`-0` becomes `0`); any other
// literal is a float and renders as Python's repr — the shortest round-trip
// digits, fixed notation with a `.0` for whole values when the decimal
// exponent is in [-4, 16), else `d.ddde+XX` with a signed two-digit minimum
// exponent.
func pyNumberText(lit string) string {
	if !strings.ContainsAny(lit, ".eE") {
		if lit == "-0" {
			return "0"
		}
		return lit
	}
	f, err := strconv.ParseFloat(lit, 64)
	if math.IsInf(f, 0) {
		// An overflowing decimal exponent is valid JSON: Python decodes it to
		// ±inf and json.dumps renders Infinity / -Infinity.
		if f < 0 {
			return "-Infinity"
		}
		return "Infinity"
	}
	if err != nil || math.IsNaN(f) {
		return lit // unreachable for a decoded JSON number; keep the literal
	}
	return pyFloatRepr(f)
}

func pyFloatRepr(f float64) string {
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	// shortest round-trip digits: d.ddd...e±XX
	e := strconv.FormatFloat(f, 'e', -1, 64)
	neg := strings.HasPrefix(e, "-")
	if neg {
		e = e[1:]
	}
	mant, expStr, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mant, ".", "", 1)
	sign := ""
	if neg {
		sign = "-"
	}
	// decimal point position relative to the digit string: dp = exp + 1
	if exp >= -4 && exp < 16 {
		dp := exp + 1
		switch {
		case dp <= 0:
			return sign + "0." + strings.Repeat("0", -dp) + digits
		case dp >= len(digits):
			return sign + digits + strings.Repeat("0", dp-len(digits)) + ".0"
		default:
			return sign + digits[:dp] + "." + digits[dp:]
		}
	}
	m := digits[:1]
	if len(digits) > 1 {
		m += "." + digits[1:]
	}
	es := "+"
	if exp < 0 {
		es = "-"
		exp = -exp
	}
	return fmt.Sprintf("%s%se%s%02d", sign, m, es, exp)
}

func hitsFromCounts(counts map[string]int) []Hit {
	if len(counts) == 0 {
		return nil
	}
	hits := make([]Hit, 0, len(counts))
	for id, n := range counts {
		hits = append(hits, Hit{Rule: id, Count: n})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Rule < hits[j].Rule })
	return hits
}

// MergeHits sums per-rule counts across several redaction passes (text +
// payload + metadata of one envelope).
func MergeHits(groups ...[]Hit) []Hit {
	counts := map[string]int{}
	for _, g := range groups {
		for _, h := range g {
			counts[h.Rule] += h.Count
		}
	}
	return hitsFromCounts(counts)
}
