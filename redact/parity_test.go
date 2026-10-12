// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package redact

// Directed Python-parity regression witnesses. Synthetic values cover Unicode
// folding, capture boundaries and marker ownership alongside the full corpus.

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestParityTurkishIFolding(t *testing.T) {
	r := New(nil)
	cases := []struct {
		name, in, rule, secret string
	}{
		{"header name with dotless i", "Authorızation: Basic FAKEf1value000001", "header-credential", "FAKEf1value000001"},
		{"json key with dotless i", `{"apıkey": "FAKEf1value000002"}`, "json-secret-field", "FAKEf1value000002"},
		{"mariadb spelled with dotless i", "marıadb -pFAKEf1value3 db", "mysql-p-flag", "FAKEf1value3"},
		{"uppercase dotted I in an env key", "APİ_KEY=FAKEf1value000004", "env-secret-assignment", "FAKEf1value000004"},
		{"dotless i inside the key run", `{"ıtoken": "FAKEf1value000005"}`, "json-secret-field", "FAKEf1value000005"},
		{"dotted I inside the key run", `{"İtoken": "FAKEf1value000006"}`, "json-secret-field", "FAKEf1value000006"},
		{"kelvin sign in token", "toKen FAKEf1value0000000000007", "bare-bearer-token", "FAKEf1value0000000000007"},
		{"long s in secret", "ſecret=FAKEf1value000008", "env-secret-assignment", "FAKEf1value000008"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, hits, err := r.String(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, tc.secret) || len(hits) != 1 || hits[0].Rule != tc.rule {
				t.Fatalf("Python redacts this as %s; Go: %q %v", tc.rule, out, hits)
			}
		})
	}
	// Structured walk: a secret-named key spelled with Turkish i.
	for _, doc := range []string{`{"ıtoken":"FAKEf1value000009"}`, `{"İtoken":"FAKEf1value000010"}`, `{"apı_key":"FAKEf1value000011"}`} {
		out, hits, err := r.JSON(json.RawMessage(doc))
		if err != nil || strings.Contains(string(out), "FAKEf1value") || len(hits) != 1 || hits[0].Rule != "json-secret-field" {
			t.Fatalf("structured walk under a Turkish-i secret key: %s %v %v", out, hits, err)
		}
	}
}

func TestParityUnicodeWordBoundary(t *testing.T) {
	r := New(nil)
	// Python: the run `AAAAAAAAAAAAAAAAAAA-` (20 chars) ends at a boundary
	// between `-` (non-word) and `é` (a letter): redacted whole. Go's ASCII
	// `\b` saw no boundary there and found none inside the run — kept.
	in := "sk-" + strings.Repeat("A", 19) + "-é"
	out, hits, _ := r.String(in)
	if len(hits) != 1 || hits[0].Rule != "openai-key" || strings.Contains(out, "AAAA") || !strings.HasSuffix(out, "]é") {
		t.Fatalf("Python redacts the 20-character payload up to the hyphen: %q %v", out, hits)
	}
	// 22 letters then `-é`: the boundary before é includes the hyphen in the match.
	in = "sk-" + strings.Repeat("A", 22) + "-é"
	out, hits, _ = r.String(in)
	if len(hits) != 1 || !strings.HasSuffix(out, "]é") {
		t.Fatalf("the hyphen belongs to the match (boundary before é): %q %v", out, hits)
	}
	// A letter glued after the run: no boundary anywhere in the run, kept (both implementations).
	in = "sk-" + strings.Repeat("A", 22) + "é"
	if out, hits, _ := r.String(in); out != in || len(hits) != 0 {
		t.Fatalf("no boundary before é: must be kept, got %q %v", out, hits)
	}
	// Leading boundary: a letter before the needle is no boundary in Python.
	in = "é" + "AKIAIOSFODNN7EXAMPLE"
	if out, hits, _ := r.String(in); out != in || len(hits) != 0 {
		t.Fatalf("letter before AKIA: no Python boundary, must be kept: %q %v", out, hits)
	}
	// mysql word followed by a letter: no trailing boundary.
	in = "mysqlé -pFAKEf2value1"
	if out, hits, _ := r.String(in); out != in || len(hits) != 0 {
		t.Fatalf("mysql glued to é is not the word: %q %v", out, hits)
	}
	// mysqldump is tried after mysql fails its boundary.
	if _, hits, _ := r.String("mysqldump -pFAKEf2value2 db"); len(hits) != 1 || hits[0].Rule != "mysql-p-flag" {
		t.Fatalf("mysqldump must still match: %v", hits)
	}
	// Grafana: `_` is a word character, so neither the suffixed nor the bare
	// end has a boundary before `é` — kept (reference-checked); a hyphen
	// before é is a boundary and the suffixed form matches.
	in = "glsa_" + strings.Repeat("a", 32) + "_0123abcdé"
	if out, hits, _ := r.String(in); out != in || len(hits) != 0 {
		t.Fatalf("grafana token glued to é: no boundary, kept: %q %v", out, hits)
	}
	in = "glsa_" + strings.Repeat("a", 32) + "_0123abcd-é"
	if out, hits, _ := r.String(in); len(hits) != 1 || !strings.HasSuffix(out, "]-é") {
		t.Fatalf("grafana token with its suffix before -é: %q %v", out, hits)
	}
}

func TestParityStructuredNumberText(t *testing.T) {
	for lit, want := range map[string]string{
		"1e7": "10000000.0", "1e8": "100000000.0", "1.234e7": "12340000.0", "12345678": "12345678", "1.50": "1.5",
		"-0": "0", "-0.0": "-0.0", "1E2": "100.0", "1e16": "1e+16", "1e15": "1000000000000000.0", "0.0001": "0.0001",
		"0.00001": "1e-05", "123456789012345678901234567890": "123456789012345678901234567890", "1.0": "1.0",
		"2.5e-7": "2.5e-07", "1e22": "1e+22", "1.7976931348623157e308": "1.7976931348623157e+308", "5e-324": "5e-324",
		"0.1": "0.1", "100": "100", "3.0e2": "300.0", "-1.5": "-1.5",
	} {
		if got := pyNumberText(lit); got != want {
			t.Errorf("pyNumberText(%s) = %s, want %s (json.dumps(json.loads(...)))", lit, got, want)
		}
	}
	r := New(nil)
	for _, doc := range []string{`{"token": 1e7}`, `{"token": 1e8}`, `{"token": 1.234e7}`, `{"token": 12345678}`} {
		out, hits, err := r.JSON(json.RawMessage(doc))
		if err != nil || len(hits) != 1 || hits[0].Rule != "json-secret-field" || !strings.Contains(string(out), `"[REDACTED:json-secret-field:`) {
			t.Fatalf("%s: the reference redacts an 8+ character json.dumps number: %s %v %v", doc, out, hits, err)
		}
	}
	// Marker text = Python's json.dumps text, so the hashes correlate across implementations.
	out, _, _ := r.JSON(json.RawMessage(`{"token": 1e7}`))
	if !strings.Contains(string(out), r.marker("json-secret-field", "10000000.0")) {
		t.Fatalf("marker must hash the json.dumps text: %s", out)
	}
	// 1e3 renders as `1000.0` (6 characters): below the floor, kept; a
	// non-secret number survives bit-exact (reference-checked).
	if out, hits, _ := r.JSON(json.RawMessage(`{"token": 1e3, "n": 9007199254740993}`)); len(hits) != 0 || !strings.Contains(string(out), "9007199254740993") {
		t.Fatalf("a short number stays, a non-secret number survives bit-exact: %s %v", out, hits)
	}
}

func TestParityUnicodeListSeparator(t *testing.T) {
	r := New(nil)
	for _, sep := range []string{" ", " ", " ", " ", "  "} {
		in := `{"auth":{"enum":[` + sep + `"FAKEf6value0001"]}}`
		out, hits, err := r.String(in)
		if err != nil || len(hits) != 1 || hits[0].Rule != "json-schema-default" || strings.Contains(out, "FAKEf6") {
			t.Fatalf("separator %q: %q %v %v", sep, out, hits, err)
		}
	}
}

func TestParityLinearFamilyRun(t *testing.T) {
	// A run of family words with no delimiter must cost O(n): the
	// identifier run after each needle is measured once per run.
	r := keyed()
	in := strings.Repeat("secret", 96000/6)
	r.String(in) // warm-up
	best := time.Duration(1 << 62)
	for i := 0; i < 5; i++ {
		start := time.Now()
		out, hits, err := r.String(in)
		if d := time.Since(start); d < best {
			best = d
		}
		if err != nil || out != in || len(hits) != 0 {
			t.Fatal("the run has no delimiter: nothing to redact")
		}
	}
	// Measured ~7 ms on the reference box (was ~24 s extrapolated before the
	// repair); 300 ms leaves room for a loaded box without hiding O(n²).
	if best > 300*time.Millisecond {
		t.Fatalf("96 KB family run took %v", best)
	}
	// Many candidates sharing one long run with no trailing boundary.
	in = strings.Repeat("sk-", 192000/3) + strings.Repeat("A", 25) + "é"
	start := time.Now()
	if _, hits, _ := r.String(in); len(hits) != 1 {
		t.Fatalf("expected one match, got %v", hits)
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("192 KB sk- run took %v", d)
	}
}

func TestParityUnicode16WordTable(t *testing.T) {
	r := New(nil)
	// U+1C89 CYRILLIC CAPITAL LETTER TJE is a letter in Unicode 16 (CPython
	// 3.14) and unassigned in Go's Unicode 15 tables: the pinned table
	// decides, not Go's unicode package.
	in := "sk-" + strings.Repeat("A", 19) + "-Ᲊ"
	if out, hits, _ := r.String(in); len(hits) != 1 || !strings.HasSuffix(out, "]Ᲊ") {
		t.Fatalf("boundary between - and a Unicode-16 letter: %q %v", out, hits)
	}
	in = "Ᲊsk-" + strings.Repeat("A", 22)
	if out, hits, _ := r.String(in); out != in || len(hits) != 0 {
		t.Fatalf("a Unicode-16 letter before sk-: no boundary, kept: %q %v", out, hits)
	}
	if !pyWord('Ᲊ') || !pyWord('_') || !pyWord('é') || !pyWord('٣') || pyWord('-') || pyWord(' ') || pyWord('́') {
		t.Fatal("pyWord table sanity")
	}
}

// TestPyWordTablePinned regenerates the table from the installed CPython
// (the reference runtime) and compares; opt-in with MEMOIRE_REDACT_PYCHECK=1.
func TestPyWordTablePinned(t *testing.T) {
	if os.Getenv("MEMOIRE_REDACT_PYCHECK") == "" {
		t.Skip("set MEMOIRE_REDACT_PYCHECK=1 (needs python3)")
	}
	out, err := exec.Command("python3", "-I", "pyword_gen.py").Output()
	if err != nil {
		t.Fatal(err)
	}
	cur, err := os.ReadFile("pyword_table.go")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(cur) {
		t.Fatal("pyword_table.go differs from the installed CPython's table: regenerate and record the Unicode version")
	}
}

func TestParityOverflowNumbers(t *testing.T) {
	for lit, want := range map[string]string{"1e309": "Infinity", "-1e309": "-Infinity", "1e400": "Infinity", "1e-400": "0.0", "-1e-400": "-0.0"} {
		if got := pyNumberText(lit); got != want {
			t.Errorf("pyNumberText(%s) = %s, want %s", lit, got, want)
		}
	}
	r := New(nil)
	for _, doc := range []string{`{"token": 1e309}`, `{"token": -1e309}`} {
		out, hits, err := r.JSON(json.RawMessage(doc))
		if err != nil || len(hits) != 1 || strings.Contains(string(out), "1e309") {
			t.Fatalf("%s: Python redacts the Infinity text: %s %v %v", doc, out, hits, err)
		}
	}
	if out, hits, _ := r.JSON(json.RawMessage(`{"token": 1e-400}`)); len(hits) != 0 || !strings.Contains(string(out), "1e-400") {
		t.Fatalf("underflow renders 0.0 (3 chars): kept bit-exact: %s %v", out, hits)
	}
}

func TestParityBlockedPrefixRunIsLinear(t *testing.T) {
	r := keyed()
	// The tail succeeds at every needle (`=x` closes the run) but the prefix
	// cannot start (`-` is not an allowed separator): the failed window
	// search must not be repeated per needle.
	in := "-" + strings.Repeat("secret", 96000/6) + "=x"
	r.String(in)
	best := time.Duration(1 << 62)
	for i := 0; i < 5; i++ {
		start := time.Now()
		out, hits, err := r.String(in)
		if d := time.Since(start); d < best {
			best = d
		}
		if err != nil || out != in || len(hits) != 0 {
			t.Fatal("no admissible prefix start: nothing to redact")
		}
	}
	if best > 300*time.Millisecond {
		t.Fatalf("96 KB blocked-prefix run took %v", best)
	}
	// Successive blocked runs, each with a successful tail — the
	// window of a needle starts at its own run, never at the search position.
	in = strings.Repeat("-xsecret=x", 96000/10)
	r.String(in)
	best = time.Duration(1 << 62)
	for i := 0; i < 5; i++ {
		start := time.Now()
		out, hits, err := r.String(in)
		if d := time.Since(start); d < best {
			best = d
		}
		if err != nil || out != in || len(hits) != 0 {
			t.Fatal("blocked runs: nothing to redact")
		}
	}
	if best > 300*time.Millisecond {
		t.Fatalf("96 KB of blocked runs took %v", best)
	}
	// The same shape through the JSON locators: a key run whose quote is
	// not right before it (`.` is outside the key class), tail succeeding.
	in = strings.Repeat(`"x.token":1,`, 96000/12)
	start := time.Now()
	if out, hits, _ := r.String(in); out != in || len(hits) != 0 {
		t.Fatalf("blocked key runs: %v", hits)
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("96 KB of blocked key runs took %v", d)
	}
	// Keyword before a run: the window reaches back over the keyword and its whitespace.
	if out, hits, _ := r.String("x export   DB_TOKEN=FAKEf5value0002 y"); len(hits) != 1 || strings.Contains(out, "FAKEf5") {
		t.Fatalf("export prefix: %q %v", out, hits)
	}
	if out, hits, _ := r.String("x const\n\tAPI_SECRET=FAKEf5value0003"); len(hits) != 1 || strings.Contains(out, "FAKEf5") {
		t.Fatalf("const prefix across a newline: %q %v", out, hits)
	}
	// Control: an allowed separator before the run redacts the value once.
	if out, hits, _ := r.String(" " + strings.Repeat("secret", 10) + "=FAKEf5value0001"); len(hits) != 1 || strings.Contains(out, "FAKEf5") {
		t.Fatalf("allowed separator: %q %v", out, hits)
	}
}

// A folded keyword (`conſt`, `ſet`: ſ is two bytes) must still be reached by
// the assignment window, or the row's prefix starts late and P0 ownership of
// an existing marker is missed: the reference keeps the assignment untouched
// when its prefix overlaps the marker's closing bracket.
func TestParityFoldedKeywordWindow(t *testing.T) {
	for _, r := range []*Redactor{New(nil), New([]byte("key-one-key-one-key-one-key-one!"))} {
		marker := r.marker("github-token", "FAKEf9marker")
		for _, kw := range []string{"const", "conſt", "ſet", "set", "export", "Kelvin-free"} {
			doc := marker + kw + "  DB_SECRET=FAKEf9value0001"
			out, hits, err := r.String(doc)
			if err != nil {
				t.Fatal(err)
			}
			if kw == "Kelvin-free" { // not a keyword: an ordinary prefix, value redacted
				if len(hits) != 1 || strings.Contains(out, "FAKEf9value") {
					t.Fatalf("%q: %q %v", kw, out, hits)
				}
				continue
			}
			if len(hits) != 0 || out != doc {
				t.Fatalf("owned prefix through %q: %q %v", kw, out, hits)
			}
		}
		// Same-pass ownership: a row-8 token's marker is minted earlier in the
		// same call; the assignment prefix after `ſet` overlaps it.
		doc := "lbx1_" + strings.Repeat("A", 20) + "ſet DB_SECRET=FAKEf9value0002"
		out, hits, err := r.String(doc)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 1 || hits[0].Rule != "liaison-letterbox-token" || !strings.HasSuffix(out, "ſet DB_SECRET=FAKEf9value0002") {
			t.Fatalf("same-pass ownership: %q %v", out, hits)
		}
		// Without a marker the folded keyword is an ordinary prefix: redacted.
		if out, hits, _ := r.String("x conſt DB_SECRET=FAKEf9value0003"); len(hits) != 1 || strings.Contains(out, "FAKEf9value") {
			t.Fatalf("conſt prefix: %q %v", out, hits)
		}
		// A multi-byte separator before the keyword keeps the window on a rune boundary.
		if out, hits, _ := r.String("é const DB_SECRET=FAKEf9value0004"); len(hits) != 1 || strings.Contains(out, "FAKEf9value") {
			t.Fatalf("multi-byte separator: %q %v", out, hits)
		}
	}
}

func TestParityPolicyLower(t *testing.T) {
	if got := pyLower("requİred"); got != "requi̇red" {
		t.Fatalf("pyLower(requİred) = %q", got)
	}
	if got := pyLower("K"); got != "k" {
		t.Fatalf("pyLower(KELVIN) = %q", got)
	}
	r := New(nil)
	// A dotted-I spelling is not the placeholder word: redacted by the reference.
	for _, doc := range []string{`{"password":"requİred"}`} {
		if out, hits, _ := r.String(doc); len(hits) != 1 || hits[0].Rule != "json-secret-field" {
			t.Fatalf("text: %q %v", out, hits)
		}
		if out, hits, _ := r.JSON(json.RawMessage(doc)); len(hits) != 1 || strings.Contains(string(out), "requİred") {
			t.Fatalf("structured: %s %v", out, hits)
		}
	}
	// Dotted-I spellings of safe keys are NOT safe keys: their values are secret-object spans.
	doc := `{"auth":{"tİtle":"FAKEf8value0001","fİle":"FAKEf8value0002","title":"FAKEf8value0003"}}`
	out, hits, _ := r.String(doc)
	if strings.Contains(out, "FAKEf8value0001") || strings.Contains(out, "FAKEf8value0002") || !strings.Contains(out, "FAKEf8value0003") || len(hits) != 1 || hits[0].Count != 2 {
		t.Fatalf("text P2: %q %v", out, hits)
	}
	jout, jhits, _ := r.JSON(json.RawMessage(doc))
	if strings.Contains(string(jout), "FAKEf8value0001") || strings.Contains(string(jout), "FAKEf8value0002") || !strings.Contains(string(jout), "FAKEf8value0003") || len(jhits) != 1 || jhits[0].Count != 2 {
		t.Fatalf("structured: %s %v", jout, jhits)
	}
}
