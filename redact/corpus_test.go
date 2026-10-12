// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package redact

// Conformance gate of the shared contract redact-v7 (§Fixture, §Procedures
// P4): the published corpus, vendored hash-pinned under testdata/ (the pin is
// the sha256 of the DECOMPRESSED bytes, the registry's published value), is
// the equality oracle between this Go port and the Python reference module.
//
// Every `tier: rules` seed passes in text mode on `input` and, for
// `structured: true` seeds, in structured mode on the parsed document; a
// `redacted` seed passes iff `secret` is absent from the output and every
// `must_remain` substring survives; a `kept` seed passes iff the output is
// byte-identical (structured: equal after JSON parse); every seed is
// idempotent; plain and keyed Redactors pass alike; hits = markers added.
// `classifier` and `policy` seeds are reported, not required. `tier: perf`
// seeds are materialised from their generator and the MEDIAN of 30 timed
// calls after one warm-up must stay within `max_ms` (P4 statement 1) — the
// one performance condition this gate fails on. Set
// CAVIAR_REDACT_PERF_REPORT=<path> to write the per-seed medians as JSON
// evidence (box, sample size, medians).

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// corpusSHA256 pins the decompressed corpus bytes to the registry's published
// value (redact-v7.md §Fixture; published reference/corpus inputs).
const corpusSHA256 = "d17eb1da7ef35fb4c10a9021357576c66443da897a43cef3fc3a58d18d962e67"

const corpusPath = "../tmp/fixtures/redact-v7-corpus.jsonl"

type seed struct {
	ID         string          `json:"id"`
	Input      *string         `json:"input"`
	Expected   string          `json:"expected"`
	Secret     string          `json:"secret"`
	MustRemain []string        `json:"must_remain"`
	Tier       string          `json:"tier"`
	Structured bool            `json:"structured"`
	Generator  *seedGenerator  `json:"generator"`
	MaxMs      float64         `json:"max_ms"`
	Note       string          `json:"note"`
	raw        json.RawMessage // the seed line, for error context
}

type seedGenerator struct {
	Kind   string `json:"kind"`
	Unit   string `json:"unit"`
	Count  int    `json:"count"`
	Prefix string `json:"prefix"`
	Suffix string `json:"suffix"`
	Key    string `json:"key"`
}

// text materialises the seed input: the literal `input`, or the generator's
// text (`repeat` = prefix + unit × count + suffix; `json-string` =
// {"<key>":"<unit × count>"}).
func (s *seed) text(t *testing.T) string {
	if s.Input != nil {
		return *s.Input
	}
	if s.Generator == nil {
		t.Fatalf("%s: neither input nor generator", s.ID)
	}
	g := s.Generator
	body := strings.Repeat(g.Unit, g.Count)
	switch g.Kind {
	case "repeat":
		return g.Prefix + body + g.Suffix
	case "json-string":
		return `{"` + g.Key + `":"` + body + `"}`
	}
	t.Fatalf("%s: unknown generator kind %q", s.ID, g.Kind)
	return ""
}

func loadCorpus(t *testing.T) []seed {
	t.Helper()
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal("materialize the pinned corpus with scripts/prepare.py first")
	}
	buf := bytes.NewBuffer(raw)
	sum := sha256.Sum256(buf.Bytes())
	if got := hex.EncodeToString(sum[:]); got != corpusSHA256 {
		t.Fatalf("corpus sha256 = %s, want the published %s (the vendored fixture is not the registry's bytes)", got, corpusSHA256)
	}
	var seeds []seed
	sc := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var s seed
		if err := json.Unmarshal(line, &s); err != nil {
			t.Fatalf("corpus line: %v", err)
		}
		s.raw = append(json.RawMessage(nil), line...)
		seeds = append(seeds, s)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}
	// 598 published v7 seeds, including 143 perf seeds.
	if len(seeds) != 598 {
		t.Fatalf("corpus has %d seeds, want 598", len(seeds))
	}
	return seeds
}

// Synthetic bytes 0..31; shared with installed-binding qualification.
func keyed() *Redactor {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return New(key)
}

// marshalJSON serialises like the Python harness compares: compact, no HTML
// escaping, sorted keys (Go maps marshal sorted).
func marshalJSON(t *testing.T, v any) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

func parseJSON(t *testing.T, s string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("parse structured input: %v", err)
	}
	return v
}

func corpusMarkers(s string) int { return len(markerRe.FindAllStringIndex(s, -1)) }

func sumHits(hits []Hit) int {
	n := 0
	for _, h := range hits {
		n += h.Count
	}
	return n
}

// checkText runs one seed in text mode under r and reports the verdict.
func checkText(t *testing.T, r *Redactor, s *seed, in string) {
	t.Helper()
	out, hits, err := r.String(in)
	if err != nil {
		t.Fatalf("%s: String error: %v", s.ID, err)
	}
	checkOutcome(t, s, in, out, hits, corpusMarkers(out)-corpusMarkers(in))
	again, hits2, err := r.String(out)
	if err != nil || again != out || len(hits2) != 0 {
		t.Fatalf("%s: not idempotent (err=%v, hits=%v, changed=%v)", s.ID, err, hits2, again != out)
	}
}

// checkStructured runs one seed in structured mode under r.
func checkStructured(t *testing.T, r *Redactor, s *seed, in string) {
	t.Helper()
	doc := parseJSON(t, in)
	out, hits, err := r.Value(doc)
	if err != nil {
		t.Fatalf("%s: Value error: %v", s.ID, err)
	}
	inText := marshalJSON(t, parseJSON(t, in))
	outText := marshalJSON(t, out)
	if s.Expected == "kept" {
		if !reflect.DeepEqual(parseJSON(t, in), out) {
			t.Fatalf("%s: kept seed changed in structured mode:\n in: %s\nout: %s", s.ID, inText, outText)
		}
	}
	checkOutcome(t, s, inText, outText, hits, corpusMarkers(outText)-corpusMarkers(inText))
	again, hits2, err := r.Value(parseJSON(t, outText))
	if err != nil || !reflect.DeepEqual(again, parseJSON(t, outText)) || len(hits2) != 0 {
		t.Fatalf("%s: not idempotent in structured mode (err=%v, hits=%v)", s.ID, err, hits2)
	}
}

func checkOutcome(t *testing.T, s *seed, in, out string, hits []Hit, markersAdded int) {
	t.Helper()
	switch s.Expected {
	case "redacted":
		if s.Secret != "" && strings.Contains(out, s.Secret) {
			t.Fatalf("%s: secret survived\n in: %s\nout: %s", s.ID, in, out)
		}
		for _, m := range s.MustRemain {
			if !strings.Contains(out, m) {
				t.Fatalf("%s: must_remain %q lost\nout: %s", s.ID, m, out)
			}
		}
		if len(hits) == 0 {
			t.Fatalf("%s: redacted seed reported no hits", s.ID)
		}
	case "kept":
		if out != in {
			t.Fatalf("%s: kept seed changed\n in: %s\nout: %s", s.ID, in, out)
		}
		if len(hits) != 0 {
			t.Fatalf("%s: kept seed reported hits %v", s.ID, hits)
		}
	default:
		t.Fatalf("%s: unknown expected %q", s.ID, s.Expected)
	}
	if n := sumHits(hits); n != markersAdded {
		t.Fatalf("%s: hits (%d) != markers added (%d): %v\nout: %s", s.ID, n, markersAdded, hits, out)
	}
	for _, h := range hits {
		if !ruleIDs[h.Rule] {
			t.Fatalf("%s: hit on unknown rule %q", s.ID, h.Rule)
		}
	}
	// No nested marker: a marker never contains "[REDACTED:" inside its span.
	for _, loc := range markerRe.FindAllStringIndex(out, -1) {
		inner := out[loc[0]+1 : loc[1]]
		if strings.Contains(inner, "[REDACTED:") {
			t.Fatalf("%s: nested marker in %q", s.ID, out[loc[0]:loc[1]])
		}
	}
}

var ruleIDs = func() map[string]bool {
	m := map[string]bool{"json-secret-object": true} // emitted by the json-schema-default pass
	for _, ru := range New(nil).table {
		m[ru.id] = true
	}
	return m
}()

func TestCorpusRulesTier(t *testing.T) {
	seeds := loadCorpus(t)
	redactors := map[string]*Redactor{"plain": New(nil), "keyed": keyed()}
	var reported []string
	for i := range seeds {
		s := &seeds[i]
		if s.Tier == "perf" {
			continue
		}
		in := s.text(t)
		for name, r := range redactors {
			t.Run(s.ID+"/"+name, func(t *testing.T) {
				if s.Tier != "rules" {
					// classifier and policy seeds: reported, not required
					out, hits, err := r.String(in)
					if err != nil {
						t.Fatalf("%s: %v", s.ID, err)
					}
					if name == "plain" {
						verdict := "readable"
						if s.Secret != "" && !strings.Contains(out, s.Secret) {
							verdict = "redacted"
						}
						reported = append(reported, fmt.Sprintf("%s (%s): %s, hits %v", s.ID, s.Tier, verdict, hits))
					}
					return
				}
				checkText(t, r, s, in)
				if s.Structured {
					checkStructured(t, r, s, in)
				}
			})
		}
	}
	sort.Strings(reported)
	for _, line := range reported {
		t.Log(line)
	}
}

type perfResult struct {
	ID       string  `json:"id"`
	Mode     string  `json:"mode"`
	MedianMs float64 `json:"median_ms"`
	MaxMs    float64 `json:"max_ms"`
	Bytes    int     `json:"bytes"`
}

type perfReport struct {
	Box       string       `json:"box"`
	GoVersion string       `json:"go_version"`
	Samples   int          `json:"samples"`
	Statistic string       `json:"statistic"`
	Keyed     bool         `json:"keyed"`
	Results   []perfResult `json:"results"`
}

const perfSamples = 30

// medianMs times fn: one untimed warm-up call, then the median of
// perfSamples calls (the mean of the two middle samples, as statistics.median).
func medianMs(fn func()) float64 { return medianMsN(perfSamples, fn) }

func medianMsN(n int, fn func()) float64 {
	fn()
	ds := make([]float64, n)
	for i := range ds {
		start := time.Now()
		fn()
		ds[i] = float64(time.Since(start).Microseconds()) / 1000
	}
	sort.Float64s(ds)
	return (ds[n/2-1] + ds[n/2]) / 2
}

func TestCorpusPerfTier(t *testing.T) {
	seeds := loadCorpus(t)
	r := keyed() // the HMAC path is the costlier marker path
	report := perfReport{Box: boxName(), GoVersion: runtime.Version(), Samples: perfSamples, Statistic: "median of 30 warm calls after one warm-up (mean of the two middle samples)", Keyed: true}
	for i := range seeds {
		s := &seeds[i]
		if s.Tier != "perf" {
			continue
		}
		in := s.text(t)
		t.Run(s.ID, func(t *testing.T) {
			// Correctness first: the perf seed scores like any seed.
			checkText(t, r, s, in)
			if s.Structured {
				checkStructured(t, r, s, in)
			}
			med := medianMs(func() {
				if _, _, err := r.String(in); err != nil {
					t.Fatal(err)
				}
			})
			report.Results = append(report.Results, perfResult{s.ID, "text", med, s.MaxMs, len(in)})
			if med > s.MaxMs {
				t.Errorf("%s text: median %.1f ms > max_ms %.0f", s.ID, med, s.MaxMs)
			}
			if s.Structured {
				doc := parseJSON(t, in)
				meds := medianMs(func() {
					// the walk mutates slices in place; a kept seed carries no
					// change, a redacted one is re-parsed per call
					d := doc
					if s.Expected == "redacted" {
						d = parseJSON(t, in)
					}
					if _, _, err := r.Value(d); err != nil {
						t.Fatal(err)
					}
				})
				report.Results = append(report.Results, perfResult{s.ID, "structured", meds, s.MaxMs, len(in)})
				if meds > s.MaxMs {
					t.Errorf("%s structured: median %.1f ms > max_ms %.0f", s.ID, meds, s.MaxMs)
				}
			}
		})
	}
	if path := os.Getenv("CAVIAR_REDACT_PERF_REPORT"); path != "" {
		b, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
			t.Fatalf("write perf report: %v", err)
		}
	}
	for _, res := range report.Results {
		t.Logf("%s %s: %.1f ms (max %.0f, %d bytes)", res.ID, res.Mode, res.MedianMs, res.MaxMs, res.Bytes)
	}
}

func boxName() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "model name") {
				if i := strings.Index(line, ":"); i >= 0 {
					return strings.TrimSpace(line[i+1:]) + " / " + runtime.GOOS + "-" + runtime.GOARCH
				}
			}
		}
	}
	return runtime.GOOS + "-" + runtime.GOARCH
}

// TestDepthFailsClosed: nesting beyond MaxNesting is ErrDepth, never a write.
func TestDepthFailsClosed(t *testing.T) {
	r := New(nil)
	deep := strings.Repeat("[", MaxNesting+1) + strings.Repeat("]", MaxNesting+1)
	if _, _, err := r.JSON(json.RawMessage(deep)); !errors.Is(err, ErrDepth) {
		t.Fatalf("structured depth %d: err=%v, want ErrDepth", MaxNesting+1, err)
	}
	ok := strings.Repeat("[", MaxNesting) + strings.Repeat("]", MaxNesting)
	if _, _, err := r.JSON(json.RawMessage(ok)); err != nil {
		t.Fatalf("structured depth %d must pass: %v", MaxNesting, err)
	}
	// Text P2: more than 512 enclosing secret-named objects.
	text := strings.Repeat(`{"secret":`, MaxNesting+1) + `{}` + strings.Repeat(`}`, MaxNesting+1)
	if _, _, err := r.String(text); !errors.Is(err, ErrDepth) {
		t.Fatalf("text P2 depth: err=%v, want ErrDepth", err)
	}
}

func TestNewRejectsShortKey(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New must panic on a key shorter than MinKeyBytes")
		}
	}()
	New([]byte("short"))
}

// TestLocatorEquivalence: the literal locators (locate.go) reproduce the
// plain regex path — the specification — byte for byte on every corpus seed
// (perf seeds at their 40 KB size, both modes, plain and keyed), and on the
// fold-exotic inputs that route a document to the regex path.
func TestLocatorEquivalence(t *testing.T) {
	seeds := loadCorpus(t)
	inputs := []string{
		"ſecret=FAKEfoldvalue01 TOKEN=FAKEfoldvalue02 Authorization: Bearer FAKEfoldtoken03",
		"\"toKen\": \"FAKEkelvinvalue04\" mysql -pFAKEkelvin05 K",
	}
	for i := range seeds {
		s := &seeds[i]
		if s.Tier == "perf" && !strings.HasSuffix(s.ID, "40k") && s.ID != "perf-14" {
			continue
		}
		inputs = append(inputs, s.text(t))
	}
	for _, r := range []*Redactor{New(nil), keyed()} {
		for _, in := range inputs {
			forceRegexPath = false
			fastOut, fastHits, fastErr := r.String(in)
			forceRegexPath = true
			slowOut, slowHits, slowErr := r.String(in)
			forceRegexPath = false
			if fastOut != slowOut || !reflect.DeepEqual(fastHits, slowHits) || (fastErr == nil) != (slowErr == nil) {
				t.Fatalf("locator path differs from the regex path\n in: %.200q\nfast: %.300q %v %v\nslow: %.300q %v %v", in, fastOut, fastHits, fastErr, slowOut, slowHits, slowErr)
			}
		}
	}
}

// TestMarkerMatchesCryptoHMAC: the precomputed-pad marker equals crypto/hmac.
func TestMarkerMatchesCryptoHMAC(t *testing.T) {
	for _, key := range [][]byte{[]byte("0123456789abcdef"), bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 100)} {
		r := New(key)
		for _, secret := range []string{"", "x", "FAKEmarkersecret", strings.Repeat("y", 1000)} {
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(secret))
			want := "[REDACTED:t:" + hex.EncodeToString(mac.Sum(nil)[:4]) + "]"
			if got := r.marker("t", secret); got != want {
				t.Fatalf("key %d bytes: marker %s, want %s", len(key), got, want)
			}
		}
	}
}
