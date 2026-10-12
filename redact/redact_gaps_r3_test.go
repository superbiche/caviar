// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package redact

// Trailing backslashes must not truncate JSON secret values at any escape depth.

import (
	"encoding/json"
	"strings"
	"testing"
)

const r3Secret = "Vt3pLq8ZmX2k" + "Rw7nBs5JdF4h" // 24 alnum chars

// encodeDepth wraps s in d successive JSON string encodings and strips the
// outermost quotes, so the text looks like it does inside a transcript field.
func encodeDepth(t *testing.T, s string, d int) string {
	t.Helper()
	for i := 0; i < d; i++ {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		s = string(b[1 : len(b)-1])
	}
	return s
}

// decodeDepth reverses encodeDepth so the redacted output can be compared as
// the inner JSON document it represents.
func decodeDepth(t *testing.T, s string, d int) string {
	t.Helper()
	for i := 0; i < d; i++ {
		var out string
		if err := json.Unmarshal([]byte(`"`+s+`"`), &out); err != nil {
			t.Fatalf("depth %d output is not a valid JSON string: %v: %s", d, err, s)
		}
		s = out
	}
	return s
}

func TestJSONSecretFieldTerminalBackslashWholeValueAtEveryDepth(t *testing.T) {
	for _, trailing := range []int{1, 2} {
		for _, follow := range []string{``, `,"next":"keep","count":9007199254740993`} {
			// Inner document: the decoded password ends with `trailing` backslashes.
			innerSecret := r3Secret + strings.Repeat(`\`, trailing)
			b, _ := json.Marshal(map[string]string{"password": innerSecret})
			inner := `{"password":` + string(b[len(`{"password":`):len(b)-1]) + follow + `}`
			for d := 0; d <= 3; d++ {
				in := encodeDepth(t, inner, d)
				out, hits, _ := plain().String(in)
				if strings.Contains(out, r3Secret) {
					t.Fatalf("depth %d trailing %d follow %v: secret survived: %s", d, trailing, follow != "", out)
				}
				if len(hits) != 1 || hits[0].Rule != "json-secret-field" || hits[0].Count != 1 {
					t.Fatalf("depth %d trailing %d follow %v: want one json-secret-field hit, got %v: %s", d, trailing, follow != "", hits, out)
				}
				dec := decodeDepth(t, out, d)
				var doc map[string]any
				if err := json.Unmarshal([]byte(dec), &doc); err != nil {
					t.Fatalf("depth %d trailing %d follow %v: redacted document is not valid JSON: %v: %s", d, trailing, follow != "", err, dec)
				}
				pw, _ := doc["password"].(string)
				if !strings.HasPrefix(pw, "[REDACTED:json-secret-field:") || !strings.HasSuffix(pw, "]") {
					t.Fatalf("depth %d: password must be exactly one marker, got %q", d, pw)
				}
				if follow != "" {
					if doc["next"] != "keep" || !strings.Contains(dec, "9007199254740993") {
						t.Fatalf("depth %d: following structure damaged: %s", d, dec)
					}
				}
			}
		}
	}
}

func TestJSONSecretFieldInteriorAndTerminalEscapesTogether(t *testing.T) {
	// Interior escaped quote AND terminal backslash in the same value, depth 0..2.
	innerSecret := r3Secret[:12] + `"` + r3Secret[12:] + `\`
	b, _ := json.Marshal(map[string]string{"token": innerSecret, "zz": "after"})
	for d := 0; d <= 2; d++ {
		in := encodeDepth(t, string(b), d)
		out, _, _ := plain().String(in)
		if strings.Contains(out, r3Secret[:12]) || strings.Contains(out, r3Secret[12:]) {
			t.Fatalf("depth %d: part of the secret survived: %s", d, out)
		}
		dec := decodeDepth(t, out, d)
		var doc map[string]any
		if err := json.Unmarshal([]byte(dec), &doc); err != nil || doc["zz"] != "after" {
			t.Fatalf("depth %d: structure after the value damaged (%v): %s", d, err, dec)
		}
	}
}

func TestJSONSecretFieldTerminalBackslashIdempotent(t *testing.T) {
	b, _ := json.Marshal(map[string]string{"password": r3Secret + `\`})
	for d := 0; d <= 2; d++ {
		in := encodeDepth(t, string(b), d)
		once, _, _ := plain().String(in)
		twice, hits, _ := plain().String(once)
		if once != twice || len(hits) != 0 {
			t.Fatalf("depth %d not idempotent: %q -> %q (%v)", d, once, twice, hits)
		}
	}
}
