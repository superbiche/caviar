// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package redact

// A marker inside a JSON secret value keeps its owning rule.

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	r4Bearer = "mN4kQ8vZ2pXr" + "7tLw3yBc6dFg"        // 24 alnum chars
	r4OpenAI = "sk-" + "Ab12Cd34Ef56Gh78Ij90Kl12Mn34" // openai-key shape
)

func onlyRule(hits []Hit) string {
	if len(hits) != 1 || hits[0].Count != 1 {
		return ""
	}
	return hits[0].Rule
}

func TestJSONSecretFieldDoesNotRewrapShapeMarkersInText(t *testing.T) {
	cases := []struct{ name, inner, rule, secret string }{
		{"bearer-under-password", "Authorization: Bearer " + r4Bearer, "bearer-header", r4Bearer},
		{"openai-under-token", r4OpenAI, "openai-key", r4OpenAI},
		{"openai-with-prefix-under-apiKey", "key=" + r4OpenAI, "openai-key", r4OpenAI},
	}
	keys := map[string]string{"bearer-under-password": "password", "openai-under-token": "token", "openai-with-prefix-under-apiKey": "apiKey"}
	for _, tc := range cases {
		b, _ := json.Marshal(map[string]string{keys[tc.name]: tc.inner, "next": "keep"})
		for d := 0; d <= 2; d++ {
			in := encodeDepth(t, string(b), d)
			out, hits, _ := plain().String(in)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("%s depth %d: secret survived: %s", tc.name, d, out)
			}
			if markerCount(out) != 1 || !strings.Contains(out, "[REDACTED:"+tc.rule+":") {
				t.Fatalf("%s depth %d: want exactly one %s marker, got: %s", tc.name, d, tc.rule, out)
			}
			if onlyRule(hits) != tc.rule {
				t.Fatalf("%s depth %d: hits must report only the owning rule %s, got %v", tc.name, d, tc.rule, hits)
			}
			dec := decodeDepth(t, out, d)
			var doc map[string]any
			if err := json.Unmarshal([]byte(dec), &doc); err != nil || doc["next"] != "keep" {
				t.Fatalf("%s depth %d: structure damaged (%v): %s", tc.name, d, err, dec)
			}
		}
	}
}

func TestJSONSecretFieldLeavesPreMarkedValuesAlone(t *testing.T) {
	// A header already redacted in an earlier capture, then embedded under a
	// secret-named key: byte-identical, zero hits (text and structured).
	marked, _, _ := plain().String("Authorization: Bearer " + r4Bearer)
	b, _ := json.Marshal(map[string]string{"password": marked, "next": "keep"})
	out, hits, _ := plain().String(string(b))
	if out != string(b) || len(hits) != 0 {
		t.Fatalf("text surface re-wrapped a marked value: %q -> %q (%v)", string(b), out, hits)
	}
	raw, hits2, _ := plain().JSON(json.RawMessage(b))
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil || doc["password"] != marked || len(hits2) != 0 {
		t.Fatalf("structured surface re-wrapped a marked value: %s (%v, %v)", raw, hits2, err)
	}
}

func TestStructuredSecretKeyWithShapeTokenOwnedOnce(t *testing.T) {
	// Structured surface: a bearer header under a secret-named key gets ONE
	// marker (whichever rule owns it) and the second pass is a no-op.
	b, _ := json.Marshal(map[string]string{"password": "Authorization: Bearer " + r4Bearer, "next": "keep"})
	once, hits, _ := plain().JSON(json.RawMessage(b))
	if strings.Contains(string(once), r4Bearer) || markerCount(string(once)) != 1 || len(hits) != 1 {
		t.Fatalf("want one owning marker and one hit: %s %v", once, hits)
	}
	twice, hits2, _ := plain().JSON(once)
	if string(twice) != string(once) || len(hits2) != 0 {
		t.Fatalf("structured pass not idempotent: %s -> %s (%v)", once, twice, hits2)
	}
}

func TestPEMBlockContainingMarkerTextIsStillRedacted(t *testing.T) {
	// A PEM block whose body contains
	// marker-looking text is still redacted whole by pem-block.
	pem := "-----BEGIN PRIVATE KEY-----\nMIIE[REDACTED:x:00000000]vQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----"
	out, hits, _ := plain().String(pem)
	if strings.Contains(out, "MIIE") || onlyRule(hits) != "pem-block" {
		t.Fatalf("PEM block must be redacted whole: %s %v", out, hits)
	}
}
