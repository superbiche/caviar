// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package redact

// Earlier markers are not re-wrapped on text or structured surfaces.

import (
	"encoding/json"
	"strings"
	"testing"
)

const r5Token = "sk-" + "Zq8Wn3Lp7Rt2Kx5Yv9Bm4Cd6Fg1Hj" // openai-key shape, 29 chars after sk-

func TestURLCredentialsDoNotRewrapShapeMarkers(t *testing.T) {
	// Password = short non-secret prefix + provider-shaped token: openai-key
	// owns the token; url-credentials must leave the marked password alone.
	url := "https://user:prefix-" + r5Token + "@db.example.net:5432/app"
	cases := []struct{ name, in string }{
		{"plain", "connect " + url + " now"},
		{"json-secret-value", mustJSON(t, map[string]string{"password": url, "next": "keep"})},
		{"json-plain-leaf", mustJSON(t, map[string]string{"message": "see " + url, "next": "keep"})},
	}
	for _, tc := range cases {
		out, hits, _ := plain().String(tc.in)
		if strings.Contains(out, r5Token) {
			t.Fatalf("%s: token survived: %s", tc.name, out)
		}
		if markerCount(out) != 1 || !strings.Contains(out, "[REDACTED:openai-key:") {
			t.Fatalf("%s: want exactly one openai-key marker, got: %s", tc.name, out)
		}
		if onlyRule(hits) != "openai-key" {
			t.Fatalf("%s: hits must report only openai-key, got %v", tc.name, hits)
		}
		if !strings.Contains(out, "https://user:prefix-[REDACTED:openai-key:") || !strings.Contains(out, "]@db.example.net:5432/app") {
			t.Fatalf("%s: URL structure around the marker must survive: %s", tc.name, out)
		}
	}
}

func TestURLCredentialsLeavePreMarkedPasswordAlone(t *testing.T) {
	marked, _, _ := plain().String(r5Token)
	in := "https://user:" + marked + "@host/db"
	out, hits, _ := plain().String(in)
	if out != in || len(hits) != 0 {
		t.Fatalf("pre-marked password re-wrapped: %q -> %q (%v)", in, out, hits)
	}
}

func TestStructuredLeafURLWithShapeTokenOwnedOnce(t *testing.T) {
	url := "https://user:prefix-" + r5Token + "@host/db"
	b, _ := json.Marshal(map[string]string{"message": url, "next": "keep"})
	once, hits, _ := plain().JSON(json.RawMessage(b))
	if strings.Contains(string(once), r5Token) || markerCount(string(once)) != 1 || onlyRule(hits) != "openai-key" {
		t.Fatalf("structured leaf: want one openai-key marker and one hit: %s %v", once, hits)
	}
	twice, hits2, _ := plain().JSON(once)
	if string(twice) != string(once) || len(hits2) != 0 {
		t.Fatalf("structured leaf not idempotent: %s -> %s (%v)", once, twice, hits2)
	}
}

func TestEveryShapeRuleKeepsOwnershipInsideURLPassword(t *testing.T) {
	// A provider-shaped secret as the whole URL password after a fixed prefix,
	// for each shape rule that can appear in a password: one owning marker.
	shapes := map[string]string{
		"aws-access-key":          "AKIA" + "ABCDEFGHIJKLMNOP",
		"github-token":            "ghp_" + strings.Repeat("Ab1", 12),
		"gitlab-token":            "glpat-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8",
		"liaison-letterbox-token": "lbx1_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8",
		"slack-token":             "xoxb-" + "1234567890-abcdefghij",
	}
	for rule, tok := range shapes {
		in := "https://user:p-" + tok + "@host/db"
		out, hits, _ := plain().String(in)
		if strings.Contains(out, tok) || markerCount(out) != 1 || onlyRule(hits) != rule {
			t.Fatalf("%s: want one owning marker, got %q %v", rule, out, hits)
		}
	}
}

func TestURLCredentialsStillOwnPlainPasswords(t *testing.T) {
	out, hits, _ := plain().String("postgres://u:" + fakeDBPassword + "@host/db")
	if strings.Contains(out, fakeDBPassword) || onlyRule(hits) != "url-credentials" {
		t.Fatalf("plain password must stay with url-credentials: %s %v", out, hits)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
