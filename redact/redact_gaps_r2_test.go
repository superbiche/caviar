// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package redact

// Regression witnesses for capture boundaries, URL authority and ownership.
//   F1 escaped quotes/backslashes inside a JSON secret value must not split
//      the redaction (prefix redacted, suffix leaked).
//   F2 the URL rule must bind the username to the authority: a colon or @
//      in the path, query or fragment of a password-less URL is not a
//      credential.
//   F3 a later generic rule must never wrap a marker produced by an earlier
//      rule; one owning marker per secret.
// Fixtures are concatenation-split like the rest of this file set.

import (
	"strings"
	"testing"
)

const (
	r2Head = "Qm4wZx8vN2kP" + "7rTy" // 16 chars: exactly the historical v2 floor (v5: 8), still well above it
	r2Tail = "b3Lq9S" + "wE"         // 8 chars after the escaped char
)

func markerCount(s string) int { return strings.Count(s, "[REDACTED:") }

func assertWholeValueGone(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, r2Head) || strings.Contains(out, r2Tail) {
		t.Fatalf("part of the secret survived: %s", out)
	}
	if markerCount(out) != 1 {
		t.Fatalf("want exactly one marker, got %d: %s", markerCount(out), out)
	}
	if !strings.Contains(out, "[REDACTED:json-secret-field:") {
		t.Fatalf("want a json-secret-field marker: %s", out)
	}
}

func TestJSONSecretFieldRedactsWholeValueWithEscapedQuote(t *testing.T) {
	// Plain JSON: the value contains an escaped quote after 16 chars (the v2 floor; the v5 floor is 8).
	in := `{"password":"` + r2Head + `\"` + r2Tail + `","next":"keep"}`
	out, _, _ := plain().String(in)
	assertWholeValueGone(t, out)
	if !strings.HasSuffix(out, `","next":"keep"}`) {
		t.Fatalf("structure after the value must survive intact: %s", out)
	}
}

func TestJSONSecretFieldRedactsWholeValueWithEscapedBackslash(t *testing.T) {
	in := `{"password":"` + r2Head + `\\` + r2Tail + `"}`
	out, _, _ := plain().String(in)
	assertWholeValueGone(t, out)
	if !strings.HasSuffix(out, `"}`) {
		t.Fatalf("closing quote and brace must survive: %s", out)
	}
}

func TestJSONSecretFieldRedactsWholeValueWithEscapedQuoteAtDepthOne(t *testing.T) {
	// Tool output escaped once inside a transcript string: delimiters are \"
	// and an interior quote is \\\" (three backslashes). The value must end
	// at the depth-1 delimiter, not at the interior quote and not at the end
	// of the string.
	in := `"{\"password\":\"` + r2Head + `\\\"` + r2Tail + `\",\"next\":\"keep\"}"`
	out, _, _ := plain().String(in)
	assertWholeValueGone(t, out)
	if !strings.HasSuffix(out, `\",\"next\":\"keep\"}"`) {
		t.Fatalf("escaped structure after the value must survive intact: %s", out)
	}
}

func TestJSONSecretFieldFloorCountsTheWholeValue(t *testing.T) {
	// Fewer than 16 chars (the v2 floor; v5: 8) before the escaped quote, more in total:
	// the floor applies to the whole value.
	in := `{"token":"abc\"` + r2Head + `"}`
	out, _, _ := plain().String(in)
	if strings.Contains(out, r2Head) || markerCount(out) != 1 {
		t.Fatalf("whole value must be redacted once: %s", out)
	}
}

func TestURLCredentialsIgnoreColonAndAtOutsideTheAuthority(t *testing.T) {
	cases := []string{
		`https://host/path:abcdef@handle`,
		`https://example.com/a?x=1:2@y`,
		`https://example.com/#frag:ab@c`,
		`https://user@host/path:abc@d`,
		`see https://docs.example.com/v1/ref:main@sha for details`,
	}
	for _, in := range cases {
		out, hits, _ := plain().String(in)
		if out != in || len(hits) != 0 {
			t.Fatalf("password-less URL must be untouched: %q -> %q (%v)", in, out, hits)
		}
	}
}

func TestURLCredentialsStillRedactAuthorityPasswords(t *testing.T) {
	cases := []struct{ in, prefix, suffix string }{
		{`postgres://u:` + fakeDBPassword + `@host/db`, `postgres://u:[REDACTED:url-credentials:`, `]@host/db`},
		{`https://user:` + fakeDBPassword + `@host:5432/x?y=1`, `https://user:[REDACTED:url-credentials:`, `]@host:5432/x?y=1`},
	}
	for _, tc := range cases {
		out, _, _ := plain().String(tc.in)
		if strings.Contains(out, fakeDBPassword) || !strings.HasPrefix(out, tc.prefix) || !strings.HasSuffix(out, tc.suffix) {
			t.Fatalf("authority password only: %q -> %q", tc.in, out)
		}
	}
}

func TestEnvAssignmentDoesNotWrapURLCredentialsMarker(t *testing.T) {
	in := `PASSWORD=postgres://u:` + fakeDBPassword + `@host/db`
	out, hits, _ := plain().String(in)
	if strings.Contains(out, fakeDBPassword) {
		t.Fatalf("secret survived: %s", out)
	}
	if markerCount(out) != 1 || strings.Contains(out, "[REDACTED:[REDACTED") || strings.Contains(out, ":[REDACTED:env-secret-assignment:") {
		t.Fatalf("want one owning url-credentials marker, got: %s", out)
	}
	if !strings.HasPrefix(out, `PASSWORD=postgres://u:[REDACTED:url-credentials:`) || !strings.HasSuffix(out, `]@host/db`) {
		t.Fatalf("URL structure around the password must survive: %s", out)
	}
	if len(hits) != 1 || hits[0].Rule != "url-credentials" {
		t.Fatalf("want exactly one url-credentials hit, got %v", hits)
	}
}

func TestEnvAssignmentDoesNotWrapJSONSecretFieldMarker(t *testing.T) {
	cases := []string{
		`DB_SECRET='{"password":"` + fakeDBPassword + `"}'`,
		`export DB_SECRET="{\"password\":\"` + fakeDBPassword + `\"}"`,
		`DB_SECRET={"password":"` + fakeDBPassword + `"}`,
	}
	for _, in := range cases {
		out, _, _ := plain().String(in)
		if strings.Contains(out, fakeDBPassword) {
			t.Fatalf("secret survived: %q -> %q", in, out)
		}
		if markerCount(out) != 1 || !strings.Contains(out, "[REDACTED:json-secret-field:") {
			t.Fatalf("want one owning json-secret-field marker: %q -> %q", in, out)
		}
		if !strings.HasPrefix(out, strings.SplitN(in, "=", 2)[0]+"=") {
			t.Fatalf("assignment key must survive: %q -> %q", in, out)
		}
	}
}

func TestEnvAssignmentStillOwnsPlainValues(t *testing.T) {
	in := `export API_TOKEN="` + fakeProviderKey + `"`
	out, hits, _ := plain().String(in)
	if strings.Contains(out, fakeProviderKey) || len(hits) != 1 || hits[0].Rule != "env-secret-assignment" {
		t.Fatalf("plain assignment must stay with env-secret-assignment: %s %v", out, hits)
	}
}

func TestGapRulesRoundTwoIdempotent(t *testing.T) {
	inputs := []string{
		`{"password":"` + r2Head + `\"` + r2Tail + `"}`,
		`PASSWORD=postgres://u:` + fakeDBPassword + `@host/db`,
		`DB_SECRET='{"password":"` + fakeDBPassword + `"}'`,
	}
	for _, in := range inputs {
		once, _, _ := plain().String(in)
		twice, hits, _ := plain().String(once)
		if once != twice || len(hits) != 0 {
			t.Fatalf("not idempotent: %q -> %q -> %q (%v)", in, once, twice, hits)
		}
	}
}
