// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package redact

// Oracle for the two redact-v1 gaps:
// a bare value under a secret-named JSON field, and credentials embedded in a
// URL. Written before the rules so the implementation has a kill criterion.
// Fixtures are concatenation-split like the rest of this file set.

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	fakeProviderKey = "k9ZpQ2vX7mT4" + "nR8sW1yB6cD3fG5h" // 28 alnum chars, no known prefix
	fakeDBPassword  = "r71Ea2eSZZdbk7Dn" + "uMnGLNNo0n7vjlmM"
)

func TestStringRedactsJSONSecretFieldsInEscapedText(t *testing.T) {
	// Transcripts carry tool output as ONE string: the JSON inside is escaped
	// (`\"apiKey\":\"…\"`) and never reaches the structured walker. The string
	// rule must see through one or more escape levels.
	cases := []struct {
		name string
		in   string
	}{
		{"plain-json", `{"id":"conductor","options":{"apiKey":"` + fakeProviderKey + `"}}`},
		{"escaped-once", `"{\"id\":\"conductor\",\"options\":{\"apiKey\":\"` + fakeProviderKey + `\"}}"`},
		{"escaped-twice", `\\\"apiKey\\\":\\\"` + fakeProviderKey + `\\\"`},
		{"snake-case", `{"api_key": "` + fakeProviderKey + `"}`},
		{"spaced-colon", `{"apiKey" : "` + fakeProviderKey + `"}`},
		{"token-field", `{"token":"` + fakeProviderKey + `"}`},
		{"password-field", `{"password":"` + fakeDBPassword + `"}`},
		{"secret-suffix", `{"clientSecret":"` + fakeProviderKey + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, hits, _ := plain().String(tc.in)
			if strings.Contains(out, fakeProviderKey) || strings.Contains(out, fakeDBPassword) {
				t.Fatalf("secret survived: %s", out)
			}
			if !strings.Contains(out, "[REDACTED:json-secret-field:") {
				t.Fatalf("missing json-secret-field marker: %s", out)
			}
			if len(hits) != 1 || hits[0].Rule != "json-secret-field" || hits[0].Count != 1 {
				t.Fatalf("want exactly one json-secret-field hit, got %v", hits)
			}
		})
	}
}

func TestStringKeepsJSONFieldNameReadable(t *testing.T) {
	out, _, _ := plain().String(`{"apiKey":"` + fakeProviderKey + `"}`)
	if !strings.HasPrefix(out, `{"apiKey":"[REDACTED:json-secret-field:`) {
		t.Fatalf("field name and quoting must survive, value only redacted: %s", out)
	}
	if !strings.HasSuffix(out, `]"}`) {
		t.Fatalf("closing quote and brace must survive: %s", out)
	}
}

func TestJSONSecretFieldLeavesNonSecretFieldsAndShortValuesAlone(t *testing.T) {
	for _, in := range []string{
		`{"model":"claude-opus-5-5","apiKeyName":"REVEILLE_API_KEY"}`, // field names ARE the value here; name-like, not secret-like
		`{"apiKey":"short"}`,                                 // below the floor (8 under v5; 16 under v2)
		`{"apiKey":"{env:REVEILLE_API_KEY}"}`,                // OpenCode env reference — a pointer, not a value
		`{"apiKey":"${PROVIDER_KEY}"}`,                       // template
		`{"apiKey":"op://Vault/item/key"}`,                   // 1Password reference
		`{"apiKey":"<your-api-key-here>"}`,                   // placeholder
		`{"apiKey":"[REDACTED:json-secret-field:deadbeef]"}`, // already redacted
		`{"tokens":128,"max_tokens":4096}`,                   // numeric siblings named like secrets
	} {
		out, hits, _ := plain().String(in)
		if out != in {
			t.Fatalf("non-secret or exempt input changed: %q -> %q", in, out)
		}
		if len(hits) != 0 {
			t.Fatalf("non-secret input reported hits: %v for %q", hits, in)
		}
	}
}

func TestJSONWalkRedactsValueUnderSecretNamedKey(t *testing.T) {
	// Structured envelopes split key and value: String(value) alone has no
	// context, so the walker must be key-aware. Numbers stay bit-exact.
	raw := json.RawMessage(`{"provider":{"id":"litellm","options":{"apiKey":"` + fakeProviderKey + `","baseURL":"https://litellm.example/v1"},"limit":{"context":128000}}}`)
	out, hits, _ := plain().JSON(raw)
	s := string(out)
	if strings.Contains(s, fakeProviderKey) {
		t.Fatalf("secret survived JSON walk: %s", s)
	}
	if !strings.Contains(s, `"apiKey":"[REDACTED:json-secret-field:`) {
		t.Fatalf("value under apiKey must be a json-secret-field marker: %s", s)
	}
	if !strings.Contains(s, `"baseURL":"https://litellm.example/v1"`) {
		t.Fatalf("sibling non-secret field must survive: %s", s)
	}
	if !strings.Contains(s, `"context":128000`) {
		t.Fatalf("numbers must survive bit-exact: %s", s)
	}
	if len(hits) != 1 || hits[0].Rule != "json-secret-field" || hits[0].Count != 1 {
		t.Fatalf("want exactly one json-secret-field hit, got %v", hits)
	}
}

func TestJSONWalkKeepsEnvReferenceUnderSecretNamedKey(t *testing.T) {
	raw := json.RawMessage(`{"options":{"apiKey":"{env:REVEILLE_API_KEY}"}}`)
	out, hits, _ := plain().JSON(raw)
	if string(out) != string(raw) {
		t.Fatalf("env reference must stay byte-identical: %s", out)
	}
	if len(hits) != 0 {
		t.Fatalf("env reference reported hits: %v", hits)
	}
}

func TestStringRedactsURLCredentials(t *testing.T) {
	cases := []struct {
		name string
		in   string
		keep []string // fragments that must survive readable
	}{
		{"postgres", "DB=postgresql://fixturedb:" + fakeDBPassword + "@database-rw.example.invalid:5432/fixturedb", []string{"postgresql://fixturedb:", "@database-rw.example.invalid:5432/fixturedb"}},
		{"https-basic", "curl https://deploy:" + fakeDBPassword + "@registry.example/v2/", []string{"https://deploy:", "@registry.example/v2/"}},
		{"redis-no-user", "redis://:" + fakeDBPassword + "@cache.internal:6379/0", []string{"redis://:", "@cache.internal:6379/0"}},
		{"short-password", "amqp://guest:" + "hunter2" + "@broker/", []string{"amqp://guest:", "@broker/"}}, // URL context is unambiguous — no length floor
		{"in-json-string", `{"uri":"postgresql://fixturedb:` + fakeDBPassword + `@database-rw.example.invalid:5432/fixturedb"}`, []string{`{"uri":"postgresql://fixturedb:`, `@database-rw.example.invalid:5432/fixturedb"}`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, hits, _ := plain().String(tc.in)
			if strings.Contains(out, fakeDBPassword) || strings.Contains(out, "hunter2") {
				t.Fatalf("password survived: %s", out)
			}
			if !strings.Contains(out, "[REDACTED:url-credentials:") {
				t.Fatalf("missing url-credentials marker: %s", out)
			}
			for _, k := range tc.keep {
				if !strings.Contains(out, k) {
					t.Fatalf("fragment %q must survive readable: %s", k, out)
				}
			}
			if len(hits) != 1 || hits[0].Rule != "url-credentials" || hits[0].Count != 1 {
				t.Fatalf("want exactly one url-credentials hit, got %v", hits)
			}
		})
	}
}

func TestURLCredentialsLeaveReferencesAndPlainURLsAlone(t *testing.T) {
	for _, in := range []string{
		"postgresql://fixturedb:${PGPASSWORD}@database-rw.example.invalid:5432/fixturedb", // template
		"https://user:<password>@host/",                   // placeholder
		"https://redaction.example.invalid/v1/search?q=x", // no userinfo
		"https://host:8443/path",                          // port, not credentials
		"user@host:/srv/path",                             // scp-style, no scheme
		"see https://example.com/@handle/profile",         // @ in path
		"mailto:someone@example.com",                      // no authority
	} {
		out, hits, _ := plain().String(in)
		if out != in {
			t.Fatalf("plain or exempt URL changed: %q -> %q", in, out)
		}
		if len(hits) != 0 {
			t.Fatalf("plain or exempt URL reported hits: %v for %q", hits, in)
		}
	}
}

func TestURLCredentialsAndEnvAssignmentDoNotDoubleRedact(t *testing.T) {
	// The URL rule and assignment rule must not redact the same value twice.
	in := "DATABASE_URL=postgresql://fixturedb:" + fakeDBPassword + "@database-rw.example.invalid:5432/fixturedb"
	out, hits, _ := plain().String(in)
	if strings.Contains(out, fakeDBPassword) {
		t.Fatalf("password survived: %s", out)
	}
	if strings.Count(out, "[REDACTED:") != 1 {
		t.Fatalf("want exactly one marker, got: %s", out)
	}
	total := 0
	for _, h := range hits {
		total += h.Count
	}
	if total != 1 {
		t.Fatalf("want one hit in total, got %v", hits)
	}
}

func TestGapRulesAreIdempotentAndKeyed(t *testing.T) {
	r := New([]byte("0123456789abcdef0123456789abcdef"))
	in := `{"apiKey":"` + fakeProviderKey + `","uri":"postgresql://fixturedb:` + fakeDBPassword + `@h/db"}`
	once, hits1, _ := r.String(in)
	twice, hits2, _ := r.String(once)
	if once != twice {
		t.Fatalf("not idempotent:\n%s\n%s", once, twice)
	}
	if len(hits1) != 2 || len(hits2) != 0 {
		t.Fatalf("hits: first %v, second %v", hits1, hits2)
	}
	unkeyed, _, _ := plain().String(in)
	if unkeyed == once {
		t.Fatalf("keyed and unkeyed markers must differ")
	}
}
