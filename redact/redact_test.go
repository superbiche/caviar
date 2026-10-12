// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package redact

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Token-shaped fixtures are concatenation-split so no source blob carries a
// contiguous secret shape: GitHub push protection blocked the v0.7.0 public
// push on the Slack fixture, and downstream scanners (trufflehog, forks' CI)
// match the same shapes. Compile-time folding hands the redactor the exact
// same runtime strings. AKIAIOSFODNN7EXAMPLE stays literal — it is AWS's
// canonical documentation key, allowlisted by scanners.
const fakePEM = "-----BEGIN RSA PRIVATE " + "KEY-----\nMIIEfakefakefakefake\nfakefakefake==\n-----END RSA PRIVATE " + "KEY-----"

func plain() *Redactor { return New(nil) }

func TestStringRedactsKnownShapes(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		rule   string
		secret string
	}{
		{"pem", "before\n" + fakePEM + "\nafter", "pem-block", fakePEM},
		{"jwt", "token eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9P", "jwt", "eyJhbGci"},
		{"aws", "key AKIAIOSFODNN7EXAMPLE here", "aws-access-key", "AKIAIOSFODNN7EXAMPLE"},
		{"openai", "use sk-" + "abcdefghijklmnopqrstuvwxyz123456", "openai-key", "sk-" + "abcdefghijklmnop"},
		{"github", "push ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789", "github-token", "ghp_"},
		{"github-pat", "pat github_pat_" + "11ABCDEFG0abcdefghijklmnop", "github-fine-grained-pat", "github_pat_" + "11ABCDEFG0"},
		{"slack", "hook xoxb-" + "123456789012-abcdefghijklmnop", "slack-token", "xoxb-"},
		{"bearer", `curl -H "Authorization: Bearer supersecrettoken123"`, "bearer-header", "supersecrettoken123"},
		{"env", "DATABASE_PASSWORD=hunter2hunter2", "env-secret-assignment", "hunter2hunter2"},
		{"env-export", "export HL3_QWEN_API_KEY=verysecretvalue99", "env-secret-assignment", "verysecretvalue99"},
		{"env-lowercase", "db_password=lowersecret42x", "env-secret-assignment", "lowersecret42x"},
		{"env-quoted-spaces", `APP_SECRET="my secret with spaces"`, "env-secret-assignment", "my secret with spaces"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, hits, _ := plain().String(tc.in)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("secret survived redaction: %s", out)
			}
			if !strings.Contains(out, "[REDACTED:"+tc.rule+":") {
				t.Fatalf("missing %s marker in: %s", tc.rule, out)
			}
			if len(hits) == 0 {
				t.Fatalf("no hits reported")
			}
		})
	}
}

func TestStringRedactsLetterboxTokensWholly(t *testing.T) {
	// The contract pattern ends in a negative lookahead the Go port cannot
	// compile, so the equivalence claim — RE2's greedy class takes the maximal
	// run — is what these cases prove: a body ending in `-` must be consumed
	// whole, leaving no tail beside the marker.
	whole := regexp.MustCompile(`^use \[REDACTED:liaison-letterbox-token:[0-9a-f]{8}\] now$`)
	for _, tc := range []struct{ name, token string }{
		{"20-char body", "lbx1_" + "AbCdEfGhIjKlMnOpQrSt"},
		{"body ending in dash", "lbx1_" + "AbCdEfGhIjKlMnOpQrS-"},
		{"body ending in underscore", "lbx1_" + "AbCdEfGhIjKlMnOpQrS_"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, hits, _ := plain().String("use " + tc.token + " now")
			if !whole.MatchString(out) {
				t.Fatalf("token not consumed whole: %q", out)
			}
			if len(hits) != 1 || hits[0].Rule != "liaison-letterbox-token" || hits[0].Count != 1 {
				t.Fatalf("unexpected hits: %v", hits)
			}
		})
	}

	t.Run("unicode left boundary follows Python (no boundary, kept)", func(t *testing.T) {
		// `\b` is evaluated with Python's Unicode word class (contract row 8
		// is the reference module's pattern): a token glued to an accented
		// letter has NO boundary before it and stays readable in both
		// implementations; a space before it is a boundary.
		in := "é" + "lbx1_" + "AbCdEfGhIjKlMnOpQrSt"
		out, hits, _ := plain().String(in)
		if out != in || len(hits) != 0 {
			t.Fatalf("no Python boundary before the token: must be kept, got %q %v", out, hits)
		}
		out, hits, _ = plain().String("é " + "lbx1_" + "AbCdEfGhIjKlMnOpQrSt")
		if len(hits) != 1 || hits[0].Rule != "liaison-letterbox-token" {
			t.Fatalf("space boundary before the token must redact: %q %v", out, hits)
		}
	})

	t.Run("19-char body is not a token", func(t *testing.T) {
		in := "use " + "lbx1_" + "AbCdEfGhIjKlMnOpQrS" + " now"
		out, hits, _ := plain().String(in)
		if out != in {
			t.Fatalf("below-threshold body was redacted: %q -> %q", in, out)
		}
		if hits != nil {
			t.Fatalf("below-threshold body reported hits: %v", hits)
		}
	})
}

func TestStringKeepsBearerPrefixReadable(t *testing.T) {
	out, _, _ := plain().String("Authorization: Bearer topsecretbearer99")
	if !strings.Contains(out, "Authorization: Bearer [REDACTED:bearer-header:") {
		t.Fatalf("bearer prefix should survive: %s", out)
	}
}

func TestExemptionsSurvive(t *testing.T) {
	for _, in := range []string{
		"DATABASE_PASSWORD=op://Vault/db/password",
		"API_TOKEN=${SOME_TEMPLATE_VAR}",
		"MY_SECRET=<your-secret-here>",
		"AWS_SECRET_ACCESS_KEY=changeme-later",
	} {
		out, hits, _ := plain().String(in)
		if out != in {
			t.Fatalf("exempt value was redacted: %q -> %q", in, out)
		}
		if len(hits) != 0 {
			t.Fatalf("exempt value reported hits: %v", hits)
		}
	}
}

func TestRedactionIsIdempotent(t *testing.T) {
	r := plain()
	once, _, _ := r.String("PASSWORD=verysecret123")
	twice, hits, _ := r.String(once)
	if twice != once {
		t.Fatalf("second pass changed output: %q -> %q", once, twice)
	}
	if len(hits) != 0 {
		t.Fatalf("second pass reported hits: %v", hits)
	}
}

func TestMarkerIsStablePerSecret(t *testing.T) {
	r := plain()
	a, _, _ := r.String("TOKEN_A=samesecretvalue1")
	b, _, _ := r.String("TOKEN_B=samesecretvalue1")
	suffix := func(s string) string {
		i := strings.LastIndex(s, ":")
		return s[i:]
	}
	if suffix(a) != suffix(b) {
		t.Fatalf("same secret produced different markers: %q vs %q", a, b)
	}
}

func TestKeyedMarkersResistDictionaryCorrelation(t *testing.T) {
	// The same secret must produce DIFFERENT markers under different keys
	// (unsalted SHA-256 prefixes of weak passwords are dictionary-recoverable),
	// and stable markers under the same key.
	k1, k2 := New([]byte("key-one-key-one-key-one-key-one!")), New([]byte("key-two-key-two-key-two-key-two!"))
	a, _, _ := k1.String("PASSWORD=weakpassword1")
	b, _, _ := k2.String("PASSWORD=weakpassword1")
	c, _, _ := k1.String("PASSWORD=weakpassword1")
	if a == b {
		t.Fatalf("different keys must produce different markers")
	}
	if a != c {
		t.Fatalf("same key must produce stable markers")
	}
	p, _, _ := plain().String("PASSWORD=weakpassword1")
	if p == a {
		t.Fatalf("keyed marker must differ from plain-hash marker")
	}
}

func TestLoadOrCreateKeyRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "redaction-key")
	k1, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("key length = %d, want 32", len(k1))
	}
	k2, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(k1) != string(k2) {
		t.Fatalf("key not stable across loads")
	}
}

func TestJSONWalksNestedValues(t *testing.T) {
	raw := json.RawMessage(`{"tool_input":{"file_path":"/x/.env","content":"API_KEY=deepnestedsecret1"},"list":["AKIAIOSFODNN7EXAMPLE"],"n":3}`)
	out, hits, _ := plain().JSON(raw)
	s := string(out)
	if strings.Contains(s, "deepnestedsecret1") || strings.Contains(s, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secret survived JSON redaction: %s", s)
	}
	if len(hits) != 2 {
		t.Fatalf("expected 2 rules hit, got %v", hits)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if v["n"].(float64) != 3 {
		t.Fatalf("non-string values must be untouched")
	}
}

func TestJSONRedactsSecretShapedKeys(t *testing.T) {
	// A secret used as a map KEY must not reach the store.
	raw := json.RawMessage(`{"payload":{"AKIAIOSFODNN7EXAMPLE":"seen at 3pm"}}`)
	out, hits, _ := plain().JSON(raw)
	if strings.Contains(string(out), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secret key survived: %s", string(out))
	}
	if !strings.Contains(string(out), "[REDACTED:aws-access-key:") {
		t.Fatalf("key marker missing: %s", string(out))
	}
	if len(hits) != 1 {
		t.Fatalf("expected key hit, got %v", hits)
	}
}

func TestJSONPreservesLargeIntegers(t *testing.T) {
	// float64 round-trips corrupt integers beyond 2^53: the
	// walk must decode with UseNumber so untouched numbers stay bit-exact
	// even when a sibling string is redacted.
	raw := json.RawMessage(`{"big":9007199254740993,"secret":"PASSWORD=verysecret123"}`)
	out, _, _ := plain().JSON(raw)
	if !strings.Contains(string(out), "9007199254740993") {
		t.Fatalf("large integer corrupted: %s", string(out))
	}
	if strings.Contains(string(out), "verysecret123") {
		t.Fatalf("secret survived: %s", string(out))
	}
}

func TestJSONCleanInputStaysByteIdentical(t *testing.T) {
	raw := json.RawMessage(`{"message":  "nothing secret here",   "n": 1}`)
	out, hits, _ := plain().JSON(raw)
	if string(out) != string(raw) {
		t.Fatalf("clean input was rewritten: %q -> %q", string(raw), string(out))
	}
	if hits != nil {
		t.Fatalf("clean input reported hits: %v", hits)
	}
}

func TestMergeHits(t *testing.T) {
	merged := MergeHits([]Hit{{Rule: "jwt", Count: 1}}, []Hit{{Rule: "jwt", Count: 2}, {Rule: "pem-block", Count: 1}})
	if len(merged) != 2 || merged[0].Rule != "jwt" || merged[0].Count != 3 {
		t.Fatalf("unexpected merge: %v", merged)
	}
}
