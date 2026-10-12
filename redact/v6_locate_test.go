// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package redact

import "testing"

func TestV6PrefixDecisions(t *testing.T) {
	for _, tc := range []struct {
		name, prefix   string
		accepted, code bool
	}{
		{"code-suffix-rejected", "sampled_token_ids = ", false, false},
		{"code-head", " db_password = ", true, true},
		{"env-suffix", "API_KEY_v2=", true, false},
		{"escaped-env", `\nAPI_KEY=`, true, false},
		{"dotted-code-head", "self.token=", true, true},
		{"first-family", "secret_TOKEN_IDS=", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := assignPrefixFinder(tc.prefix + "Ab3xyz9Q")(0)
			if (m != nil) != tc.accepted {
				t.Fatal("prefix decision mismatch")
			}
			if m != nil && (m[1] != len(tc.prefix) || (m[2] != 0) != tc.code) {
				t.Fatal("prefix metadata mismatch")
			}
		})
	}
	for _, tc := range []struct {
		prefix   string
		accepted bool
	}{
		{"--token=", true}, {" --my_token=", true}, {`\n--token=`, true},
		{"foo--token=", false}, {"---token=", false}, {"262144-token ", false},
	} {
		m := cliPrefixFinder(tc.prefix + "Ab3xyz9Q")(0)
		if (m != nil) != tc.accepted {
			t.Fatal("CLI prefix decision mismatch")
		}
	}
}

func TestV6BareReferenceScope(t *testing.T) {
	for _, value := range []string{"str(process.env.TOKEN)", "config.get(", "$(cat", "ENV[", "self.token", "System.getenv<String>()"} {
		if !assignBareKept("API_KEY="+value, []int{0, 8, 0, 0, 7}, 8, 8+len(value), value) {
			t.Fatal("reference not kept for env-style key")
		}
	}
	if assignBareKept("API_KEY=abc(def)", []int{0, 8, 0, 0, 7}, 8, 16, "abc(def)") {
		t.Fatal("opaque env-style literal kept")
	}
	if !assignBareKept("api_key=abc(def)", []int{0, 8, 1, 0, 7}, 8, 16, "abc(def)") {
		t.Fatal("code-cased call not kept")
	}
}
