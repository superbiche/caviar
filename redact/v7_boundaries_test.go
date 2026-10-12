// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package redact

import (
	"reflect"
	"testing"
)

func TestV7NonSecretBoundaries(t *testing.T) {
	cases := []struct{ name, input string }{
		{"scope-operator", "Token::Ab3xyz9Q99"},
		{"mysql-semicolon", "mysql a;grep -pfoo"},
		{"mysql-pipe", "mysql a|grep -pfoo"},
		{"mysql-ampersand", "mysql a&grep -pfoo"},
		{"mysql-backtick", "mysql a `grep -pfoo`"},
	}
	for _, mode := range []struct {
		name string
		key  []byte
	}{{"plain", nil}, {"keyed", make([]byte, 32)}} {
		for _, tc := range cases {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				r := New(mode.key)
				out, hits, err := r.String(tc.input)
				if err != nil || out != tc.input || len(hits) != 0 {
					t.Fatal("non-secret boundary changed on text route")
				}
				input := map[string]any{"text": tc.input}
				value, hits, err := r.Value(input)
				if err != nil || !reflect.DeepEqual(value, input) || len(hits) != 0 {
					t.Fatal("non-secret boundary changed on structured route")
				}
			})
		}
	}
}
