// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package wire

import (
	"encoding/json"
	"testing"
)

func TestStrictRepresentation(t *testing.T) {
	bad := [][]byte{[]byte(`{"x":1,"x":2}`), []byte(`{"x":"\ud800"}`), []byte(`"\udc00"`), []byte(`{} {}`), []byte(`NaN`), {34, 255, 34}}
	for _, b := range bad {
		if _, err := Decode(b); err == nil {
			t.Fatal("accepted unsupported representation")
		}
	}
	v, err := Decode([]byte(`{"n":9007199254740993,"s":"\ud83d\ude00","a":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["n"] != json.Number("9007199254740993") || m["s"] != "😀" {
		t.Fatal("representation changed")
	}
}
