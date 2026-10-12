// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package redact

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
)

// TestDifferentialDump is the Go half of the Go-vs-Python differential
// (contract §Reference implementation: the two reference implementations are
// compared on the corpus and on mutated inputs). Gated by
// CAVIAR_REDACT_DIFF_IN (JSONL of {"id","text"}) and CAVIAR_REDACT_DIFF_OUT:
// writes {"id","out","hits","err"} per input under the plain Redactor.
// A native-dump consumer can compare the same inputs against Python. The
// installed-binding campaign in scripts/differential.py instead exercises
// this core through the actual packaged worker in both key modes.
func TestDifferentialDump(t *testing.T) {
	in, out := os.Getenv("CAVIAR_REDACT_DIFF_IN"), os.Getenv("CAVIAR_REDACT_DIFF_OUT")
	if in == "" || out == "" {
		t.Skip("set CAVIAR_REDACT_DIFF_IN and CAVIAR_REDACT_DIFF_OUT")
	}
	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	r := New(nil)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<22), 1<<22)
	n := 0
	for sc.Scan() {
		var rec struct {
			ID   string `json:"id"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		res, hits, rerr := r.String(rec.Text)
		o := map[string]any{"id": rec.ID, "out": res, "hits": hits}
		if rerr != nil {
			o["err"] = rerr.Error()
		}
		if err := enc.Encode(o); err != nil {
			t.Fatal(err)
		}
		n++
	}
	t.Logf("%d inputs dumped", n)
}
