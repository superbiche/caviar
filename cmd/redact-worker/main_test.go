// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

type panickingReader struct{}

func (panickingReader) Read([]byte) (int, error) { panic("synthetic reader failure") }

func TestPanicGuardFailsClosed(t *testing.T) {
	var out bytes.Buffer
	if run(panickingReader{}, &out) != 1 {
		t.Fatal("panic did not fail the generation")
	}
	if out.Len() != 0 {
		t.Fatal("panic emitted output")
	}
}

func TestOversizeBeforeAllocation(t *testing.T) {
	var h [8]byte
	binary.BigEndian.PutUint64(h[:], requestCap+1)
	if _, err := readFrame(bytes.NewReader(h[:])); err == nil {
		t.Fatal("accepted oversized frame")
	}
}
func TestPlainOnlyByExplicitInitAndOrderedRequest(t *testing.T) {
	var in, out bytes.Buffer
	if err := writeFrame(&in, map[string]any{"kind": "init", "protocol": 1, "generation": "01234567890123456789012345678901", "plain": true, "key": nil}); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(&in, map[string]any{"kind": "redact", "generation": "01234567890123456789012345678901", "id": "1", "mode": "value", "value": map[string]any{"n": 9007199254740993}}); err != nil {
		t.Fatal(err)
	}
	if err := serve(&in, &out); err != io.EOF {
		t.Fatal("unexpected stream termination")
	}
	ready, err := readFrame(&out)
	if err != nil || ready["kind"] != "ready" {
		t.Fatal("no handshake")
	}
	result, err := readFrame(&out)
	if err != nil || result["kind"] != "result" {
		t.Fatal("no result")
	}
	var invalid bytes.Buffer
	writeFrame(&invalid, map[string]any{"kind": "init", "protocol": 1, "generation": "01234567890123456789012345678901", "plain": false, "key": nil})
	if serve(&invalid, io.Discard) == nil {
		t.Fatal("missing key accepted")
	}
}
