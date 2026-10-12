// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

// caviar-redact-worker is a serial framed-stdio overlay on Caviar's core. It emits no diagnostics or caller data to stderr.
package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"strconv"

	"github.com/superbiche/caviar/internal/wire"
	"github.com/superbiche/caviar/redact"
)

const requestCap = 2 << 20
const responseCap = 8 << 20

// Release/source/corpus are build inputs from the reviewed provenance manifest.
var release string
var source string
var corpus string

func readFrame(r io.Reader) (map[string]any, error) {
	var h [8]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint64(h[:])
	if n == 0 || n > requestCap {
		return nil, wire.ErrInvalid
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	v, err := wire.Decode(b)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, wire.ErrInvalid
	}
	return m, nil
}
func writeFrame(w io.Writer, m map[string]any) error {
	b, err := json.Marshal(m)
	if err != nil || len(b) > responseCap {
		return wire.ErrInvalid
	}
	var h [8]byte
	binary.BigEndian.PutUint64(h[:], uint64(len(b)))
	for _, part := range [][]byte{h[:], b} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}
func fields(m map[string]any, names ...string) bool {
	if len(m) != len(names) {
		return false
	}
	for _, n := range names {
		if _, ok := m[n]; !ok {
			return false
		}
	}
	return true
}
func identity(g string) map[string]any {
	return map[string]any{"kind": "ready", "generation": g, "protocol": 1, "release": release, "rules": redact.RulesVersion, "source": source, "corpus": corpus}
}
func serve(r io.Reader, w io.Writer) error {
	init, err := readFrame(r)
	if err != nil {
		return err
	}
	if !fields(init, "kind", "generation", "protocol", "key", "plain") || init["kind"] != "init" || init["protocol"] != json.Number("1") {
		return wire.ErrInvalid
	}
	g, ok := init["generation"].(string)
	if !ok || len(g) != 32 {
		return wire.ErrInvalid
	}
	// Key bytes arrive only through stdin and are never emitted or logged.
	plain, ok := init["plain"].(bool)
	if !ok {
		return wire.ErrInvalid
	}
	var key []byte
	if plain {
		if init["key"] != nil {
			return wire.ErrInvalid
		}
	} else {
		encoded, ok := init["key"].(string)
		if !ok || len(encoded) > 87384 {
			return wire.ErrInvalid
		}
		key, err = base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(key) < 16 || len(key) > 65536 {
			return wire.ErrInvalid
		}
	}
	core := redact.New(key)
	if err = writeFrame(w, identity(g)); err != nil {
		return err
	}
	for seq := uint64(1); ; seq++ {
		m, err := readFrame(r)
		if err != nil {
			return err
		}
		if m["kind"] != "redact" || m["generation"] != g || m["id"] != strconv.FormatUint(seq, 10) {
			return wire.ErrInvalid
		}
		mode, ok := m["mode"].(string)
		if !ok {
			return wire.ErrInvalid
		}
		var result any
		var hits []redact.Hit
		switch mode {
		case "text":
			if !fields(m, "kind", "generation", "id", "mode", "text") {
				return wire.ErrInvalid
			}
			text, ok := m["text"].(string)
			if !ok {
				return wire.ErrInvalid
			}
			result, hits, err = core.String(text)
		case "value":
			if !fields(m, "kind", "generation", "id", "mode", "value") {
				return wire.ErrInvalid
			}
			result, hits, err = core.Value(m["value"])
		default:
			return wire.ErrInvalid
		}
		reply := map[string]any{"kind": "result", "generation": g, "id": m["id"]}
		if err != nil {
			reply["error"] = "core_failure"
		} else {
			if hits == nil {
				hits = []redact.Hit{}
			}
			reply["result"] = result
			reply["hits"] = hits
		}
		if err = writeFrame(w, reply); err != nil {
			return err
		}
	}
}
func run(r io.Reader, w io.Writer) (exitCode int) {
	// A panic is a failed generation, not an opportunity to expose a Go stack or
	// return an unredacted fallback. The parent detects EOF and reaps the child.
	defer func() {
		if recover() != nil {
			exitCode = 1
		}
	}()
	if serve(r, w) != nil {
		return 1
	}
	return 0
}
func main() {
	os.Exit(run(os.Stdin, os.Stdout))
}
