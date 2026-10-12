// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas

package redact

import (
	"fmt"
	"os"
	"sort"
	"testing"
)

// TestPerfRows reports the per-row median (ms) of every perf seed, the row
// alone on the raw input — reference-module-style evidence (contract P4
// statement 2), never a gate. Enabled by MEMOIRE_REDACT_PERF_ROWS=1.
func TestPerfRows(t *testing.T) {
	if os.Getenv("MEMOIRE_REDACT_PERF_ROWS") == "" {
		t.Skip("set MEMOIRE_REDACT_PERF_ROWS=1")
	}
	seeds := loadCorpus(t)
	r := keyed()
	type cell struct {
		seed, rule string
		ms         float64
	}
	var cells []cell
	for i := range seeds {
		s := &seeds[i]
		if s.Tier != "perf" || s.Generator == nil || s.Generator.Count < 100000 && s.ID[len(s.ID)-4:] != "300k" {
			continue
		}
		in := s.text(t)
		for _, ru := range r.table {
			ru := ru
			ms := medianMsN(10, func() {
				counts := map[string]int{}
				o := newOwned(in)
				if ru.apply != nil {
					_, _ = ru.apply(in, counts, o)
				} else {
					_ = r.applyRegex(ru, in, counts, o)
				}
			})
			cells = append(cells, cell{s.ID, ru.id, ms})
		}
	}
	sort.Slice(cells, func(i, j int) bool { return cells[i].ms > cells[j].ms })
	for _, c := range cells[:60] {
		fmt.Printf("%-14s %-24s %7.1f ms\n", c.seed, c.rule, c.ms)
	}
}
