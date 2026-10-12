#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Bind retained installed-route results to the exact rebuilt client/worker."""
import hashlib
import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
evidence = json.loads((ROOT / "docs/qualification-results.json").read_text())
pins = json.loads((ROOT / "docs/UPSTREAM.json").read_text())
assert evidence["cases"] == pins["corpus_counts"]["parity_cases"] and not evidence["mismatches"], "binding parity failed"
assert evidence["samples_per_row"] == 30 and len(evidence["p4_rows"]) == pins["corpus_counts"]["p4_rows"], "incomplete P4"
assert not evidence["p4_over_budget"], "P4 over budget"
assert "tmp/delivery-work/installed/" in evidence["binding_path"], "binding was not installed"
for name, expected in evidence["artifact_hashes"].items():
    path = ROOT / "python/caviar_redact" / name
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, "qualified artifact mismatch"
release = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
assert evidence["identity"] == {"protocol": 1, "release": release, "rules": pins["rules"], "source": pins["source"], "corpus": pins["corpus_sha256"]}, "qualification identity mismatch"
assert evidence["reference_sha256"] == pins["reference_sha256"], "qualification reference mismatch"
assert len({(r["id"], r["mode"], r["keyed"]) for r in evidence["p4_rows"]}) == len(evidence["p4_rows"]), "duplicate P4 rows"
assert all(len(r["samples_ms"]) == 30 and r["median_ms"] <= r["max_ms"] for r in evidence["p4_rows"]), "incomplete or over-budget P4 row"
wheel = ROOT / "dist" / ("caviar_redact-" + release + "-py3-none-linux_x86_64.whl")
assert hashlib.sha256(wheel.read_bytes()).hexdigest() == evidence["wheel_sha256"], "wheel changed after qualification"
print("Exact installed-wheel full corpus/P4 evidence binding: PASS")
