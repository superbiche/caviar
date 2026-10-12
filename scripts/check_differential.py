#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Bind the complete differential campaign to the candidate payload."""
import hashlib
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
evidence = json.loads((ROOT / "docs/differential-results.json").read_text())
pins = json.loads((ROOT / "docs/UPSTREAM.json").read_text())
version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
assert evidence["seed"] == 0xCA6106 and evidence["cases"] == 10000 and evidence["comparisons"] == 40000
assert not evidence["differences"] and evidence["reference_sha256"] == pins["reference_sha256"]
assert evidence["identity"] == {"protocol": 1, "release": version, "rules": pins["rules"], "source": pins["source"], "corpus": pins["corpus_sha256"]}
assert "tmp/delivery-work/installed/" in evidence["binding_path"]
for name, expected in evidence["artifact_hashes"].items():
    assert hashlib.sha256((ROOT / "python/caviar_redact" / name).read_bytes()).hexdigest() == expected, "differential payload mismatch"
print("Exact installed-wheel deterministic differential evidence binding: PASS")
