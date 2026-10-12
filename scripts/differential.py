#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Bounded deterministic Go-worker/Python differential campaign, streamed."""
import argparse
import hashlib
import gzip
import importlib.util
import json
from pathlib import Path
import random
import sys
import time

from caviar_redact import Client, CaviarError
from caviar_redact.client import _manifest_identity

ROOT = Path(__file__).resolve().parents[1]
SEED = 0xCA6106
CASES = 10000
TEXT_CAP = 65536


from campaign_inputs import generate


def run(output, reference):
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14):
        raise ValueError("direct reference gate requires canonical CPython 3.14; use qualify_compat for targets")
    pins = json.loads((ROOT / "docs/UPSTREAM.json").read_text())
    reference = reference or ROOT / "tmp/fixtures/redact-v7-reference.py"
    assert hashlib.sha256(reference.read_bytes()).hexdigest() == pins["reference_sha256"], "reference mismatch"
    spec = importlib.util.spec_from_file_location("caviar_diff_reference", reference)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    package = Path(sys.modules["caviar_redact"].__file__).resolve().parent
    assert package.is_relative_to(ROOT / "tmp/delivery-work/installed"), "installed wheel required"
    identity = _manifest_identity(json.loads((package / "_bin/manifest.json").read_text()))
    key = bytes(range(32))
    clients = {False: Client(None, allow_plain=True), True: Client(key)}
    references = {False: module.Redactor(), True: module.Redactor(key=key)}
    rng = random.Random(SEED)
    corpus_raw = (ROOT / pins["corpus_fixture"]).read_bytes()
    if pins["corpus_format"] == "gzip-jsonl":
        corpus_raw = gzip.decompress(corpus_raw)
    assert hashlib.sha256(corpus_raw).hexdigest() == pins["corpus_sha256"]
    corpus_inputs = [row["input"] for line in corpus_raw.splitlines() if line
                     for row in (json.loads(line),)
                     if row["tier"] == "rules" and "input" in row and len(row["input"].encode()) <= TEXT_CAP - 4096]
    assert corpus_inputs
    stream_digest = hashlib.sha256()
    comparisons = 0
    differences = []
    started = time.monotonic()
    try:
        for i in range(CASES):
            if time.monotonic() - started > 1800:
                raise RuntimeError("campaign deadline")
            text = generate(rng, i, corpus_inputs)
            value = {"ordinary": [text, None, i], "nested": {"token": text}}
            stream_digest.update(json.dumps([i, text, value], ensure_ascii=True, separators=(",", ":")).encode() + b"\n")
            for keyed in (False, True):
                for mode, data in (("text", text), ("value", value)):
                    oracle = references[keyed]
                    try:
                        expected = oracle.string(data) if mode == "text" else oracle.json_value(data)
                    except module.RedactDepthError:
                        expected = "core_failure"
                    try:
                        actual = clients[keyed].string(data) if mode == "text" else clients[keyed].value(data)
                    except CaviarError as exc:
                        actual = exc.code
                    comparisons += 1
                    if actual != expected:
                        differences.append({"id": i, "mode": mode, "keyed": keyed})
                        # One bounded synthetic reproducer, private by default.
                        output.with_suffix(".repro.json").write_text(json.dumps({"id": i, "text": text, "value": value}))
                        raise RuntimeError("differential mismatch")
            if (i + 1) % 1000 == 0:
                print("Differential cases:", i + 1, flush=True)
    finally:
        for client in clients.values():
            client.close()
        result = {"seed": SEED, "cases": comparisons // 4, "comparisons": comparisons,
                  "differences": differences, "input_sha256": stream_digest.hexdigest(),
                  "identity": identity, "reference_sha256": pins["reference_sha256"],
                  "binding_path": str(package), "text_cap": TEXT_CAP, "tree_depth_cap": 32,
                  "artifact_hashes": {name: hashlib.sha256((package / name).read_bytes()).hexdigest()
                      for name in ("client.py", "__init__.py", "_bin/manifest.json", "_bin/caviar-redact-worker")}}
        output.write_text(json.dumps(result, indent=2) + "\n")
    assert comparisons == CASES * 4 and not differences


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reference", type=Path)
    args = parser.parse_args()
    run(args.output, args.reference)
