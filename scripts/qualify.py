#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Installed-binding oracle and P4 gate; evidence contains metadata only."""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import sys
import time

from caviar_redact import Client, CaviarError
from caviar_redact.client import _manifest_identity

ROOT = Path(__file__).resolve().parents[1]


from campaign_inputs import materialize


def run(args):
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14):
        raise ValueError("direct reference gate requires canonical CPython 3.14; use qualify_compat for targets")
    provenance = json.loads((ROOT / "docs/UPSTREAM.json").read_text())
    counts = provenance["corpus_counts"]
    package_dir = Path(sys.modules["caviar_redact"].__file__).resolve().parent
    identity = _manifest_identity(json.loads((package_dir / "_bin/manifest.json").read_text()))
    reference_path = Path(args.reference) if args.reference else ROOT / "tmp/fixtures/redact-v7-reference.py"
    if hashlib.sha256(reference_path.read_bytes()).hexdigest() != provenance["reference_sha256"]:
        raise SystemExit("Reference hash mismatch")
    corpus_path = Path(args.corpus) if args.corpus else ROOT / provenance["corpus_fixture"]
    raw = corpus_path.read_bytes()
    if corpus_path.suffix == ".gz":
        raw = gzip.decompress(raw)
    if hashlib.sha256(raw).hexdigest() != identity["corpus"]:
        raise SystemExit("Corpus hash mismatch")
    seeds = [json.loads(line) for line in raw.splitlines() if line]
    if len(seeds) != counts["seeds"]:
        raise SystemExit("Corpus count mismatch")
    spec = importlib.util.spec_from_file_location("caviar_qualification_reference", reference_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    # Synthetic qualification key shared with Caviar's native corpus gate.
    key = bytes(range(32))
    references = {False: module.Redactor(), True: module.Redactor(key=key)}
    clients = {False: Client(None, allow_plain=True), True: Client(key)}
    artifacts = {name: hashlib.sha256((package_dir / name).read_bytes()).hexdigest()
                 for name in ("__init__.py", "client.py", "_bin/caviar-redact-worker", "_bin/manifest.json")}
    wheel = ROOT / "dist" / ("caviar_redact-" + identity["release"] + "-py3-none-linux_x86_64.whl")
    result = {"artifact_hashes": artifacts,
              "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
              "identity": identity, "reference_sha256": provenance["reference_sha256"],
              "python": platform.python_version(), "platform": platform.platform(),
              "binding_path": str(Path(sys.modules["caviar_redact"].__file__).resolve()),
              "samples_per_row": args.samples, "warmups": 1, "cases": 0,
              "mismatches": [], "p4_rows": [], "load_before": list(os.getloadavg())}
    try:
        for seed in seeds:
            text = materialize(seed)
            modes = [("text", text)]
            if seed.get("structured"):
                modes.append(("value", json.loads(text)))
            for keyed in (False, True):
                for mode, value in modes:
                    reference = references[keyed]
                    expected = reference.string(value) if mode == "text" else reference.json_value(value)
                    call = clients[keyed].string if mode == "text" else clients[keyed].value
                    actual = call(value)
                    result["cases"] += 1
                    label = {"id": seed["id"], "mode": mode, "keyed": keyed}
                    if actual != expected:
                        result["mismatches"].append(label)
                    # Existing P4 condition, measured on the full Python call.
                    if seed["tier"] == "perf" and args.samples:
                        durations = []
                        call(value)
                        for _ in range(args.samples):
                            start = time.perf_counter_ns()
                            output = call(value)
                            durations.append((time.perf_counter_ns() - start) / 1e6)
                            if output != expected:
                                result["mismatches"].append(dict(label, timed=True))
                        median = statistics.median(durations)
                        result["p4_rows"].append(dict(label, bytes=len(text.encode()),
                            max_ms=seed["max_ms"], samples_ms=durations,
                            median_ms=median, ratio=median / seed["max_ms"]))
            if result["cases"] % 50 < 4:
                print(f"Binding cases: {result['cases']}/{counts['parity_cases']}", flush=True)
    finally:
        for client in clients.values():
            client.close()
    result["load_after"] = list(os.getloadavg())
    result["p4_over_budget"] = [dict(id=r["id"], mode=r["mode"], keyed=r["keyed"], ratio=r["ratio"])
                               for r in result["p4_rows"] if r["ratio"] > 1]
    result["worst_ratio"] = max((r["ratio"] for r in result["p4_rows"]), default=None)
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("cases", "mismatches", "worst_ratio", "p4_over_budget")}))
    if result["cases"] != counts["parity_cases"] or result["mismatches"] or result["p4_over_budget"]:
        raise SystemExit(1)
    if args.samples and len(result["p4_rows"]) != counts["p4_rows"]:
        raise SystemExit("P4 row count mismatch")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", default=None)
    parser.add_argument("--corpus", default=None)
    parser.add_argument("--output", default=str(ROOT / "tmp/delivery-work/qualification.json"))
    parser.add_argument("--samples", type=int, choices=(0, 15, 30), default=30)
    run(parser.parse_args())
