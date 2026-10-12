#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas
"""Compare one installed interpreter to the streamed canonical 3.14 oracle."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import statistics
import sys
import time
import tomllib
from canonical_results import digest
from caviar_redact import Client, CaviarError
from caviar_redact.client import _manifest_identity

ROOT = Path(__file__).resolve().parents[1]
LINE_CAP = 16 * 1024 * 1024


def verify_oracle(path, pins):
    meta = json.loads(path.with_suffix('.meta.json').read_text())
    assert meta['oracle_python'].startswith('3.14.') and meta['oracle_implementation'] == 'cpython'
    assert meta['reference_sha256'] == pins['reference_sha256'] and meta['corpus_sha256'] == pins['corpus_sha256']
    assert meta['generator_sha256'] == digest(ROOT / 'scripts/campaign_inputs.py')
    assert meta['sha256'] == digest(path)
    kind = meta['kind']
    assert kind in ('corpus', 'differential')
    assert meta['records'] == (pins['corpus_counts']['parity_cases'] if kind == 'corpus' else 40000)
    return meta


def run(args):
    pins = json.loads((ROOT / 'docs/UPSTREAM.json').read_text())
    meta = verify_oracle(args.oracle, pins)
    kind = meta["kind"]
    package = Path(sys.modules['caviar_redact'].__file__).resolve().parent
    assert package.is_relative_to(ROOT / 'tmp/delivery-work/installed'), 'installed binding required'
    identity = _manifest_identity(json.loads((package / '_bin/manifest.json').read_text()))
    release = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version']
    assert importlib.metadata.version('caviar-redact') == identity['release'] == release
    wheel = ROOT / ('dist/caviar_redact-' + release + '-py3-none-linux_x86_64.whl')
    result = {'identity': identity, 'artifact_hashes': {n: digest(package / n) for n in
              ('__init__.py', 'client.py', 'pool.py', '_bin/caviar-redact-worker', '_bin/manifest.json')},
              'wheel_sha256': digest(wheel), 'reference_sha256': pins['reference_sha256'],
              'oracle': meta, 'python': platform.python_version(), 'platform': platform.platform(),
              'binding_path': str(package), 'samples_per_row': 30, 'warmups': 1,
              'cases': 0, 'mismatches': [], 'p4_rows': [], 'load_before': list(os.getloadavg())}
    clients = {False: Client(None, allow_plain=True), True: Client(bytes(range(32)))}
    labels = set()
    input_hash = hashlib.sha256()
    comparisons = 0
    try:
        with args.oracle.open('rb') as stream:
            while True:
                line = stream.readline(LINE_CAP + 1)
                if not line:
                    break
                assert len(line) <= LINE_CAP and line.endswith(b'\n'), 'oracle record exceeds cap'
                row = json.loads(line)
                label = {k: row[k] for k in ('id', 'mode', 'keyed')}
                key = tuple(label.values())
                assert key not in labels, 'duplicate oracle record'
                labels.add(key)
                if kind == 'differential' and row['mode'] == 'text' and row['keyed'] is False:
                    tree = {'ordinary': [row['data'], None, row['id']], 'nested': {'token': row['data']}}
                    input_hash.update(json.dumps([row['id'], row['data'], tree], ensure_ascii=True,
                                                separators=(',', ':')).encode() + b'\n')
                expected = row['error'] or (row['expected'][0], row['expected'][1])
                call = clients[row['keyed']].string if row['mode'] == 'text' else clients[row['keyed']].value
                def invoke():
                    try:
                        return call(row['data'])
                    except CaviarError as exc:
                        return exc.code
                actual = invoke()
                comparisons += 1
                if actual != expected:
                    result['mismatches'].append(label)
                    raise RuntimeError('installed oracle mismatch; values withheld')
                if kind == 'corpus' and row['perf']:
                    assert invoke() == expected, 'warmup mismatch'
                    durations = []
                    for _ in range(30):
                        start = time.perf_counter_ns()
                        actual = invoke()
                        durations.append((time.perf_counter_ns() - start) / 1e6)
                        assert actual == expected, 'timed mismatch'
                    median = statistics.median(durations)
                    result['p4_rows'].append(dict(label, bytes=row['bytes'], max_ms=row['max_ms'],
                        samples_ms=durations, median_ms=median, ratio=median / row['max_ms']))
    finally:
        for client in clients.values():
            client.close()
        result['load_after'] = list(os.getloadavg())
        result['cases'] = comparisons if kind == 'corpus' else comparisons // 4
        result['worst_ratio'] = max((r['ratio'] for r in result['p4_rows']), default=None)
        result['p4_over_budget'] = [{k: r[k] for k in ('id', 'mode', 'keyed', 'ratio')}
                                   for r in result['p4_rows'] if r['ratio'] > 1]
        if kind == 'differential':
            result.update(seed=0xCA6106, comparisons=comparisons, differences=result['mismatches'],
                          input_sha256=input_hash.hexdigest(), text_cap=65536, tree_depth_cap=32)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    assert comparisons == meta['records'] and not result['mismatches']
    if kind == 'corpus':
        assert len(result['p4_rows']) == pins['corpus_counts']['p4_rows'] and not result['p4_over_budget']
    print(json.dumps({'kind': kind, 'python': result['python'], 'comparisons': comparisons,
                      'mismatches': len(result['mismatches']), 'worst_ratio': result['worst_ratio']}))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--oracle', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    run(p.parse_args())
