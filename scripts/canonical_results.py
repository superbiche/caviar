#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas
"""Stream pinned public-reference expectations, exclusively under CPython 3.14."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import random
import sys
from campaign_inputs import generate, materialize, TEXT_CAP
from prepare import prepare

ROOT = Path(__file__).resolve().parents[1]
SEED = 0xCA6106


def write_results(output, kind):
    if sys.implementation.name != 'cpython' or sys.version_info[:2] != (3, 14):
        raise ValueError('canonical oracle requires CPython 3.14')
    prepare()
    pins = json.loads((ROOT / 'docs/UPSTREAM.json').read_text())
    reference = ROOT / 'tmp/fixtures/redact-v7-reference.py'
    corpus = ROOT / pins['corpus_fixture']
    assert hashlib.sha256(reference.read_bytes()).hexdigest() == pins['reference_sha256']
    raw = corpus.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == pins['corpus_sha256']
    seeds = [json.loads(line) for line in raw.splitlines() if line]
    assert len(seeds) == pins['corpus_counts']['seeds']
    spec = importlib.util.spec_from_file_location('canonical_reference', reference)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    references = {False: module.Redactor(), True: module.Redactor(key=bytes(range(32)))}
    def cases():
        if kind == 'corpus':
            for row in seeds:
                text = materialize(row)
                modes = [('text', text)]
                if row.get('structured'):
                    modes.append(('value', json.loads(text)))
                for keyed in (False, True):
                    for mode, value in modes:
                        yield {'id': row['id'], 'mode': mode, 'keyed': keyed,
                               'data': value, 'bytes': len(text.encode()),
                               'max_ms': row.get('max_ms'), 'perf': row['tier'] == 'perf'}
        else:
            inputs = [r['input'] for r in seeds if r['tier'] == 'rules' and 'input' in r
                      and len(r['input'].encode()) <= TEXT_CAP - 4096]
            assert inputs
            rng = random.Random(SEED)
            for i in range(10000):
                text = generate(rng, i, inputs)
                tree = {'ordinary': [text, None, i], 'nested': {'token': text}}
                for keyed in (False, True):
                    for mode, data in [('text', text), ('value', tree)]:
                        yield {'id': i, 'mode': mode, 'keyed': keyed, 'data': data}
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation: never silently replace or reuse unbound expectations.
    count = 0
    with output.open('x', encoding='utf-8') as out:
        for row in cases():
            oracle = references[row['keyed']]
            try:
                expected = (oracle.string(row['data']) if row['mode'] == 'text'
                            else oracle.json_value(row['data']))
                row['expected'] = expected
                row['error'] = None
            except module.RedactDepthError:
                row['expected'] = None
                row['error'] = 'core_failure'
            out.write(json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n')
            count += 1
    expected_count = pins['corpus_counts']['parity_cases'] if kind == 'corpus' else 40000
    assert count == expected_count
    meta = {'kind': kind, 'records': count, 'oracle_python': platform.python_version(),
            'oracle_implementation': sys.implementation.name,
            'reference_sha256': pins['reference_sha256'], 'corpus_sha256': pins['corpus_sha256'],
            'seed': SEED if kind == 'differential' else None,
            'generator_sha256': hashlib.sha256((ROOT / 'scripts/campaign_inputs.py').read_bytes()).hexdigest(),
            'sha256': digest(output)}
    output.with_suffix('.meta.json').write_text(json.dumps(meta, indent=2) + '\n')
    print(json.dumps({'kind': kind, 'records': count, 'oracle_python': meta['oracle_python'], 'sha256': meta['sha256']}))


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--kind', choices=('corpus', 'differential'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    write_results(args.output, args.kind)
