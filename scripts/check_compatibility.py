#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas
"""Require complete, artifact-bound installed qualification for all three minors."""
import hashlib
import json
from pathlib import Path
import statistics
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def verify():
    pins = json.loads((ROOT / 'docs/UPSTREAM.json').read_text())
    release = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version']
    matrix = json.loads((ROOT / 'docs/compatibility-results.json').read_text())
    assert release == matrix['release'] == '0.3.1'
    assert set(matrix['targets']) == {'3.12', '3.13', '3.14'}
    current_oracles = matrix['current_oracles']
    assert set(current_oracles) == {'corpus', 'differential'}
    for kind, current in current_oracles.items():
        assert current['kind'] == kind
        assert current['oracle_python'].startswith('3.14.') and current['oracle_implementation'] == 'cpython'
        assert current['reference_sha256'] == pins['reference_sha256'] and current['corpus_sha256'] == pins['corpus_sha256']
        assert current['generator_sha256'] == hashlib.sha256((ROOT / 'scripts/campaign_inputs.py').read_bytes()).hexdigest()
    corpus_oracles, diff_oracles, input_streams = set(), set(), set()
    for minor, files in matrix['targets'].items():
        for kind in ('qualification', 'differential'):
            filename = files[kind]['path']
            assert filename == 'docs/' + kind + '-' + minor + '.json', 'unexpected receipt path'
            data = (ROOT / filename).read_bytes()
            assert hashlib.sha256(data).hexdigest() == files[kind]['sha256']
            evidence = json.loads(data)
            assert evidence['python'].startswith(minor + '.')
            assert 'tmp/delivery-work/installed/' in evidence['binding_path']
            assert evidence['identity'] == {'protocol': 1, 'release': release, 'rules': pins['rules'],
                                             'source': pins['source'], 'corpus': pins['corpus_sha256']}
            assert evidence['reference_sha256'] == pins['reference_sha256']
            oracle = evidence['oracle']
            assert oracle['oracle_python'].startswith('3.14.') and oracle['oracle_implementation'] == 'cpython'
            assert oracle['reference_sha256'] == pins['reference_sha256'] and oracle['corpus_sha256'] == pins['corpus_sha256']
            current = current_oracles['corpus' if kind == 'qualification' else 'differential']
            assert all(oracle[field] == current[field] for field in current if field != 'generator_sha256'), 'oracle expectation stream changed'
            for name, expected in evidence['artifact_hashes'].items():
                assert hashlib.sha256((ROOT / 'python/caviar_redact' / name).read_bytes()).hexdigest() == expected
            assert evidence['wheel_sha256'] == matrix['wheel_sha256']
            if kind == 'qualification':
                corpus_oracles.add(oracle['sha256'])
                assert oracle['kind'] == 'corpus' and oracle['records'] == pins['corpus_counts']['parity_cases']
                assert evidence['cases'] == pins['corpus_counts']['parity_cases'] and not evidence['mismatches']
                rows = evidence['p4_rows']
                assert evidence['samples_per_row'] == 30 and evidence['warmups'] == 1
                assert len(rows) == pins['corpus_counts']['p4_rows'] and not evidence['p4_over_budget']
                assert len({(r['id'], r['mode'], r['keyed']) for r in rows}) == len(rows)
                assert all(len(r['samples_ms']) == 30 and r['median_ms'] == statistics.median(r['samples_ms'])
                           and 0 <= r['median_ms'] <= r['max_ms'] and r['ratio'] == r['median_ms'] / r['max_ms'] for r in rows)
            else:
                diff_oracles.add(oracle['sha256'])
                input_streams.add(evidence['input_sha256'])
                assert oracle['kind'] == 'differential' and oracle['records'] == 40000 and oracle['seed'] == 0xCA6106
                assert evidence['seed'] == 0xCA6106 and evidence['cases'] == 10000 and evidence['comparisons'] == 40000
                assert not evidence['differences']
        assert files['lifecycle']['exit'] == 0 and files['ready_identity_mutant']['exit'] != 0
    assert len(corpus_oracles) == len(diff_oracles) == len(input_streams) == 1
    wheel = ROOT / 'dist/caviar_redact-0.3.1-py3-none-linux_x86_64.whl'
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == matrix['wheel_sha256']
    print('Three-minor canonical-oracle installed compatibility evidence: PASS')


if __name__ == '__main__':
    verify()
