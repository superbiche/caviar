# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas
"""Canonical oracle isolation and byte/pin binding refusal checks."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from canonical_results import write_results
from qualify_compat import verify_oracle, ROOT


class CanonicalTests(unittest.TestCase):
    def test_target_minor_cannot_generate_canonical_results(self):
        for minor in (12, 13):
            with mock.patch('canonical_results.sys.version_info', (3, minor)):
                with self.assertRaisesRegex(ValueError, 'CPython 3.14'):
                    write_results(Path('unused'), 'corpus')

    def test_oracle_pins_and_runtime_fail_closed(self):
        pins = json.loads((ROOT / 'docs/UPSTREAM.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'oracle.jsonl'
            p.write_bytes(b'{}\n')
            meta = {'oracle_python': '3.14.8', 'oracle_implementation': 'cpython',
                    'reference_sha256': pins['reference_sha256'], 'corpus_sha256': pins['corpus_sha256'],
                    'generator_sha256': hashlib.sha256((ROOT / 'scripts/campaign_inputs.py').read_bytes()).hexdigest(),
                    'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'kind': 'corpus',
                    'records': pins['corpus_counts']['parity_cases']}
            def save(data):
                p.with_suffix('.meta.json').write_text(json.dumps(data))
            save(meta)
            self.assertEqual(verify_oracle(p, pins), meta)
            for field, bad in [('oracle_python', '3.13.15'), ('oracle_implementation', 'pypy'),
                               ('reference_sha256', '0'*64), ('corpus_sha256', '0'*64),
                               ('generator_sha256', '0'*64), ('records', 1), ('kind', 'other')]:
                save(dict(meta, **{field: bad}))
                with self.assertRaises(AssertionError):
                    verify_oracle(p, pins)
            save(meta)
            p.write_bytes(b'{"changed":true}\n')
            with self.assertRaises(AssertionError):
                verify_oracle(p, pins)
