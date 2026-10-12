# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas
"""Verify and materialize pinned public conformance inputs, offline."""
import json
from pathlib import Path
try:
    from .fixtures import materialize, verify, bounded_read
except ImportError:
    from fixtures import materialize, verify, bounded_read
ROOT = Path(__file__).resolve().parents[1]

def prepare():
    pins = json.loads((ROOT / 'docs/UPSTREAM.json').read_text())
    for name, output, pin in [('corpus', 'redact-v7-corpus.jsonl', 'corpus_sha256'),
                              ('reference', 'redact-v7-reference.py', 'reference_sha256')]:
        artifact = ROOT / f'fixtures/redact-v7.{name}.b85'
        metadata = json.loads((ROOT / f'fixtures/redact-v7.{name}.manifest.json').read_text())
        raw = verify(artifact, metadata)
        if metadata['decoded_sha256'] != pins[pin]:
            raise ValueError('published input pin mismatch')
        destination = ROOT / 'tmp/fixtures' / output
        for parent in (ROOT / 'tmp', ROOT / 'tmp/fixtures'):
            if parent.is_symlink():
                raise ValueError('fixture output symlink')
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or bounded_read(destination) != raw:
                raise ValueError('existing materialized input mismatch')
        else:
            materialize(ROOT, artifact, metadata, destination)
    print('Pinned corpus and reference materialized; no input values printed')

if __name__ == '__main__':
    prepare()
