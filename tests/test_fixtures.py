# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas
"""Refusal probes use synthetic text only, never full corpus fixture values."""
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from scripts import fixtures as f


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1])
        self.root = Path(self.temporary.name)
        self.raw = b'{"synthetic": "fixture"}\n'
        self.packed = gzip.compress(self.raw, mtime=0)
        self.encoded = f.encode(self.packed)
        self.artifact = self.root / 'fixture.b85'
        self.artifact.write_bytes(self.encoded)
        self.metadata = {'schema': 1, 'encoding': 'gzip-base85-v1',
                         'encoded_sha256': f.digest(self.encoded), 'decoded_sha256': f.digest(self.raw),
                         'decoded_bytes': len(self.raw), 'seeds': 1}

    def tearDown(self):
        self.temporary.cleanup()

    def test_roundtrip_and_no_overwrite(self):
        dest = self.root / 'tmp/fixture.jsonl'
        f.materialize(self.root, self.artifact, self.metadata, dest)
        self.assertEqual(dest.read_bytes(), self.raw)
        with self.assertRaises(FileExistsError):
            f.materialize(self.root, self.artifact, self.metadata, dest)

    def test_changed_encoding_and_decoded_pin_refuse(self):
        self.artifact.write_bytes(self.encoded + b'\n')
        with self.assertRaisesRegex(ValueError, 'encoded fixture hash'):
            f.verify(self.artifact, self.metadata)
        self.artifact.write_bytes(self.encoded)
        self.metadata['decoded_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'decoded fixture identity'):
            f.verify(self.artifact, self.metadata)

    def test_container_and_canonical_refusals(self):
        for flag in (4, 8, 16):
            changed = bytearray(self.packed)
            changed[3] = flag
            with self.assertRaisesRegex(ValueError, 'header/flags'):
                f.unpack(bytes(changed))
        with self.assertRaisesRegex(ValueError, 'single gzip member'):
            f.unpack(self.packed + gzip.compress(b'', mtime=0))
        with self.assertRaisesRegex(ValueError, 'noncanonical'):
            f.decode(self.encoded + b'\n')
        with mock.patch.object(f, 'CAP', 16):
            with self.assertRaisesRegex(ValueError, 'decoded size cap'):
                f.unpack(self.packed)

    def test_output_boundaries_and_symlink_refuse(self):
        for dest in (self.root / 'outside.jsonl', self.root / 'tmp/../../escape.jsonl'):
            with self.subTest(dest=dest.name), self.assertRaises(ValueError):
                f.materialize(self.root, self.artifact, self.metadata, dest)
        (self.root / 'tmp').symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            f.materialize(self.root, self.artifact, self.metadata, self.root / 'tmp/fixture.jsonl')


if __name__ == '__main__':
    unittest.main()

class PreparedFixtureReuseTests(unittest.TestCase):
    setUp = FixtureTests.setUp
    tearDown = FixtureTests.tearDown
    def test_reuse_refuses_parent_symlink(self):
        from scripts import prepare
        (self.root / 'docs').mkdir()
        (self.root / 'fixtures').mkdir()
        (self.root / 'docs/UPSTREAM.json').write_text(json.dumps({'corpus_sha256': f.digest(self.raw), 'reference_sha256': f.digest(self.raw)}))
        for name in ('corpus', 'reference'):
            (self.root / f'fixtures/redact-v7.{name}.b85').write_bytes(self.encoded)
            (self.root / f'fixtures/redact-v7.{name}.manifest.json').write_text(json.dumps(self.metadata))
        outside = self.root / 'other'
        outside.mkdir()
        (outside / 'redact-v7-corpus.jsonl').write_bytes(self.raw)
        (self.root / 'tmp').mkdir()
        (self.root / 'tmp/fixtures').symlink_to(outside, target_is_directory=True)
        with mock.patch.object(prepare, 'ROOT', self.root), self.assertRaisesRegex(ValueError, 'symlink'):
            prepare.prepare()
