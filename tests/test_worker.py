# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Malformed real-process wire tests; synthetic data only."""
import json
import os
from pathlib import Path
import selectors
import struct
import subprocess
import unittest

from caviar_redact.client import Client, REQUEST_CAP


class WorkerTests(unittest.TestCase):
    def refuse(self, payload, declared=None):
        worker = Client(bytes(range(32)))._artifact_dir() / "caviar-redact-worker"
        proc = subprocess.Popen([str(worker)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env={"GOMAXPROCS": "1"})
        frame = struct.pack(">Q", len(payload) if declared is None else declared) + payload
        try:
            output, diagnostics = proc.communicate(frame, timeout=2)
            self.assertEqual(output, b"")
            self.assertEqual(diagnostics, b"")
            self.assertNotEqual(proc.returncode, 0)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()

    def test_no_partial_output_for_malformed_init(self):
        for payload in (b'{"kind":"init","kind":"init"}', b'"\\ud800"', b'"\xff"',
                        b'{"protocol":NaN}', b'{} {}', b'{}'):
            self.refuse(payload)

    def test_truncated_and_oversize_frame_refuse(self):
        self.refuse(b"{}", declared=10)
        self.refuse(b"", declared=REQUEST_CAP + 1)

    def test_stream_identity_sequence_refuse_before_result(self):
        with Client(bytes(range(32))) as client:
            client.string("ordinary sentence")
            proc = client._proc
            bad = {"kind": "redact", "generation": client._generation, "id": "99",
                   "mode": "text", "text": "ordinary sentence"}
            data = json.dumps(bad).encode()
            os.write(proc.stdin.fileno(), struct.pack(">Q", len(data)) + data)
            proc.wait(timeout=2)
            self.assertNotEqual(proc.returncode, 0)
            self.assertEqual(os.read(proc.stdout.fileno(), 8), b"")


if __name__ == "__main__":
    unittest.main()
