# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Real-worker lifecycle and lossless-representation tests, no fixture bodies."""
import math
from contextlib import contextmanager
import json
import hashlib
import os
from pathlib import Path
import signal
import shutil
import subprocess
import threading
import tempfile
import time
import unittest
from unittest import mock

from caviar_redact import Client, CaviarError
from caviar_redact.client import REQUEST_CAP

# Synthetic key is test-only, not a managed consumer key.
KEY = bytes(range(32))
REAL_POPEN = subprocess.Popen


@contextmanager
def spawns():
    processes = []
    def launch(*args, **kwargs):
        process = REAL_POPEN(*args, **kwargs)
        processes.append(process)
        return process
    with mock.patch("caviar_redact.client.subprocess.Popen", side_effect=launch):
        yield processes


class ClientTests(unittest.TestCase):
    def assert_code(self, code, action):
        with self.assertRaises(CaviarError) as raised:
            action()
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)

    def test_key_and_plain_are_explicit(self):
        self.assert_code("key_required", lambda: Client(None))
        self.assert_code("invalid_key", lambda: Client(b"short"))
        with Client(None, allow_plain=True) as client:
            self.assertEqual(client.string("ordinary sentence"), ("ordinary sentence", []))

    def test_numbers_and_json_types_roundtrip(self):
        value = {"n": 2**150, "small": 1e-200, "negative_zero": -0.0,
                 "a": [None, True, False, 1.25, "😀"], "o": {}}
        with Client(KEY) as client:
            result, hits = client.value(value)
            self.assertEqual(result, value)
            self.assertEqual(math.copysign(1, result["negative_zero"]), -1)
            self.assertEqual(hits, [])
            self.assertEqual(client.value(None), (None, []))

    def test_domain_refusals_never_spawn(self):
        with Client(KEY) as client, spawns() as spawned:
            for value in (float("nan"), float("inf"), {1: "x"}, ("x",), "\ud800", object(), 1 << 14001):
                self.assert_code("unsupported_value", lambda: client.value(value))
                self.assertIsNone(client._proc)
            self.assert_code("request_too_large", lambda: client.string("x" * (REQUEST_CAP + 1)))
            self.assertEqual(len(spawned), 0)

    def test_dead_worker_fails_call_then_later_restarts(self):
        with Client(KEY) as client:
            client.string("ordinary sentence")
            old = client._proc
            old.kill()
            old.wait()
            self.assert_code("worker_failure", lambda: client.string("ordinary sentence"))
            self.assertIsNone(client._proc)
            self.assertEqual(client.string("ordinary sentence"), ("ordinary sentence", []))
            self.assertNotEqual(old.pid, client._proc.pid)

    def test_stopped_worker_deadline_busy_and_reaping(self):
        with Client(KEY, timeout=0.15) as client:
            client.string("ordinary sentence")
            old = client._proc
            os.kill(old.pid, signal.SIGSTOP)
            result = []
            def blocked():
                try:
                    client.string("ordinary sentence")
                except CaviarError as exc:
                    result.append(exc.code)
            thread = threading.Thread(target=blocked)
            started = time.monotonic()
            thread.start()
            time.sleep(0.03)
            self.assert_code("busy", lambda: client.string("ordinary sentence"))
            thread.join(2)
            self.assertEqual(result, ["deadline"])
            self.assertLess(time.monotonic() - started, 1)
            self.assertIsNotNone(old.poll())
            self.assertEqual(client.string("ordinary sentence"), ("ordinary sentence", []))

    def test_write_backpressure_deadline(self):
        with Client(KEY, timeout=0.15) as client:
            client.string("ordinary sentence")
            old = client._proc
            os.kill(old.pid, signal.SIGSTOP)
            self.assert_code("deadline", lambda: client.string("ordinary sentence " * 20000))
            self.assertIsNotNone(old.poll())
            self.assertIsNone(client._proc)

    def test_initialization_deadline_and_key_pipe_custody(self):
        with Client(KEY, timeout=0.000001) as client:
            self.assert_code("deadline", lambda: client.string("ordinary sentence"))
            self.assertIsNone(client._proc)
        with Client(KEY) as client:
            client.string("ordinary sentence")
            args = Path(f"/proc/{client._proc.pid}/cmdline").read_bytes()
            environment = Path(f"/proc/{client._proc.pid}/environ").read_bytes()
            import base64
            self.assertNotIn(base64.b64encode(KEY), args + environment)
            self.assertNotIn(KEY, args + environment)

    def test_aggregate_size_refuses_shared_reference_expansion(self):
        value = ["x" * (1 << 20)] * 100000
        with Client(KEY, timeout=1) as client:
            started = time.monotonic()
            self.assert_code("request_too_large", lambda: client.value(value))
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertIsNone(client._proc)

    def test_float_expansion_is_bounded_before_spawn(self):
        with Client(KEY) as client, spawns() as spawned:
            self.assert_code("request_too_large", lambda: client.value(
                [1.2345678901234567e+200] * 100000))
            self.assertIsNone(client._proc)
            self.assertEqual(len(spawned), 0)

    def test_encoded_escaping_cap_refuses_without_sending_payload(self):
        with Client(KEY) as client:
            with spawns() as spawned:
                self.assert_code("request_too_large", lambda: client.string(
                    "\x00" * (REQUEST_CAP // 3)))
                self.assertEqual(len(spawned), 1)
            self.assertIsNone(client._proc)
            self.assertEqual(client.string("ordinary sentence"), ("ordinary sentence", []))

    def test_fork_child_refuses_and_close_preserves_parent_worker(self):
        with Client(KEY) as client:
            client.string("ordinary sentence")
            original = client._proc
            read_fd, write_fd = os.pipe()
            child_kill = mock.patch.object(original, "kill", side_effect=AssertionError(
                "fork child attempted to signal the parent's worker"))
            child_kill.start()
            try:
                pid = os.fork()
            except BaseException:
                child_kill.stop()
                os.close(read_fd)
                os.close(write_fd)
                raise
            if pid == 0:
                os.close(read_fd)
                outcome = b"unexpected"
                try:
                    try:
                        client.string("ordinary sentence")
                    except CaviarError as exc:
                        outcome = exc.code.encode("ascii")
                    client.close()
                    os.write(write_fd, outcome)
                finally:
                    os.close(write_fd)
                    os._exit(0)
            os.close(write_fd)
            try:
                outcome = os.read(read_fd, 64)
            finally:
                os.close(read_fd)
                _, exit_code = os.waitpid(pid, 0)
                child_kill.stop()
            self.assertEqual(exit_code, 0)
            self.assertEqual(outcome, b"forked_client")
            self.assertIsNone(original.poll())
            self.assertEqual(client.string("ordinary sentence"), ("ordinary sentence", []))
            self.assertIs(client._proc, original)

    def test_copied_artifact_tampering_refuses_before_spawn(self):
        directory = Path.cwd() / "tmp/delivery-work/test-artifacts"
        directory.mkdir(parents=True, exist_ok=True)
        for damage in ("digest", "size", "symlink", "version", "source", "owner", "source_kind", "source_path"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory(dir=directory) as tmp:
                with Client(KEY) as client:
                    copied = Path(tmp) / "_bin"
                    shutil.copytree(client._artifact_dir(), copied)
                    executable = copied / "caviar-redact-worker"
                    manifest_file = copied / "manifest.json"
                    if damage == "digest":
                        with executable.open("r+b") as stream:
                            stream.seek(executable.stat().st_size // 2)
                            byte = stream.read(1)
                            stream.seek(-1, 1)
                            stream.write(bytes([byte[0] ^ 1]))
                    elif damage == "size":
                        with executable.open("ab") as stream:
                            stream.write(b"x")
                        manifest = json.loads(manifest_file.read_text())
                        manifest["sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
                        manifest_file.write_text(json.dumps(manifest))
                    elif damage == "symlink":
                        target = copied / "worker-copy"
                        executable.rename(target)
                        executable.symlink_to(target.name)
                    else:
                        manifest = json.loads(manifest_file.read_text())
                        if damage in ("owner", "source_kind", "source_path"):
                            manifest["upstream"][damage] = "unsupported"
                        else:
                            manifest["identity"]["release" if damage == "version" else "source"] = (
                                "0.0.0" if damage == "version" else "0" * 40)
                        manifest_file.write_text(json.dumps(manifest))
                    with mock.patch.object(client, "_artifact_dir", return_value=copied), spawns() as spawned:
                        self.assert_code("artifact", lambda: client.string("ordinary sentence"))
                        self.assertEqual(len(spawned), 0)
                    self.assertIsNone(client._proc)

    def test_ready_identity_refusal_reaps_then_recovers(self):
        directory = Path.cwd() / "tmp/delivery-work/test-artifacts"
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=directory) as tmp, Client(KEY) as client:
            copied = Path(tmp) / "_bin"
            shutil.copytree(client._artifact_dir(), copied)
            manifest_file = copied / "manifest.json"
            manifest = json.loads(manifest_file.read_text())
            wrong_source = "0" * 40 if manifest["identity"]["source"] != "0" * 40 else "1" * 40
            manifest["identity"]["source"] = wrong_source
            manifest["upstream"]["source"] = wrong_source
            manifest_file.write_text(json.dumps(manifest))
            with mock.patch.object(client, "_artifact_dir", return_value=copied), spawns() as spawned:
                self.assert_code("identity", lambda: client.string("ordinary sentence"))
                self.assertEqual(len(spawned), 1)
            self.assertIsNone(client._proc)
            self.assertIsNotNone(spawned[0].poll())
            self.assertEqual(client.string("ordinary sentence"), ("ordinary sentence", []))
            self.assertNotEqual(client._proc.pid, spawned[0].pid)

    def test_unsupported_target_refuses_before_spawn(self):
        with Client(KEY) as client:
            with mock.patch("caviar_redact.client.platform.machine", return_value="aarch64"), spawns() as spawned:
                self.assert_code("unsupported_target", lambda: client.string("ordinary sentence"))
                self.assertEqual(len(spawned), 0)
            self.assertIsNone(client._proc)

    def test_keyboard_cancellation_discards_generation(self):
        with Client(KEY) as client:
            client.string("ordinary sentence")
            old = client._proc
            with mock.patch.object(client, "_exchange", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    client.string("ordinary sentence")
            self.assertIsNotNone(old.poll())
            self.assertIsNone(client._proc)
            self.assertEqual(client.string("ordinary sentence"), ("ordinary sentence", []))

    def test_near_cap_record_is_complete(self):
        text = "ordinary sentence " * 110000
        with Client(KEY) as client:
            clean, hits = client.string(text)
            self.assertTrue(clean == text, "near-cap text changed or was truncated")
            self.assertEqual(hits, [])

    def test_core_depth_refusal_reaps_without_result(self):
        text = '{"secret":' * 514 + '"synthetic-value"' + '}' * 514
        with Client(KEY) as client:
            self.assert_code("core_failure", lambda: client.string(text))
            self.assertIsNone(client._proc)
            self.assertEqual(client.string("ordinary sentence"), ("ordinary sentence", []))

    def test_invalid_response_discards_real_generation(self):
        for damage in ("identity", "type", "hits"):
            with Client(KEY) as client:
                client.string("ordinary sentence")
                old = client._proc
                reply = {"kind": "result", "generation": client._generation,
                         "id": str(client._seq + 1), "result": "ordinary sentence", "hits": []}
                if damage == "identity":
                    reply["generation"] = "foreign"
                elif damage == "type":
                    reply["result"] = None
                else:
                    reply["hits"] = [{"rule": "any", "count": True}]
                with mock.patch.object(client, "_exchange", return_value=reply):
                    self.assert_code("protocol", lambda: client.string("ordinary sentence"))
                self.assertIsNotNone(old.poll())
                self.assertIsNone(client._proc)

    def test_close_cancels_and_prevents_reuse(self):
        client = Client(KEY)
        client.string("ordinary sentence")
        old = client._proc
        os.kill(old.pid, signal.SIGSTOP)
        result = []
        def blocked():
            try:
                client.string("ordinary sentence")
            except CaviarError as exc:
                result.append(exc.code)
        thread = threading.Thread(target=blocked)
        thread.start()
        time.sleep(0.03)
        client.close()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(result), 1)
        self.assertIsNotNone(old.poll())
        self.assert_code("closed", lambda: client.string("ordinary sentence"))

    def test_bad_identity_and_frame_reap_real_worker(self):
        with Client(KEY) as client:
            with mock.patch("caviar_redact.client.PROTOCOL", 999):
                self.assert_code("artifact", lambda: client.string("ordinary sentence"))
            self.assertIsNone(client._proc)
            client.string("ordinary sentence")
            old = client._proc
            with mock.patch("caviar_redact.client.RESPONSE_CAP", 1):
                self.assert_code("protocol", lambda: client.string("ordinary sentence"))
            self.assertIsNotNone(old.poll())
            self.assertEqual(client.string("ordinary sentence"), ("ordinary sentence", []))

    def test_missing_artifact_fail_closed(self):
        with Client(KEY) as client:
            with mock.patch.object(client, "_artifact_dir", return_value=Path("/nonexistent/caviar")):
                self.assert_code("artifact", lambda: client.string("ordinary sentence"))


if __name__ == "__main__":
    unittest.main()
