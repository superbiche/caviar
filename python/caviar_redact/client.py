# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Private framed pipes, caller-owned keys and bounded serial admission."""
import base64
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import struct
import subprocess
import threading
import time
import uuid

REQUEST_CAP = 2 << 20
RESPONSE_CAP = 8 << 20
PROTOCOL = 1


class CaviarError(Exception):
    """Only a stable failure code; never caller data or subprocess diagnostics."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise CaviarError("deadline")
    return left


def _domain(value, cap=REQUEST_CAP, deadline=None):
    """Bound depth and aggregate work before serializing JSON representations."""
    stack = [(iter((value,)), 0, False)]
    budget = 0
    while stack:
        if deadline is not None:
            _remaining(deadline)
        iterator, depth, keys = stack[-1]
        try:
            item = next(iterator)
        except StopIteration:
            stack.pop()
            continue
        if depth > 500 or (keys and type(item) is not str):
            raise CaviarError("unsupported_value")
        budget += 1
        if type(item) is str:
            if len(item) > cap:
                raise CaviarError("request_too_large")
            try:
                budget += len(item.encode("utf-8", "strict"))
            except UnicodeError:
                raise CaviarError("unsupported_value") from None
        elif item is None or type(item) is bool:
            pass
        elif type(item) is int:
            # Keep decimal conversion bounded even if a caller changes Python's
            # process-global integer-string limit.
            if item.bit_length() > 14000:
                raise CaviarError("unsupported_value")
            budget += max(1, item.bit_length() // 3)
        elif type(item) is float:
            if not math.isfinite(item):
                raise CaviarError("unsupported_value")
            budget += len(repr(item))
        elif type(item) is list:
            if len(item) > cap:
                raise CaviarError("request_too_large")
            stack.append((iter(item), depth + 1, False))
        elif type(item) is dict:
            if len(item) > cap:
                raise CaviarError("request_too_large")
            stack.append((iter(item), depth + 1, True))
            stack.append((iter(item.values()), depth + 1, False))
        else:
            raise CaviarError("unsupported_value")
        if budget > cap:
            raise CaviarError("request_too_large")


def _encode(value, deadline=None):
    """Encode a bounded init or an envelope around a domain-validated payload."""
    if deadline is not None:
        _remaining(deadline)
    data = json.dumps(value, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8", "strict")
    if deadline is not None:
        _remaining(deadline)
    if len(data) > REQUEST_CAP:
        raise CaviarError("request_too_large")
    return struct.pack(">Q", len(data)) + data


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise CaviarError("protocol")
        result[key] = value
    return result


def _bad_constant(_):
    raise CaviarError("protocol")


def _decode(data, deadline=None):
    try:
        value = json.loads(data.decode("utf-8", "strict"),
                           object_pairs_hook=_pairs, parse_constant=_bad_constant)
        # The wire rejects invalid Unicode in keys and values in both directions.
        _domain(value, RESPONSE_CAP, deadline)
        return value
    except CaviarError as exc:
        if exc.code == "deadline":
            raise
        raise CaviarError("protocol") from None
    except (ValueError, UnicodeError, RecursionError):
        raise CaviarError("protocol") from None


def _manifest_identity(manifest):
    try:
        package_version = importlib.metadata.version("caviar-redact")
    except importlib.metadata.PackageNotFoundError:
        raise CaviarError("artifact") from None
    identity = manifest.get("identity")
    upstream = manifest.get("upstream")
    if (type(identity) is not dict or type(upstream) is not dict
            or set(identity) != {"protocol", "release", "rules", "source", "corpus"}
            or type(identity["protocol"]) is not int or identity["protocol"] != PROTOCOL
            or identity["release"] != package_version):
        raise CaviarError("artifact")
    for name, pattern in (("rules", r"redact-v[0-9]+"),
                          ("source", r"[0-9a-f]{40}"), ("corpus", r"[0-9a-f]{64}")):
        if type(identity[name]) is not str or re.fullmatch(pattern, identity[name]) is None:
            raise CaviarError("artifact")
    if (identity["rules"] != upstream.get("rules")
            or upstream.get("owner") != "Caviar"
            or upstream.get("source_kind") != "git-tree"
            or upstream.get("source_path") != "redact"
            or identity["source"] != upstream.get("source")
            or identity["corpus"] != upstream.get("corpus_sha256")):
        raise CaviarError("artifact")
    return identity


class Client:
    """One persistent worker per trust domain. A busy call fails immediately.

    `string(text)` / `value(json_value)` return (result, list of {rule,count}).
    Errors raise CaviarError with no fallback. A later call can start a new
    generation after failure; the failed call is never replayed.
    """

    def __init__(self, key, *, timeout=5.0, allow_plain=False):
        if key is None:
            if allow_plain is not True:
                raise CaviarError("key_required")
        elif type(key) is not bytes or not 16 <= len(key) <= 65536:
            raise CaviarError("invalid_key")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise CaviarError("invalid_timeout")
        self._owner_pid = os.getpid()
        self._key = key
        self._timeout = float(timeout)
        self._lock = threading.Lock()
        self._proc = None
        self._generation = None
        self._seq = 0
        self._closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        # Closing never waits for the call lock. Killing the direct child also
        # wakes an active pipe exchange; that call cannot return an old result.
        self._closed = True
        self._stop()
        self._key = None

    def _stop(self):
        proc, self._proc = self._proc, None
        if proc is not None and os.getpid() != self._owner_pid:
            proc.stdin.close()
            proc.stdout.close()
            return
        if proc is not None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            # SIGKILL leaves no live worker; reap the direct child before reuse.
            proc.wait()
            proc.stdin.close()
            proc.stdout.close()
        self._generation = None
        self._seq = 0

    def _artifact_dir(self):
        return Path(__file__).resolve().parent / "_bin"

    def _start(self, deadline):
        if self._closed:
            raise CaviarError("closed")
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise CaviarError("unsupported_target")
        key = self._key
        directory = self._artifact_dir()
        try:
            manifest_path = directory / "manifest.json"
            if manifest_path.stat().st_size > 16384:
                raise CaviarError("artifact")
            manifest = _decode(manifest_path.read_bytes())
            identity = _manifest_identity(manifest)
            if (manifest.get("target") != "linux/amd64"
                    or manifest.get("goamd64") != "v1"):
                raise CaviarError("artifact")
            executable = directory / "caviar-redact-worker"
            if executable.is_symlink() or not executable.is_file():
                raise CaviarError("artifact")
            size = executable.stat().st_size
            if not 0 < size <= 32 << 20 or size != manifest.get("size"):
                raise CaviarError("artifact")
            digest = hashlib.sha256()
            with executable.open("rb") as stream:
                while chunk := stream.read(65536):
                    _remaining(deadline)
                    digest.update(chunk)
            if digest.hexdigest() != manifest.get("sha256"):
                raise CaviarError("artifact")
            _remaining(deadline)
            proc = subprocess.Popen([str(executable)], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    env={"GOMAXPROCS": "1"}, close_fds=True)
            self._proc = proc
            if self._closed:
                raise CaviarError("closed")
            os.set_blocking(proc.stdin.fileno(), False)
            os.set_blocking(proc.stdout.fileno(), False)
            self._generation = uuid.uuid4().hex
            self._seq = 0
            request = {"kind": "init", "protocol": 1, "generation": self._generation,
                       "key": None if key is None else base64.b64encode(key).decode("ascii"),
                       "plain": key is None}
            reply = self._exchange(proc, _encode(request, deadline), deadline)
            if reply != dict(identity, kind="ready", generation=self._generation):
                raise CaviarError("identity")
        except CaviarError:
            raise
        except (OSError, ValueError, TypeError, AttributeError):
            raise CaviarError("artifact") from None

    def _exchange(self, proc, frame, deadline):
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdin, selectors.EVENT_WRITE)
            offset = 0
            while offset < len(frame):
                if not selector.select(_remaining(deadline)):
                    raise CaviarError("deadline")
                try:
                    count = os.write(proc.stdin.fileno(), memoryview(frame)[offset:])
                except BlockingIOError:
                    continue
                if count == 0:
                    raise CaviarError("worker_failure")
                offset += count
            selector.unregister(proc.stdin)
            selector.register(proc.stdout, selectors.EVENT_READ)

            def read_exact(size):
                result = bytearray()
                while len(result) < size:
                    if not selector.select(_remaining(deadline)):
                        raise CaviarError("deadline")
                    try:
                        chunk = os.read(proc.stdout.fileno(), min(size - len(result), 65536))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        raise CaviarError("worker_failure")
                    result.extend(chunk)
                return result

            size = struct.unpack(">Q", read_exact(8))[0]
            if not 0 < size <= RESPONSE_CAP:
                raise CaviarError("protocol")
            reply = _decode(read_exact(size), deadline)
            _remaining(deadline)
            if type(reply) is not dict:
                raise CaviarError("protocol")
            return reply

    def string(self, text):
        if type(text) is not str:
            raise CaviarError("unsupported_value")
        return self._call("text", text)

    def value(self, value):
        return self._call("value", value)

    def _call(self, mode, value):
        if os.getpid() != self._owner_pid:
            raise CaviarError("forked_client")
        deadline = time.monotonic() + self._timeout
        if not self._lock.acquire(blocking=False):
            raise CaviarError("busy")
        try:
            if self._closed:
                raise CaviarError("closed")
            # Validate before starting a child or putting any data on its pipes.
            _domain(value, deadline=deadline)
            if self._proc is None:
                self._start(deadline)
            self._seq += 1
            identifier = str(self._seq)
            request = {"kind": "redact", "generation": self._generation,
                       "id": identifier, "mode": mode,
                       "text" if mode == "text" else "value": value}
            frame = _encode(request, deadline)
            _remaining(deadline)
            reply = self._exchange(self._proc, frame, deadline)
            base = {"kind": "result", "generation": self._generation, "id": identifier}
            if any(reply.get(k) != v for k, v in base.items()):
                raise CaviarError("protocol")
            if set(reply) == set(base) | {"error"} and reply["error"] == "core_failure":
                raise CaviarError("core_failure")
            if set(reply) != set(base) | {"result", "hits"}:
                raise CaviarError("protocol")
            result, hits = reply["result"], reply["hits"]
            if mode == "text" and type(result) is not str:
                raise CaviarError("protocol")
            if type(hits) is not list:
                raise CaviarError("protocol")
            seen = set()
            for hit in hits:
                if (type(hit) is not dict or set(hit) != {"rule", "count"}
                        or type(hit["rule"]) is not str or not hit["rule"]
                        or type(hit["count"]) is not int or hit["count"] <= 0
                        or hit["rule"] in seen):
                    raise CaviarError("protocol")
                seen.add(hit["rule"])
            _remaining(deadline)
            if self._closed:
                raise CaviarError("closed")
            return result, hits
        except CaviarError:
            self._stop()
            raise
        except (OSError, ValueError, TypeError, OverflowError, RecursionError):
            self._stop()
            raise CaviarError("worker_failure") from None
        except BaseException:
            self._stop()
            raise
        finally:
            self._lock.release()
