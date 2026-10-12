# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Bounded concurrent admission over N serial workers, each its own process."""
import os
import threading
import time
from collections import deque

from .client import CaviarError, Client

SIZE_MIN = 1
SIZE_MAX = 32
ACQUIRE_MIN = 0.0
ACQUIRE_MAX = 60.0


class Pool:
    """N serial workers admitted under a bounded wait.

    `string(text)` / `value(json_value)` return (result, list of {rule,count})
    and raise CaviarError like Client. Each client keeps one worker process and
    one trust-domain key copy, so a stuck call is killed at its own deadline by
    its own client without touching the other workers. Admission waits at most
    `acquire_timeout` for an idle client, then raises `busy`; the client
    timeout starts at admission, so the worst case is `acquire_timeout +
    timeout`. A failed call returns its client to the pool (it restarts its
    worker on next use) and is never replayed on another worker. A result is
    returned only if completion commits before terminal closure; otherwise it
    is discarded and the call raises `closed`. `close()` is terminal and
    idempotent. In a forked child, calls refuse with `forked_client` and
    `close()` disposes of only this process's pipe copies; neither blocks on
    inherited state nor touches the parent's workers.
    """

    def __init__(self, key, size, *, acquire_timeout, timeout=5.0, allow_plain=False):
        if type(size) is not int or not (SIZE_MIN <= size <= SIZE_MAX):
            raise CaviarError("invalid_size")
        # Exact built-in type plus the bounded range rejects NaN, infinities
        # and arbitrarily large integers without any float conversion.
        if (type(acquire_timeout) not in (int, float)
                or not (ACQUIRE_MIN <= acquire_timeout <= ACQUIRE_MAX)):
            raise CaviarError("invalid_acquire_timeout")
        self._clients = [Client(key, timeout=timeout, allow_plain=allow_plain)
                          for _ in range(size)]
        self._free = deque(self._clients)
        self._cond = threading.Condition()
        self._closed = False
        self._acquire_timeout = float(acquire_timeout)
        self._owner_pid = os.getpid()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def string(self, text):
        return self._dispatch("string", text)

    def value(self, value):
        return self._dispatch("value", value)

    def _dispatch(self, method, argument):
        if os.getpid() != self._owner_pid:
            raise CaviarError("forked_client")
        client = self._acquire()
        try:
            result = getattr(client, method)(argument)
        except BaseException as exc:
            self._release(client)
            if self._closed and isinstance(exc, CaviarError):
                raise CaviarError("closed") from exc
            raise
        with self._cond:
            # Completion and closure observe the same condition-protected
            # state: the result is returned only if completion commits before
            # terminal closure, otherwise it is discarded.
            if self._closed:
                raise CaviarError("closed")
            self._free.append(client)
            self._cond.notify_all()
        return result

    def close(self):
        # Never waits for in-flight calls: mark closed and release every
        # admission waiter, then close every client (killing and reaping
        # every child). In-flight calls surface `closed` through their client.
        if os.getpid() != self._owner_pid:
            # Forked child: another parent thread may hold the inherited
            # condition, so never take it. Each client closes only this
            # process's pipe copies and never signals the parent's workers.
            self._closed = True
            for client in self._clients:
                client.close()
            return
        with self._cond:
            if self._closed:
                return
            self._closed = True
            self._free.clear()
            self._cond.notify_all()
        for client in self._clients:
            client.close()

    def _acquire(self):
        with self._cond:
            if self._closed:
                raise CaviarError("closed")
            deadline = time.monotonic() + self._acquire_timeout
            while not self._free and not self._closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._cond.wait(remaining)
            if self._closed:
                raise CaviarError("closed")
            if not self._free:
                raise CaviarError("busy")
            return self._free.popleft()

    def _release(self, client):
        with self._cond:
            self._free.append(client)
            self._cond.notify_all()
