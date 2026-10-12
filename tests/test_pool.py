# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Bounded pool admission and per-worker isolation tests, no fixture bodies."""
import os
import select
import signal
import subprocess
import threading
import time
import unittest
from contextlib import contextmanager
from unittest import mock

from caviar_redact import CaviarError, Pool

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


def hold_exchange(client, on_enter, release):
    """Run a call's real worker init, then hold it at the first redact exchange
    until `release` is set: the call is deterministically in flight on its real
    worker, without stopped processes or near-cap timing margins.
    `on_enter(proc)` reports the in-flight worker process."""
    original = client._exchange
    state = {"phase": 0}
    def exchange(proc, frame, deadline):
        state["phase"] += 1
        if state["phase"] == 2:
            on_enter(proc)
            release.wait(15)
        return original(proc, frame, deadline)
    return exchange


def capture(outcomes, key, action):
    """Record exactly one outcome per launched call: its result, its
    CaviarError code, or any other exception object."""
    try:
        outcomes[key] = action()
    except CaviarError as exc:
        outcomes[key] = exc.code
    except BaseException as exc:
        outcomes[key] = exc


class PoolTests(unittest.TestCase):
    def assert_code(self, code, action):
        with self.assertRaises(CaviarError) as raised:
            action()
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)

    def test_concurrent_calls_run_in_parallel_on_real_workers(self):
        size = 2
        for plain in (False, True):
            with self.subTest(plain=plain):
                pool = Pool(None if plain else KEY, size, acquire_timeout=1.0,
                            allow_plain=plain)
                try:
                    with spawns() as spawned:
                        entered = {client: threading.Event() for client in pool._clients}
                        processes = {}
                        release = threading.Event()
                        for client in pool._clients:
                            def on_enter(proc, client=client):
                                processes[client] = proc
                                entered[client].set()
                            client._exchange = hold_exchange(client, on_enter, release)
                        outcomes = {}
                        threads = [threading.Thread(target=capture, args=(
                                       outcomes, index,
                                       lambda: pool.string("ordinary sentence")))
                                   for index in range(size)]
                        for thread in threads:
                            thread.start()
                        try:
                            for client in pool._clients:
                                self.assertTrue(entered[client].wait(10))
                            # Both calls are in flight at once, on two distinct
                            # real worker processes.
                            self.assertTrue(all(thread.is_alive() for thread in threads))
                            first, second = (processes[client] for client in pool._clients)
                            self.assertNotEqual(first.pid, second.pid)
                            for process in (first, second):
                                self.assertIn(process.pid,
                                              [p.pid for p in spawned])
                            release.set()
                        finally:
                            release.set()
                        for thread in threads:
                            thread.join(10)
                            self.assertFalse(thread.is_alive())
                        self.assertEqual(outcomes, {index: ("ordinary sentence", [])
                                                    for index in range(size)})
                finally:
                    pool.close()

    def test_inflight_completion_cannot_escape_terminal_close(self):
        for method, argument in (("string", "ordinary sentence"),
                                 ("value", {"n": 2**150, "a": [1.25, "😀"]})):
            with self.subTest(method=method):
                pool = Pool(KEY, 2, acquire_timeout=1.0, timeout=10.0)
                try:
                    with spawns() as spawned:
                        entered = {client: threading.Event() for client in pool._clients}
                        releases = {client: threading.Event() for client in pool._clients}
                        for client in pool._clients:
                            client._exchange = hold_exchange(
                                client,
                                lambda proc, client=client: entered[client].set(),
                                releases[client])
                        # Gate each client's close so pool.close() pauses
                        # between clients, exposing the completion/closure window.
                        gates, reached = {}, {}
                        for client in pool._clients:
                            original_close = client.close
                            gate = threading.Event()
                            here = threading.Event()
                            def gated(original=original_close, gate=gate, here=here):
                                here.set()
                                gate.wait(10)
                                return original()
                            client.close = gated
                            gates[client] = gate
                            reached[client] = here
                        outcomes = {}
                        def call(index):
                            try:
                                outcomes[index] = getattr(pool, method)(argument)
                            except CaviarError as exc:
                                outcomes[index] = exc.code
                        client_a, client_b = pool._clients
                        first = threading.Thread(target=call, args=(0,))
                        first.start()
                        self.assertTrue(entered[client_a].wait(10))
                        second = threading.Thread(target=call, args=(1,))
                        second.start()
                        self.assertTrue(entered[client_b].wait(10))
                        close_thread = threading.Thread(target=pool.close)
                        close_thread.start()
                        try:
                            # Pool is terminal and paused closing client_a's
                            # worker while client_b's call is still in flight.
                            self.assertTrue(reached[client_a].wait(10))
                            gates[client_a].set()
                            releases[client_b].set()
                            second.join(10)
                            self.assertFalse(second.is_alive())
                            # The completed result must be discarded, not returned.
                            self.assertEqual(outcomes[1], "closed")
                            releases[client_a].set()
                            gates[client_b].set()
                            first.join(10)
                            self.assertFalse(first.is_alive())
                            close_thread.join(10)
                            self.assertFalse(close_thread.is_alive())
                            self.assertEqual(outcomes[0], "closed")
                            for process in spawned:
                                self.assertIsNotNone(process.poll())
                            self.assert_code("closed",
                                             lambda: pool.string("ordinary sentence"))
                        finally:
                            for client in pool._clients:
                                releases[client].set()
                                gates[client].set()
                            first.join(10)
                            close_thread.join(25)
                finally:
                    pool.close()

    def test_forked_child_close_completes_without_deadlock(self):
        pool = Pool(KEY, 2, acquire_timeout=1.0)
        try:
            with spawns() as spawned:
                pool.string("ordinary sentence")
                pool.string("ordinary sentence")
                self.assertEqual(len(spawned), 2)
                # The forked child must never signal the parent's workers.
                patches = []
                for process in spawned:
                    patch = mock.patch.object(
                        process, "kill",
                        side_effect=AssertionError(
                            "forked child signaled the parent's worker"))
                    patch.start()
                    patches.append(patch)
                try:
                    # Fork while another parent thread holds the pool condition.
                    held = threading.Event()
                    released = threading.Event()
                    def hold_condition():
                        with pool._cond:
                            held.set()
                            released.wait(10)
                    holder = threading.Thread(target=hold_condition)
                    holder.start()
                    self.assertTrue(held.wait(5))
                    read_fd, write_fd = os.pipe()
                    try:
                        pid = os.fork()
                    except BaseException:
                        os.close(read_fd)
                        os.close(write_fd)
                        raise
                    if pid == 0:
                        os.close(read_fd)
                        outcome = b"fail"
                        try:
                            signal.alarm(10)
                            start = time.monotonic()
                            pool.close()
                            with pool:
                                pass
                            outcome = ("%010.3f"
                                       % (time.monotonic() - start)).encode("ascii")
                        except BaseException:
                            pass
                        try:
                            os.write(write_fd, outcome)
                        except OSError:
                            pass
                        finally:
                            os.close(write_fd)
                        os._exit(0 if outcome != b"fail" else 1)
                    os.close(write_fd)
                    released.set()
                    holder.join(10)
                    self.assertFalse(holder.is_alive())
                    outcome = b""
                    deadline = time.monotonic() + 15
                    while len(outcome) < 10:
                        if time.monotonic() > deadline:
                            os.kill(pid, signal.SIGKILL)
                            os.waitpid(pid, 0)
                            self.fail("forked child close did not complete promptly")
                        ready, _, _ = select.select([read_fd], [], [], 0.1)
                        if ready:
                            chunk = os.read(read_fd, 10 - len(outcome))
                            if not chunk:
                                break
                            outcome += chunk
                    _, status = os.waitpid(pid, 0)
                    os.close(read_fd)
                    self.assertEqual(status, 0)
                    self.assertLess(float(outcome), 5.0)
                    self.assertEqual(pool.string("ordinary sentence"),
                                     ("ordinary sentence", []))
                finally:
                    for patch in patches:
                        patch.stop()
        finally:
            pool.close()

    def test_admission_waits_then_succeeds_when_a_worker_frees(self):
        pool = Pool(KEY, 1, acquire_timeout=3.0, timeout=5.0)
        try:
            client = pool._clients[0]
            entered = threading.Event()
            release = threading.Event()
            client._exchange = hold_exchange(client, lambda proc: entered.set(), release)
            holder_code = []
            holder_result = []
            def holder():
                try:
                    holder_result.append(pool.string("ordinary sentence"))
                except CaviarError as exc:
                    holder_code.append(exc.code)
            holder_thread = threading.Thread(target=holder)
            holder_thread.start()
            try:
                self.assertTrue(entered.wait(10))
                waiter_code = []
                waiter_result = []
                def waiter():
                    try:
                        waiter_result.append(pool.string("ordinary sentence"))
                    except CaviarError as exc:
                        waiter_code.append(exc.code)
                waiter_thread = threading.Thread(target=waiter)
                waiter_thread.start()
                time.sleep(0.05)
                self.assertTrue(waiter_thread.is_alive())
                release.set()
            finally:
                release.set()
            holder_thread.join(10)
            waiter_thread.join(10)
            self.assertFalse(holder_thread.is_alive())
            self.assertFalse(waiter_thread.is_alive())
            self.assertEqual(holder_code, [])
            self.assertEqual(holder_result, [("ordinary sentence", [])])
            self.assertEqual(waiter_code, [])
            self.assertEqual(waiter_result, [("ordinary sentence", [])])
        finally:
            pool.close()

    def test_admission_busy_when_all_workers_held_past_acquire_timeout(self):
        acquire_timeout = 0.5
        pool = Pool(KEY, 2, acquire_timeout=acquire_timeout, timeout=5.0)
        try:
            entered = {client: threading.Event() for client in pool._clients}
            release = threading.Event()
            for client in pool._clients:
                client._exchange = hold_exchange(
                    client,
                    lambda proc, client=client: entered[client].set(),
                    release)
            outcomes = {}
            threads = [threading.Thread(target=capture, args=(
                           outcomes, index, lambda: pool.string("ordinary sentence")))
                       for index in range(2)]
            for thread in threads:
                thread.start()
            try:
                for client in pool._clients:
                    self.assertTrue(entered[client].wait(10))
                start = time.monotonic()
                self.assert_code("busy", lambda: pool.string("ordinary sentence"))
                elapsed = time.monotonic() - start
                self.assertGreaterEqual(elapsed, acquire_timeout - 0.2)
                self.assertLess(elapsed, acquire_timeout + 2.0)
                release.set()
            finally:
                release.set()
            for thread in threads:
                thread.join(10)
                self.assertFalse(thread.is_alive())
            self.assertEqual(outcomes, {index: ("ordinary sentence", [])
                                        for index in range(2)})
        finally:
            pool.close()

    def test_slow_call_does_not_delay_other_worker(self):
        pool = Pool(KEY, 2, acquire_timeout=1.0, timeout=5.0)
        try:
            slow = pool._clients[0]
            release = threading.Event()
            entered = threading.Event()
            original = slow._exchange
            def slow_exchange(proc, frame, deadline):
                entered.set()
                release.wait()
                return original(proc, frame, deadline)
            slow._exchange = slow_exchange
            outcomes = {}
            held = threading.Thread(target=capture, args=(
                outcomes, "held", lambda: pool.string("ordinary sentence")))
            held.start()
            try:
                self.assertTrue(entered.wait(5))
                started = time.monotonic()
                self.assertEqual(pool.string("ordinary sentence"), ("ordinary sentence", []))
                elapsed = time.monotonic() - started
                # The other call completed on its real worker while the first
                # call was still held.
                self.assertTrue(held.is_alive())
                self.assertLess(elapsed, 1.0)
            finally:
                release.set()
                held.join(10)
                self.assertFalse(held.is_alive())
            self.assertEqual(outcomes, {"held": ("ordinary sentence", [])})
        finally:
            pool.close()

    def test_killed_worker_fails_then_pool_recovers(self):
        pool = Pool(KEY, 1, acquire_timeout=1.0, timeout=5.0)
        try:
            with spawns() as spawned:
                pool.string("ordinary sentence")
                self.assertEqual(len(spawned), 1)
                process = spawned[0]
                process.kill()
                process.wait()
                self.assert_code("worker_failure",
                                 lambda: pool.string("ordinary sentence"))
                self.assertEqual(pool.string("ordinary sentence"),
                                 ("ordinary sentence", []))
                self.assertEqual(len(spawned), 2)
                self.assertNotEqual(spawned[0].pid, spawned[1].pid)
        finally:
            pool.close()

    def test_terminal_close_does_not_convert_other_base_exceptions(self):
        for interrupt in (KeyboardInterrupt, SystemExit):
            with self.subTest(interrupt=interrupt.__name__):
                pool = Pool(KEY, 1, acquire_timeout=1.0, timeout=5.0)
                try:
                    client = pool._clients[0]
                    original = client._exchange
                    entered = threading.Event()
                    release = threading.Event()
                    state = {"phase": 0}
                    def interrupt_exchange(proc, frame, deadline):
                        state["phase"] += 1
                        if state["phase"] == 2:
                            entered.set()
                            release.wait(15)
                            raise interrupt
                        return original(proc, frame, deadline)
                    client._exchange = interrupt_exchange
                    outcomes = {}
                    def call():
                        try:
                            outcomes["result"] = pool.string("ordinary sentence")
                        except BaseException as exc:
                            outcomes["exc"] = exc
                    thread = threading.Thread(target=call)
                    thread.start()
                    try:
                        self.assertTrue(entered.wait(10))
                        pool.close()
                        release.set()
                    finally:
                        release.set()
                    thread.join(10)
                    self.assertFalse(thread.is_alive())
                    # Only CaviarError may be converted to `closed`; any other
                    # BaseException propagates unchanged.
                    self.assertNotIn("result", outcomes)
                    self.assertIsInstance(outcomes.get("exc"), interrupt)
                    self.assert_code("closed",
                                     lambda: pool.string("ordinary sentence"))
                finally:
                    pool.close()

    def test_close_reaps_children_and_releases_waiters(self):
        pool = Pool(KEY, 1, acquire_timeout=3.0, timeout=5.0)
        try:
            with spawns() as spawned:
                client = pool._clients[0]
                entered = threading.Event()
                release = threading.Event()
                client._exchange = hold_exchange(client, lambda proc: entered.set(), release)
                in_flight_code = []
                def in_flight():
                    try:
                        pool.string("ordinary sentence")
                    except CaviarError as exc:
                        in_flight_code.append(exc.code)
                in_flight_thread = threading.Thread(target=in_flight)
                in_flight_thread.start()
                self.assertTrue(entered.wait(10))
                waiter_code = []
                def waiter():
                    try:
                        pool.string("ordinary sentence")
                    except CaviarError as exc:
                        waiter_code.append(exc.code)
                waiter_thread = threading.Thread(target=waiter)
                waiter_thread.start()
                time.sleep(0.05)
                self.assertTrue(waiter_thread.is_alive())
                pool.close()
                waiter_thread.join(2)
                self.assertFalse(waiter_thread.is_alive())
                self.assertEqual(waiter_code, ["closed"])
                release.set()
                in_flight_thread.join(10)
                self.assertFalse(in_flight_thread.is_alive())
                self.assertEqual(in_flight_code, ["closed"])
                for process in spawned:
                    self.assertIsNotNone(process.poll())
                self.assert_code("closed", lambda: pool.string("ordinary sentence"))
                pool.close()
        finally:
            pool.close()

    def test_fork_child_refuses_and_parent_unaffected(self):
        pool = Pool(KEY, 2, acquire_timeout=1.0)
        try:
            pool.string("ordinary sentence")
            original = pool._clients[0]._proc
            self.assertIsNotNone(original)
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
                        pool.string("ordinary sentence")
                    except CaviarError as exc:
                        outcome = exc.code.encode("ascii")
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
            self.assertEqual(pool.string("ordinary sentence"), ("ordinary sentence", []))
        finally:
            pool.close()

    def test_invalid_arguments_refuse(self):
        for size in (0, 33, True, 2.0, "2", None):
            self.assert_code("invalid_size",
                             lambda: Pool(KEY, size, acquire_timeout=1.0))
        for acquire_timeout in (-0.1, 61, float("inf"), float("nan"), "1", None, True,
                               10**1000, -10**1000):
            self.assert_code("invalid_acquire_timeout",
                             lambda: Pool(KEY, 1, acquire_timeout=acquire_timeout))
        self.assert_code("key_required",
                         lambda: Pool(None, 1, acquire_timeout=1.0))
        self.assert_code("invalid_key",
                         lambda: Pool(b"short", 1, acquire_timeout=1.0))
        for timeout in (0, -1, 61, float("inf")):
            self.assert_code("invalid_timeout",
                             lambda: Pool(KEY, 1, acquire_timeout=1.0, timeout=timeout))

    def test_value_roundtrip_through_pool(self):
        with Pool(KEY, 2, acquire_timeout=1.0) as pool:
            value = {"n": 2**150, "small": 1e-200,
                     "a": [None, True, False, 1.25, "😀"], "o": {}}
            result, hits = pool.value(value)
            self.assertEqual(result, value)
            self.assertEqual(hits, [])
            self.assertEqual(pool.value(None), (None, []))


if __name__ == "__main__":
    unittest.main()
