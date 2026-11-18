"""Regression: a stalled session must not block unrelated agent polls."""
import base64
import threading
import time
import unittest
from unittest import mock
import https_poc as h


class ExchangeConcurrency(unittest.TestCase):
    def test_network_wait_does_not_hold_registry_lock(self):
        entered, release = threading.Event(), threading.Event()
        class SlowSocket:
            def recv(self, size):
                entered.set()
                if not release.wait(3):
                    raise TimeoutError()
                return b"final-response"
        state = h.State.__new__(h.State)
        state.lock = threading.RLock()
        state.config = {"max_bytes": 1024, "idle_seconds": 10}
        state.jobs = {"slow": {"id": "slow", "service": "lab-echo",
            "assigned": True, "done": threading.Event(), "seq": 0,
            "ready": True, "bytes": 0, "activity": time.monotonic(),
            "deadline": time.monotonic() + 10, "socket": SlowSocket()}}
        body = {"action": "exchange", "service": "lab-echo", "job": "slow",
                "seq": 0, "data": "", "closed": False, "ready": True}
        errors, results = [], []
        def exchange():
            try:
                results.append(state.exchange(body))
            except Exception as error:
                errors.append(error)
        with mock.patch.object(h, "service_allowed", return_value=True):
            worker = threading.Thread(target=exchange)
            worker.start()
            try:
                self.assertTrue(entered.wait(1))
                acquired = state.lock.acquire(timeout=.2)
                self.assertTrue(acquired, "network read held the shared registry lock")
                if acquired:
                    state.lock.release()
                self.assertEqual({"idle": True}, state.exchange(
                    {"action": "poll", "services": ["lab-echo"]}))
            finally:
                release.set()
                worker.join(4)
        self.assertFalse(worker.is_alive())
        self.assertEqual([], errors)
        self.assertEqual(b"final-response", base64.b64decode(results[0]["data"]))
