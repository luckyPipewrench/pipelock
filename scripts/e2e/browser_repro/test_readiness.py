# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Synthetic witnesses for owned proxy startup; no containment claim."""
import http.server
import json
import os
import signal
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
import urllib.request

from run import Cancellation, Process, owned_proxy_address, wait_owned_proxy


def startup(address):
    return json.dumps({"event": "startup", "listen": address}).encode() + b"\n"


def observed_process(output, poll=None, total=None):
    return SimpleNamespace(
        process=SimpleNamespace(poll=poll or (lambda: None)),
        output_snapshot=lambda _name: (output, len(output) if total is None else total),
    )


class ProxyReadinessTests(unittest.TestCase):
    def test_complete_owned_record_selects_only_the_bound_loopback_address(self):
        evidence = b'{"event":"config_reload","listen":"127.0.0.1:1"}\n' + startup("127.0.0.1:54321")
        self.assertEqual(owned_proxy_address(evidence, len(evidence)), "http://127.0.0.1:54321")
        self.assertIsNone(owned_proxy_address(evidence[:-1], len(evidence)-1))
        self.assertIsNone(owned_proxy_address(b"", 0))

    def test_ambiguous_invalid_or_truncated_evidence_is_rejected(self):
        cases = [startup("127.0.0.1:0"), startup("0.0.0.0:8080"), startup("localhost:8080"),
                 startup("127.0.0.1:65536"), startup("127.0.0.1:1/path"), startup("[::1]:80"),
                 b'{"event":"startup","listen":123}\n', b'{"event":"startup"}\n',
                 b'{"event":"startup","event":"other","listen":"127.0.0.1:80"}\n',
                 b"invalid\n", b"[]\n", startup("127.0.0.1:80")*2, b"x"*65537]
        for evidence in cases:
            with self.subTest(evidence=evidence[:100]), self.assertRaises(RuntimeError):
                owned_proxy_address(evidence, len(evidence))
        evidence = startup("127.0.0.1:80")
        with self.assertRaisesRegex(RuntimeError, "truncated"):
            owned_proxy_address(evidence, len(evidence)+1)

    def test_no_witness_never_contacts_an_unrelated_healthy_listener(self):
        opener = Mock()
        opener.open.side_effect = AssertionError("health requested without owned startup")
        with self.assertRaisesRegex(RuntimeError, "owned proxy readiness deadline"):
            wait_owned_proxy(observed_process(b""), opener, Cancellation(), timeout=0)
        opener.open.assert_not_called()

    def test_exit_or_cancellation_before_readiness_never_contacts_listener(self):
        evidence = startup("127.0.0.1:54321")
        opener = Mock()
        with self.assertRaisesRegex(RuntimeError, "exited before readiness"):
            wait_owned_proxy(observed_process(evidence, poll=lambda: 1), opener, Cancellation())
        cancellation = Cancellation()
        cancellation.interrupted(signal.SIGTERM, None)
        with self.assertRaisesRegex(RuntimeError, "runner interrupted"):
            wait_owned_proxy(observed_process(evidence), opener, cancellation)
        opener.open.assert_not_called()

    def test_health_is_requested_only_at_the_actual_owned_ephemeral_endpoint(self):
        arrivals = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                arrivals.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        address = f"127.0.0.1:{server.server_address[1]}"
        evidence = startup(address)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            self.assertEqual(wait_owned_proxy(observed_process(evidence), opener, Cancellation(), timeout=2), "http://"+address)
            self.assertEqual(arrivals, ["/health"])
            polls = iter([None, 1])
            with self.assertRaisesRegex(RuntimeError, "exited during readiness"):
                wait_owned_proxy(observed_process(evidence, poll=lambda: next(polls)), opener, Cancellation(), timeout=2)
            self.assertEqual(arrivals, ["/health", "/health"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_short_startup_record_is_drained_before_pipe_eof(self):
        read_fd, write_fd = os.pipe()
        process = Process.__new__(Process)
        process.output_lock = threading.Lock()
        process.buffers, process.counts = {"stdout": bytearray()}, {"stdout": 0}
        process.eof, process.read_errors = {"stdout": False}, {}
        process.process = SimpleNamespace(stdout=os.fdopen(read_fd, "rb"))
        thread = threading.Thread(target=process.drain, args=("stdout",), daemon=True)
        thread.start()
        evidence = startup("127.0.0.1:54321")
        try:
            os.write(write_fd, evidence)
            deadline = time.monotonic()+2
            while process.output_snapshot("stdout")[1] < len(evidence) and time.monotonic() < deadline:
                threading.Event().wait(0.01)
            self.assertEqual(process.output_snapshot("stdout"), (evidence, len(evidence)))
            self.assertFalse(process.eof["stdout"], "startup must arrive before writer closes")
        finally:
            os.close(write_fd)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        self.assertTrue(process.eof["stdout"])
        self.assertFalse(process.read_errors)


if __name__ == "__main__":
    unittest.main()
