# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.parse
import urllib.request

from fixture import CANARY, HOST, Fixture, generated_bundle, write_fixtures
from run import Cancellation, Process, config_for, isolated_environment, write_json


class FixtureTests(unittest.TestCase):
    def test_bundle_is_deterministic_generated_and_marker_is_opt_in(self):
        body = generated_bundle(4096)
        self.assertEqual(hashlib.sha256(body).digest(), hashlib.sha256(generated_bundle(4096)).digest())
        self.assertGreaterEqual(len(body), 4096)
        self.assertLess(len(body), 4200)
        self.assertIn(b"function fixtureRow", body)
        self.assertIn(b"window.fixture", body)
        self.assertNotIn(b"BROWSER_REPRO_RESPONSE_MARKER", body)
        self.assertEqual(generated_bundle(4096, marker=True), body+b"\n/* BROWSER_REPRO_RESPONSE_MARKER */\n")
        for size in (0, 4095, 8_000_001):
            with self.assertRaises(ValueError):
                generated_bundle(size)

    def test_frozen_fixtures_match_manifest_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixtures"
            manifest = write_fixtures(output, 4096)
            for name, expected in manifest.items():
                path = output / name
                body = path.read_bytes()
                self.assertEqual(expected, {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()})
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((output / "generated-fixtures.json").read_text()), manifest)
            with self.assertRaises(FileExistsError):
                write_fixtures(output, 4096)

    def test_real_fixture_routes_and_auth(self):
        with Fixture(4096, delay=0) as fixture:
            connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
            connection.request("GET", "/account")
            response = connection.getresponse()
            self.assertEqual(response.status, 303)
            self.assertEqual(response.headers["Location"], "/login")
            response.read()
            connection.request("POST", "/session", "user=fixture&code=wrong")
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
            connection.request("POST", "/session", "user=fixture&code=fixture-only")
            response = connection.getresponse()
            self.assertEqual(response.status, 303)
            cookie = response.headers["Set-Cookie"]
            self.assertIn("HttpOnly", cookie)
            self.assertIn("Max-Age=3600", cookie)
            response.read()
            connection.request("GET", "/account", headers={"Cookie": cookie})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn(b"Synthetic browser fixture", response.read())
            connection.request("GET", "/bundle.js")
            response = connection.getresponse()
            self.assertEqual(response.headers.get_all("Cache-Control"), ["public, max-age=3600"])
            self.assertEqual(response.read(), generated_bundle(4096))
            connection.request("GET", "/api/data?scenario=error")
            response = connection.getresponse()
            self.assertEqual(response.status, 503)
            self.assertIn("error", json.loads(response.read()))
            connection.request("GET", "/api/data?scenario=incomplete")
            response = connection.getresponse()
            with self.assertRaises(http.client.IncompleteRead):
                response.read()
            connection.close()

    def test_route_evidence_does_not_store_queries_and_is_bounded(self):
        with Fixture(4096, delay=0) as fixture:
            connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
            for index in range(40):
                connection.request("GET", f"/unknown-{index}?private=do-not-record")
                connection.getresponse().read()
            connection.close()
            evidence = fixture.evidence()
            self.assertEqual(evidence["counts"], {"other": 40})
            self.assertEqual(len(evidence["routes"]["other"]), 32)
            self.assertNotIn("private", json.dumps(evidence))

    def test_configuration_preserves_defaults_and_limits_fixture_trust(self):
        config = config_for()
        self.assertEqual(config["mode"], "strict")
        self.assertEqual(config["api_allowlist"], [HOST])
        self.assertEqual(config["trusted_domains"], [HOST])
        self.assertEqual(config["response_scanning"], {"enabled": True, "action": "block"})
        self.assertNotIn("patterns", config["response_scanning"])
        self.assertNotIn("dlp", config)
        self.assertNotIn("ssrf", config)
        self.assertNotIn("sandbox", config)
        self.assertEqual(config["canary_tokens"]["tokens"][0]["value"], CANARY)

    @unittest.skipUnless(Path(f"/proc/self/task/{os.getpid()}/children").is_file(), "procfs children enumeration unavailable; cannot verify process cleanup")
    def test_both_output_pipes_are_drained_beyond_retention_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = isolated_environment(root)
            command = [sys.executable, "-c", "import os; os.write(1,b'o'*200000); os.write(2,b'e'*200000)"]
            process = Process(command, root / "flood", env, root)
            try:
                self.assertEqual(process.wait(10), 0)
            finally:
                result = process.stop()
            for name in ("stdout", "stderr"):
                self.assertEqual(result["streams"][name]["total_bytes"], 200000)
                self.assertEqual(result["streams"][name]["retained_bytes"], 65536)
                self.assertTrue(result["streams"][name]["truncated"])
            self.assertTrue(result["cleanup"]["cleanup_complete"])

    def test_drain_distinguishes_read_error_from_eof(self):
        process = Process.__new__(Process)
        process.buffers = {"stdout": bytearray()}
        process.counts = {"stdout": 0}
        process.eof = {"stdout": False}
        process.read_errors = {}
        stream = Mock()
        stream.read.side_effect = [b"kept", OSError("synthetic read failure")]
        process.process = Mock(stdout=stream)
        process.drain("stdout")
        self.assertFalse(process.eof["stdout"])
        self.assertIn("synthetic read failure", process.read_errors["stdout"])
        self.assertEqual(process.buffers["stdout"], b"kept")

    def test_cleanup_witness_and_explicit_eof_are_required(self):
        for complete, unexpected, eof in ((False, False, True), (True, True, True), (True, False, False), (True, False, True)):
            with self.subTest(complete=complete, unexpected=unexpected, eof=eof), tempfile.TemporaryDirectory() as temporary:
                process = Process.__new__(Process)
                process.output = Path(temporary) / "child"
                process.process = Mock(returncode=0)
                process.process.poll.return_value = 0
                process.threads = []
                process.buffers = {"stdout": bytearray(b"synthetic"), "stderr": bytearray()}
                process.counts = {"stdout": 9, "stderr": 0}
                process.eof = {"stdout": eof, "stderr": eof}
                process.read_errors = {}
                write_json(process.output.with_suffix(".cleanup.json"), {"cleanup_complete": complete, "unexpected_live_descendants": unexpected})
                if complete and not unexpected and eof:
                    self.assertTrue(process.stop()["streams_drained"])
                else:
                    with self.assertRaises(RuntimeError):
                        process.stop()

    def test_process_refuses_missing_cleanup_facility(self):
        with patch("run.Path.is_file", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "procfs children file is absent"):
                Process(["unused"], Path("unused"), {}, Path("."))

    def test_cancellation_waits_for_safe_checkpoint_and_restores_handlers(self):
        cancellation = Cancellation()
        previous = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
        cancellation.install()
        try:
            cancellation.interrupted(signal.SIGTERM, None)
            cancellation.interrupted(signal.SIGINT, None)
            self.assertEqual(cancellation.signum, signal.SIGTERM)
            process = Process.__new__(Process)
            process.cancellation = cancellation
            process.command = ["synthetic"]
            process.process = Mock()
            with self.assertRaisesRegex(RuntimeError, "runner interrupted"):
                process.wait(10)
            process.process.wait.assert_not_called()
            with patch("run.subprocess.Popen") as launch:
                with self.assertRaisesRegex(RuntimeError, "runner interrupted"):
                    Process(["unused"], Path("unused"), {}, Path("."), cancellation)
                launch.assert_not_called()
        finally:
            cancellation.restore()
        self.assertEqual(previous, {signum: signal.getsignal(signum) for signum in previous})

    def test_wait_retains_deadline_and_normal_exit(self):
        process = Process.__new__(Process)
        process.cancellation = Cancellation()
        process.command = ["synthetic"]
        process.process = Mock()
        process.process.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 0.1), 7]
        self.assertEqual(process.wait(10), 7)
        with self.assertRaises(subprocess.TimeoutExpired):
            process.wait(0)

    @unittest.skipUnless(Path(f"/proc/self/task/{os.getpid()}/children").is_file(), "procfs children enumeration unavailable; cannot verify cancellation cleanup")
    def test_external_cancellation_reaps_supervised_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = """
import signal, sys, threading, time
from pathlib import Path
from run import Cancellation, Process, isolated_environment, write_json
root = Path(sys.argv[1])
cancellation = Cancellation()
cancellation.install()
process = None
try:
    process = Process([sys.executable, '-c', "import os, signal; os.write(1, b'r'*8192); signal.pause()"], root / 'child', isolated_environment(root), root, cancellation)
    deadline = time.monotonic() + 5
    while process.counts['stdout'] < 8192:
        cancellation.check()
        if process.process.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError('synthetic child readiness absent')
        threading.Event().wait(0.01)
    print('ready', flush=True)
    process.wait(30)
except RuntimeError:
    pass
finally:
    if process:
        write_json(root / 'result.json', process.stop())
    cancellation.restore()
"""
            runner = subprocess.Popen([sys.executable, "-c", script, str(root)], cwd=Path(__file__).parent,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                import selectors
                with selectors.DefaultSelector() as selector:
                    selector.register(runner.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(5), "synthetic runner did not become ready")
                self.assertEqual(runner.stdout.readline().strip(), "ready")
                runner.send_signal(signal.SIGTERM)
                _out, errors = runner.communicate(timeout=12)
                self.assertEqual(runner.returncode, 0, errors)
                result = json.loads((root / "result.json").read_text())
                self.assertTrue(result["cleanup"]["cleanup_complete"])
                self.assertFalse(result["cleanup"]["unexpected_live_descendants"])
                self.assertTrue(result["streams_drained"])
            finally:
                if runner.poll() is None:
                    runner.send_signal(signal.SIGTERM)
                    runner.communicate(timeout=12)

    def test_environment_is_not_copied_and_outputs_are_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = isolated_environment(root)
            self.assertEqual(set(env), {"PATH", "LANG", "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "TMPDIR", "PIPELOCK_POSTURE_PROOF"})
            self.assertTrue(Path(env["HOME"]).is_dir())
            path = root / "result.json"
            write_json(path, {"status": "pending"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text()), {"status": "pending"})


if __name__ == "__main__":
    unittest.main()
