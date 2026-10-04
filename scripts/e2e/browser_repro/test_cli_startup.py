# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Real CLI startup component checks, not a browser/containment matrix.

Set PIPELOCK_BROWSER_TEST_BIN to the already-built candidate. This test owns
only a direct CLI child with generated configuration and no child commands.
Its bounded child cleanup does not replace Process's production supervisor or
make the complete browser matrix supported when procfs cleanup is unavailable.
"""
from contextlib import contextmanager
import errno
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request

from run import (
    Cancellation, Process, config_for, isolated_environment,
    owned_proxy_address, proxy_command, wait_owned_proxy, write_json,
)


class DirectCLI:
    """Own one CLI process; reuse the harness's bounded pipe observation only."""

    drain = Process.drain
    output_snapshot = Process.output_snapshot

    def __init__(self, command, env, cwd):
        self.buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self.counts = {"stdout": 0, "stderr": 0}
        self.eof = {"stdout": False, "stderr": False}
        self.read_errors = {}
        self.output_lock = threading.Lock()
        self.threads = []
        self.process = subprocess.Popen(
            command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            for name in self.buffers:
                thread = threading.Thread(target=self.drain, args=(name,), daemon=True)
                thread.start()
                self.threads.append(thread)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def join_output(self):
        deadline = time.monotonic() + 5
        for thread in self.threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in self.threads):
            raise AssertionError("direct CLI pipe drain did not terminate")
        if not all(self.eof.values()) or self.read_errors:
            raise AssertionError(f"direct CLI output did not reach clean EOF: {self.read_errors}")

    def wait(self, timeout=10):
        code = self.process.wait(timeout=timeout)
        self.join_output()
        return code

    def close(self):
        try:
            if self.process.poll() is None:
                try:
                    self.process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        self.process.kill()
                    except ProcessLookupError:
                        pass
                    self.process.wait(timeout=5)
            else:
                self.process.wait(timeout=5)
        finally:
            try:
                self.join_output()
            finally:
                for stream in (self.process.stdout, self.process.stderr):
                    stream.close()

    def diagnostics(self):
        return "\n".join(
            f"{name}: {self.output_snapshot(name)[0].decode('utf-8', errors='replace')}"
            for name in self.buffers
        )


@contextmanager
def healthy_listener():
    """Keep a real healthy, unrelated listener bound throughout the refusal."""
    arrivals = []
    lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            with lock:
                arrivals.append(self.path)
            body = b"unrelated-listener-ready"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    try:
        thread.start()
        yield server, arrivals, lock
    finally:
        if thread.is_alive():
            server.shutdown()
        server.server_close()
        if thread.ident is not None:
            thread.join(timeout=5)
        if thread.is_alive():
            raise AssertionError("unrelated listener did not terminate")


class CLIStartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        name = "PIPELOCK_BROWSER_TEST_BIN"
        if name not in os.environ:
            raise unittest.SkipTest(f"set {name} to run the real CLI startup component tests")
        supplied = os.environ[name]
        if not supplied:
            raise AssertionError(f"{name} was supplied but is empty")
        try:
            cls.binary = Path(supplied).resolve(strict=True)
        except (OSError, ValueError) as error:
            raise AssertionError(f"{name} must name an existing candidate executable") from error
        if not cls.binary.is_file() or not os.access(cls.binary, os.X_OK):
            raise AssertionError(f"{name} must name an executable file: {cls.binary}")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="browser-cli-startup-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.env = isolated_environment(self.work)
        self.config = self.work / "pipelock.json"
        write_json(self.config, config_for())
        self.env["PIPELOCK_CONFIG"] = str(self.config)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def test_shared_startup_command_reaches_owned_health_and_retains_the_port(self):
        command = proxy_command(self.binary, self.config)
        listen = command[-1]
        expected = "http://" + listen
        with DirectCLI(command, self.env, self.work) as child:
            address = wait_owned_proxy(child, self.opener, Cancellation(), expected_address=expected)
            self.assertRegex(listen, r"^127\.0\.0\.1:[1-9][0-9]{0,4}$")
            port = int(listen.rsplit(":", 1)[1])
            self.assertGreaterEqual(port, 49152)
            self.assertLessEqual(port, 65535)
            self.assertEqual(address, expected, child.diagnostics())
            self.assertEqual(owned_proxy_address(*child.output_snapshot("stdout")), expected)
            with self.opener.open(address + "/health", timeout=2) as response:
                self.assertEqual(response.status, 200)
                body = json.loads(response.read(65537))
            self.assertEqual(body["status"], "healthy")
            self.assertEqual(body["mode"], "strict")
            self.assertTrue(body["response_scan_enabled"])
            self.assertTrue(body["forward_proxy_enabled"])
            self.assertIsNone(child.process.poll(), child.diagnostics())
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as competing:
                with self.assertRaises(OSError) as refused:
                    competing.bind(("127.0.0.1", port))
                self.assertEqual(refused.exception.errno, errno.EADDRINUSE)
        self.assertEqual(child.process.returncode, 0, child.diagnostics())

    def test_occupied_healthy_listener_cannot_substitute_for_owned_startup(self):
        with healthy_listener() as (server, arrivals, lock):
            listen = f"127.0.0.1:{server.server_address[1]}"
            expected = "http://" + listen
            # Establish that the competing listener really answers health,
            # then count only requests made during the actual CLI attempt.
            with self.opener.open(expected + "/health", timeout=2) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b"unrelated-listener-ready")
            with lock:
                self.assertEqual(arrivals, ["/health"])
                arrivals.clear()
            command = proxy_command(self.binary, self.config, listen=listen)
            with DirectCLI(command, self.env, self.work) as child:
                with self.assertRaisesRegex(RuntimeError, "proxy exited before readiness"):
                    wait_owned_proxy(child, self.opener, Cancellation(), expected_address=expected)
                self.assertNotEqual(child.wait(), 0, child.diagnostics())
                self.assertIsNone(owned_proxy_address(*child.output_snapshot("stdout")))
                stderr = child.output_snapshot("stderr")[0].decode("utf-8", errors="replace")
                self.assertIn("fetch_proxy.listen", stderr)
                self.assertIn("address already in use", stderr)
            with lock:
                self.assertEqual(arrivals, [], "readiness contacted the unrelated healthy listener")

    def test_real_cli_rejects_port_zero_with_file_backed_config(self):
        # The repaired shared helper itself rejects zero; exercise the old
        # failing argv directly to retain a real CLI witness for the defect.
        command = [str(self.binary), "run", "--config", str(self.config), "--listen", "127.0.0.1:0"]
        with DirectCLI(command, self.env, self.work) as child:
            self.assertNotEqual(child.wait(), 0, child.diagnostics())
            self.assertIsNone(owned_proxy_address(*child.output_snapshot("stdout")))
            stderr = child.output_snapshot("stderr")[0].decode("utf-8", errors="replace")
            self.assertIn("fetch_proxy.listen port must be between 1 and 65535", stderr)


if __name__ == "__main__":
    unittest.main()
