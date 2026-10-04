# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Fault-injected supervisor reports; these do not establish runtime cleanup."""
import errno
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from run import Process


class ProcessTimeoutReportingTests(unittest.TestCase):
    def stalled_process(self, root):
        process = Process.__new__(Process)
        process.output = root / "driver"
        process.signal_grace_seconds = 20
        process.output_lock = threading.Lock()
        process.buffers = {"stdout": bytearray(b"x" * 65536),
                           "stderr": bytearray(b"generated launch failure\n")}
        process.counts = {"stdout": 80000, "stderr": len(process.buffers["stderr"])}
        process.read_errors = {}
        signals, waits = [], []
        timeout = subprocess.TimeoutExpired(["generated-supervisor"], 26)
        def wait(timeout):
            waits.append(timeout)
            raise failure
        failure = timeout
        process.process = SimpleNamespace(poll=lambda: None, send_signal=signals.append,
                                          wait=wait, returncode=None)
        return process, signals, waits, failure

    def test_timeout_preserves_bounded_snapshots_without_claiming_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process, signals, waits, failure = self.stalled_process(root)
            # A stale positive witness cannot certify a still-running owner.
            process.output.with_suffix(".cleanup.json").write_text('{"cleanup_complete":true}')
            with self.assertRaisesRegex(RuntimeError, "did not complete descendant cleanup") as raised:
                process.stop()
            self.assertIs(raised.exception.__cause__, failure)
            self.assertEqual(signals, [signal.SIGTERM])
            self.assertEqual(waits, [26])
            self.assertEqual(process.output.with_suffix(".stdout").read_bytes(), b"x" * 65536)
            self.assertEqual(process.output.with_suffix(".stderr").read_bytes(), b"generated launch failure\n")
            record = json.loads(process.output.with_suffix(".process.json").read_bytes())
            self.assertTrue(record["supervisor_timeout"])
            self.assertIsNone(record["exit_code"])
            self.assertFalse(record["streams_drained"])
            self.assertEqual(record["cleanup"], {"cleanup_complete": False})
            self.assertEqual(record["streams"]["stdout"],
                             {"total_bytes": 80000, "retained_bytes": 65536, "truncated": True})
            for suffix in (".stdout", ".stderr", ".process.json"):
                self.assertEqual(process.output.with_suffix(suffix).stat().st_mode & 0o777, 0o600)

    def test_timeout_remains_primary_when_one_stream_cannot_be_saved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process, signals, _, failure = self.stalled_process(root)
            original = Path.write_bytes
            def fail_stdout(path, data):
                if path == process.output.with_suffix(".stdout"):
                    raise OSError(errno.EIO, "generated stream save failure")
                return original(path, data)
            with patch.object(Path, "write_bytes", fail_stdout), self.assertRaises(RuntimeError) as raised:
                process.stop()
            self.assertIs(raised.exception.__cause__, failure)
            self.assertIn("did not complete descendant cleanup", str(raised.exception))
            self.assertIn("generated stream save failure", str(raised.exception))
            self.assertEqual(signals, [signal.SIGTERM])
            self.assertEqual(process.output.with_suffix(".stderr").read_bytes(), b"generated launch failure\n")
            record = json.loads(process.output.with_suffix(".process.json").read_bytes())
            self.assertFalse(record["cleanup"]["cleanup_complete"])
            self.assertIn("stdout", record["evidence_errors"][0])

    def test_timeout_remains_primary_when_failure_record_cannot_be_saved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process, signals, _, failure = self.stalled_process(root)
            with patch("run.write_json", side_effect=OSError(errno.EIO, "generated record save failure")), \
                    self.assertRaises(RuntimeError) as raised:
                process.stop()
            self.assertIs(raised.exception.__cause__, failure)
            self.assertIn("generated record save failure", str(raised.exception))
            self.assertEqual(signals, [signal.SIGTERM])
            self.assertTrue(process.output.with_suffix(".stdout").is_file())
            self.assertTrue(process.output.with_suffix(".stderr").is_file())


if __name__ == "__main__":
    unittest.main()
