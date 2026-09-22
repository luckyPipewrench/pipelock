# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Exercise CI process ownership while commands start, run, and shut down."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SUPERVISOR = ROOT / "scripts" / "ci_process_supervisor.py"
WRAPPER = ROOT / "scripts" / "ci-test-with-retry.sh"


def await_file(path: Path, process: subprocess.Popen) -> None:
    """Wait for the fixture's explicit readiness signal under a finite deadline."""
    deadline = time.monotonic() + 5
    while not path.exists() or not path.read_text():
        if process.poll() is not None or time.monotonic() >= deadline:
            raise AssertionError(f"fixture did not become ready: {path.name}")
        time.sleep(0.01)


@unittest.skipUnless(sys.platform == "linux", "Linux child adoption")
class TestCiProcessSupervisor(unittest.TestCase):
    def test_wrapper_helpers_ignore_cdpath(self) -> None:
        """Relative invocation must select helpers beside the actual wrapper."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            alternate = directory / "scripts"
            alternate.mkdir()
            marker = directory / "alternate-helper-ran"
            (alternate / SUPERVISOR.name).write_text(
                "import os, pathlib\n"
                "pathlib.Path(os.environ['ALTERNATE_HELPER_MARKER']).touch()\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["bash", str(WRAPPER.relative_to(ROOT)), "--packages", "example.com/p/pkg",
                 "--attempt-timeout-seconds", "5", "--", "bash", "-c", "pwd -P"],
                cwd=ROOT,
                env=dict(os.environ, CDPATH=str(directory), ALTERNATE_HELPER_MARKER=str(marker)),
                text=True, capture_output=True, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), str(ROOT.resolve()))
            self.assertFalse(marker.exists(), "wrapper selected an alternate helper")

    def test_wrapper_interruption_during_first_capture_reader_startup(self) -> None:
        """An interrupt between reader launch and PID assignment cannot leak it."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            reader_file = directory / "reader-pid"
            bash_env = directory / "bash-env"
            bash_env.write_text(
                'set -T\n'
                'trap \'if [[ ${reader_probe_sent:-0} == 0 && '
                '$BASH_COMMAND == "local stdout_tee_pid="* ]]; then '
                'reader_probe_sent=1; printf "%s\\n" "$!" > "$READER_PID_FILE"; '
                'kill -TERM "$BASHPID"; fi\' DEBUG\n', encoding="utf-8",
            )
            reader_pid = None
            with (directory / "output").open("w") as output:
                process = subprocess.Popen(
                    ["bash", str(WRAPPER), "--packages", "example.com/p/pkg",
                     "--", "bash", "-c", "printf completed"],
                    cwd=ROOT, env=dict(os.environ, BASH_ENV=str(bash_env),
                                      READER_PID_FILE=str(reader_file)),
                    stdout=output, stderr=output, start_new_session=True,
                )
                try:
                    self.assertEqual(process.wait(timeout=8), 143)
                    self.assertTrue(reader_file.exists(), "startup interrupt was not exercised")
                    reader_pid = int(reader_file.read_text())
                    deadline = time.monotonic() + 2
                    while True:
                        try:
                            os.kill(reader_pid, 0)
                        except ProcessLookupError:
                            break
                        if time.monotonic() >= deadline:
                            self.fail("capture reader survived wrapper cancellation")
                        time.sleep(0.01)
                finally:
                    if reader_file.exists():
                        reader_pid = int(reader_file.read_text())
                        try:
                            os.kill(reader_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if process.poll() is None:
                        process.terminate()
                    process.wait(timeout=8)

    def test_reaps_exited_orphans_while_command_is_running(self) -> None:
        """The still-running command observes its exited orphan disappear."""
        script = r'''
import os, subprocess, sys, time
intermediate = subprocess.Popen([
    sys.executable, "-c",
    "import subprocess, sys; child = subprocess.Popen([sys.executable, '-c', 'pass']); "
    "print(child.pid, flush=True)",
], stdout=subprocess.PIPE, text=True)
pid = int(intermediate.communicate(timeout=3)[0])
deadline = time.monotonic() + 2
while time.monotonic() < deadline:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        print("orphan reaped while command is running", flush=True)
        sys.exit(7)
    time.sleep(0.01)
sys.exit("orphan retained until command completion")
'''
        with tempfile.TemporaryDirectory() as tmp:
            status = Path(tmp) / "status.json"
            result = subprocess.run(
                [sys.executable, str(SUPERVISOR), "--status-file", str(status),
                 "--", sys.executable, "-c", script],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
            self.assertIn("orphan reaped while command is running", result.stdout)
            self.assertTrue(json.loads(status.read_text())["cleanup_complete"])

    def test_interruption_allows_command_cleanup_handlers(self) -> None:
        """TERM and INT reach the command before the forced-cleanup deadline."""
        script = r'''
import pathlib, signal, sys, time
def finish(signum, _frame):
    pathlib.Path(sys.argv[2]).write_text(str(signum))
    print("command cleanup completed", flush=True)
    sys.exit(0)
signal.signal(signal.SIGTERM, finish)
signal.signal(signal.SIGINT, finish)
pathlib.Path(sys.argv[1]).write_text("ready")
while True:
    time.sleep(1)
'''
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signum), tempfile.TemporaryDirectory() as tmp:
                ready, ack, status = (Path(tmp) / name for name in ("ready", "ack", "status"))
                process = subprocess.Popen(
                    [sys.executable, str(SUPERVISOR), "--status-file", str(status),
                     "--", sys.executable, "-c", script, str(ready), str(ack)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    start_new_session=True,
                )
                try:
                    await_file(ready, process)
                    process.send_signal(signum)
                    stdout, stderr = process.communicate(timeout=8)
                    self.assertEqual(process.returncode, 128 + signum, stdout + stderr)
                    self.assertTrue(ack.exists(), "command cleanup handler never ran")
                    self.assertEqual(ack.read_text(), str(signum))
                    self.assertIn("command cleanup completed", stdout)
                    self.assertTrue(json.loads(status.read_text())["cleanup_complete"])
                finally:
                    if process.poll() is None:
                        process.terminate()
                    process.communicate(timeout=8)

    def test_wrapper_interruption_before_supervisor_session_setup(self) -> None:
        """Cancellation must collect the child even before its process group exists."""
        real_python = shutil.which("python3")
        self.assertIsNotNone(real_python)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            ready, release, ran = (directory / name for name in ("ready", "release", "ran"))
            os.mkfifo(release, 0o600)
            release_fd = os.open(release, os.O_RDWR)
            launcher = directory / "python3"
            launcher.write_text(
                '#!/bin/bash\n'
                'case "$1" in\n'
                '  */ci_process_supervisor.py)\n'
                '    printf "%s\\n" "$$" > "$STARTUP_READY"\n'
                '    IFS= read -r _ < "$STARTUP_RELEASE"\n'
                '    ;;\n'
                'esac\n'
                f'exec "{real_python}" "$@"\n', encoding="utf-8",
            )
            launcher.chmod(0o700)
            env = dict(os.environ, PATH=f"{tmp}:{os.environ['PATH']}",
                       STARTUP_READY=str(ready), STARTUP_RELEASE=str(release),
                       COMMAND_RAN=str(ran))
            supervisor_pid = None
            with (directory / "output").open("w") as output:
                process = subprocess.Popen(
                    ["bash", str(WRAPPER), "--packages", "example.com/p/pkg",
                     "--attempt-timeout-seconds", "5", "--", "bash", "-c",
                     'printf started > "$COMMAND_RAN"'],
                    cwd=ROOT, env=env, stdout=output, stderr=output,
                    start_new_session=True,
                )
                try:
                    await_file(ready, process)
                    supervisor_pid = int(ready.read_text())
                    self.assertNotEqual(os.getpgid(supervisor_pid), supervisor_pid)
                    process.terminate()
                    self.assertEqual(process.wait(timeout=8), 143)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(supervisor_pid, 0)
                    self.assertFalse(ran.exists(), "command started after cancellation")
                finally:
                    if supervisor_pid is not None:
                        try:
                            os.kill(supervisor_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if process.poll() is None:
                        process.terminate()
                    process.wait(timeout=8)
                    os.close(release_fd)


if __name__ == "__main__":
    unittest.main()
