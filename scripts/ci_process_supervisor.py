#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Own and reap one Linux CI command's children, including detached descendants.

Run this as a dedicated subprocess, never inside a shared test process. Child
adoption belongs to this process only; it supplies cleanup, not a security sandbox.
The caller owns the command deadline and may send TERM to request cleanup.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


CLEANUP_SECONDS = 2.0
SIGNAL_GRACE_SECONDS = 2.0


def enable_child_adoption() -> None:
    """Become the nearest surviving ancestor of this command's orphaned children."""
    if sys.platform != "linux":
        raise OSError("CI child adoption requires Linux")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot enable CI child adoption")


def reap_exited_children(process: subprocess.Popen[bytes]) -> bool:
    """Collect exited children without disturbing live ones or losing command status."""
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return False
        if pid == 0:
            return True
        if pid == process.pid:
            process.returncode = os.waitstatus_to_exitcode(status)


def interrupt_command(process: subprocess.Popen[bytes], signum: int) -> None:
    """Forward cancellation while the unreaped command still owns its group ID."""
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + SIGNAL_GRACE_SECONDS
    while reap_exited_children(process) and time.monotonic() < deadline:
        time.sleep(0.01)


def cleanup_children(
    process: subprocess.Popen[bytes], cleanup_processes: dict[int, str],
) -> tuple[bool, bool]:
    """Kill and reap only our children until adoption has exposed the entire tree."""
    deadline = time.monotonic() + CLEANUP_SECONDS
    had_live_descendants = False
    children_file = Path(f"/proc/self/task/{os.getpid()}/children")
    while True:
        children = [int(value) for value in children_file.read_text().split()]
        for pid in children:
            # No other thread or signal handler reaps children here. Their PIDs
            # cannot be recycled between this observation and the signal.
            exited = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            if exited is None:
                if pid != process.pid:
                    had_live_descendants = True
                if pid not in cleanup_processes:
                    try:
                        name = Path(f"/proc/{pid}/comm").read_text(errors="replace").strip()
                    except OSError:
                        name = "unavailable"
                    cleanup_processes[pid] = name
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        if not reap_exited_children(process):
            return True, had_live_descendants
        if time.monotonic() >= deadline:
            return False, had_live_descendants
        time.sleep(0.01)


def supervise(command: list[str], status_file: Path) -> int:
    """Preserve command status after cleanup, refusing an apparently clean leak."""
    received_signal = 0

    def interrupted(signum: int, _frame: object) -> None:
        nonlocal received_signal
        received_signal = signum

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    enable_child_adoption()
    if os.getsid(0) != os.getpid():
        os.setsid()
    if received_signal:
        status_file.write_text(json.dumps({
            "cleanup_complete": True,
            "live_descendants_after_command": False,
            "unexpected_live_descendants": False,
            "exit_code": 128 + received_signal,
        }) + "\n", encoding="utf-8")
        return 128 + received_signal
    process = subprocess.Popen(command, start_new_session=True)
    returncode = 125
    complete = False
    had_live_descendants = False
    cleanup_processes: dict[int, str] = {}
    try:
        while not received_signal:
            # Adopted zombies need collecting during the command as well as at
            # teardown. Otherwise a long-running test sees its killed child as
            # still present until the entire CI attempt finishes.
            reap_exited_children(process)
            result = process.returncode
            if result is not None:
                returncode = result if result >= 0 else 128 - result
                break
            time.sleep(0.01)
    finally:
        if received_signal:
            interrupt_command(process, received_signal)
        complete, had_live_descendants = cleanup_children(process, cleanup_processes)
        if received_signal:
            returncode = 128 + received_signal
        unexpected_descendants = returncode == 0 and had_live_descendants
        if not complete or unexpected_descendants:
            returncode = 125
        report = {
            "cleanup_complete": complete,
            "live_descendants_after_command": had_live_descendants,
            "unexpected_live_descendants": unexpected_descendants,
            "exit_code": returncode,
            "cleanup_processes": [
                {"pid": pid, "name": name} for pid, name in sorted(cleanup_processes.items())
            ],
        }
        status_file.write_text(json.dumps(report) + "\n", encoding="utf-8")
        if not complete or unexpected_descendants:
            # Preserve diagnosis before the wrapper removes its temporary report.
            # JSON escapes process-name controls; arguments and environment stay private.
            print("ci-process-supervisor: " + json.dumps(report), file=sys.stderr)
    return returncode


def main() -> int:
    """Launch one command in a dedicated child-adoption process."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status-file", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a command is required")
    try:
        return supervise(command, args.status_file)
    except OSError as exc:
        print(f"ci-process-supervisor: {exc}", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
