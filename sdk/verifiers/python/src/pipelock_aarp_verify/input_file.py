# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Bound reads of verifier artifacts supplied by another trust domain."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

MAX_VERIFIER_INPUT_BYTES = 8 << 20
MAX_RECORDER_LINE_BYTES = 1 << 20


def read_verifier_file(path: str | Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise OSError("input must be a regular file")
        if info.st_size > MAX_VERIFIER_INPUT_BYTES:
            raise OSError(f"input exceeds {MAX_VERIFIER_INPUT_BYTES} bytes")
        data = stream.read(MAX_VERIFIER_INPUT_BYTES + 1)
        if len(data) > MAX_VERIFIER_INPUT_BYTES:
            raise OSError(f"input exceeds {MAX_VERIFIER_INPUT_BYTES} bytes")
        return data


def iter_verifier_jsonl_lines(path: str | Path) -> Iterator[bytes]:
    """Yield bounded JSONL lines without imposing a whole-history byte cap."""
    try:
        path_before = os.stat(path)
    except OSError as exc:
        raise OSError("input changed while opening") from exc
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    initial = os.fstat(fd)
    if not stat.S_ISREG(initial.st_mode):
        os.close(fd)
        raise OSError("input must be a regular file")
    if (initial.st_dev, initial.st_ino) != (path_before.st_dev, path_before.st_ino):
        os.close(fd)
        raise OSError("input changed while opening")
    with os.fdopen(fd, "rb") as stream:
        before = initial
        remaining = initial.st_size
        try:
            while remaining > 0:
                # A recorder line may contain a 1 MiB payload followed by CRLF.
                # Read one extra byte so an overlong line is detected without
                # allocating based on the file's total size.
                line = stream.readline(min(MAX_RECORDER_LINE_BYTES + 3, remaining))
                if not line:
                    break
                remaining -= len(line)
                payload = line[:-1] if line.endswith(b"\n") else line
                if payload.endswith(b"\r") and line.endswith(b"\r\n"):
                    payload = payload[:-1]
                if len(payload) > MAX_RECORDER_LINE_BYTES or len(line) > MAX_RECORDER_LINE_BYTES + 2:
                    raise OSError(
                        f"line exceeds {MAX_RECORDER_LINE_BYTES}-byte recorder entry limit"
                    )
                yield line
        finally:
            after = os.fstat(stream.fileno())
            try:
                path_after = os.stat(path)
            except OSError as exc:
                raise OSError("input changed while reading") from exc
            # Unix ctime catches an ordinary same-inode overwrite even when an
            # operator restores mtime. On Windows or coarse-timestamp filesystems,
            # stat timestamps cannot prove an atomic snapshot.
            if (
                before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns
                or path_after.st_dev != before.st_dev
                or path_after.st_ino != before.st_ino
            ):
                raise OSError("input changed while reading")
