# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Bound reads of verifier artifacts supplied by another trust domain."""

from __future__ import annotations

import os
import stat
from pathlib import Path

MAX_VERIFIER_INPUT_BYTES = 8 << 20


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
