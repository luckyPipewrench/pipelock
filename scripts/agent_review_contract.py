#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Validate callers and repository profiles as bounded data, never executable code."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import re
import stat
import tomllib

# Same limit and no-symlink reader as the existing review caller contract.
MAX_DATA_BYTES = 65536
LOCAL_CALL = "./.github/workflows/agent-review-reusable.yaml"
REMOTE_CALL = "pipelab-org/pipelock/.github/workflows/agent-review-reusable.yaml@"
EXPECTED_CALLER = r"""name: PR-Agent review

on:
  # Default-branch code only; the identity gate and fork admission are tested.
  issue_comment: # zizmor: ignore[dangerous-triggers]
    types: [created]

permissions: {}

jobs:
  review:
    if: >-
      github.event_name == 'issue_comment' &&
      github.event.action == 'created' &&
      github.actor == 'luckyPipewrench' &&
      github.actor_id == '142104046' &&
      github.run_attempt == '1' &&
      github.triggering_actor == 'luckyPipewrench' &&
      github.event.comment.user.login == 'luckyPipewrench' &&
      github.event.comment.user.id == 142104046 &&
      github.event.comment.user.type == 'User' &&
      github.event.comment.author_association == 'MEMBER' &&
      github.event.issue.pull_request &&
      github.event.comment.body == '/agent-review'
    permissions:
      contents: read
      issues: write
      pull-requests: write
    uses: ./.github/workflows/agent-review-reusable.yaml
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      ANTHROPIC_API_KEY_2: ${{ secrets.ANTHROPIC_API_KEY_2 }}
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
"""


def read_data(path):
    """Read bounded UTF-8 data without following any path-component symlink."""
    path = pathlib.Path(path)
    if ".." in path.parts:
        raise ValueError("review data path must not traverse parents")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(path.anchor if path.is_absolute() else ".", directory_flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_DATA_BYTES:
                raise ValueError("review data must be a bounded regular file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(MAX_DATA_BYTES + 1)
            if len(data) > MAX_DATA_BYTES:
                raise ValueError("review data exceeds the data limit")
            return data.decode("utf-8")
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def validate_caller(path, source_sha, *, allow_local=False):
    """The trusted validator's source pin is authority, never the proposed pin."""
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("reviewer source must be a full immutable SHA")
    text = read_data(path)
    expected = EXPECTED_CALLER.replace(LOCAL_CALL, REMOTE_CALL + source_sha + " # main")
    if text != expected and not (allow_local and text == EXPECTED_CALLER):
        raise ValueError("caller differs from the trusted maintainer-gated definition")
    return source_sha


def load_profile(path):
    """The initial profile API permits only instructions and explicit exclusions."""
    raw = read_data(path)
    data = tomllib.loads(raw)
    if (set(data) != {"review", "ignore"}
            or not isinstance(data["review"], dict)
            or not isinstance(data["ignore"], dict)
            or set(data["review"]) != {"instructions"}
            or set(data["ignore"]) != {"glob"}):
        raise ValueError("profile permits only review.instructions and ignore.glob")
    instructions, globs = data["review"]["instructions"], data["ignore"]["glob"]
    if (not isinstance(instructions, str) or not instructions.strip()
            or not isinstance(globs, list)
            or any(not isinstance(g, str) or not g for g in globs)):
        raise ValueError("profile instructions and exclusions have invalid types or values")
    return data, hashlib.sha256(raw.encode("utf-8")).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    try:
        validate_caller(args.root / ".github/workflows/agent-review.yaml", args.source_sha,
                        allow_local=os.environ.get("GITHUB_REPOSITORY") == "pipelab-org/pipelock")
        load_profile(args.root / ".github/agent-review.toml")
    except (OSError, ValueError):
        # Paths and parser messages can contain proposed content. Fixed output only.
        parser.exit(1, "Invalid review caller or profile\n")
    print("Review caller and profile contract passed")


if __name__ == "__main__":
    main()
