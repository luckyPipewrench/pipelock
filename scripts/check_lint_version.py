# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Require the installed golangci-lint to match the CI action pin."""

import re
import subprocess
import sys
from pathlib import Path

from yaml_contracts import UniqueKeyLoader, yaml


def workflow_pin(path):
    workflow = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    if not isinstance(jobs, dict):
        raise ValueError("workflow jobs are missing or malformed")
    pins = []
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            raise ValueError("workflow steps are malformed")
        for step in steps:
            if not isinstance(step, dict):
                continue
            action = step.get("uses", "")
            if isinstance(action, str) and re.fullmatch(
                r"golangci/golangci-lint-action@[^\s]+", action
            ):
                settings = step.get("with")
                pin = settings.get("version") if isinstance(settings, dict) else None
                if not isinstance(pin, str) or not re.fullmatch(r"v\d+\.\d+\.\d+", pin):
                    raise ValueError("golangci-lint action version pin is missing or malformed")
                pins.append(pin.removeprefix("v"))
    if not pins or len(set(pins)) != 1:
        raise ValueError("golangci-lint action version pin is missing or ambiguous")
    return pins[0]


def main():
    if len(sys.argv) < 2:
        print("usage: check_lint_version.py WORKFLOW [WORKFLOW...]", file=sys.stderr)
        return 2
    try:
        pins = {workflow_pin(path) for path in sys.argv[1:]}
        if len(pins) != 1:
            raise ValueError("golangci-lint action version pins disagree across workflows")
        pin = pins.pop()
        output = subprocess.check_output(
            ["golangci-lint", "--version"], text=True, stderr=subprocess.STDOUT,
            timeout=10,
        )
        match = re.search(r"\bversion v?(\d+\.\d+\.\d+)(?![\w.+-])", output)
        if not match:
            raise ValueError("could not read the installed golangci-lint version")
        if match.group(1) != pin:
            raise ValueError(f"installed golangci-lint {match.group(1)} differs from CI pin {pin}")
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, yaml.YAMLError) as exc:
        print(f"check-lint-version: {exc}", file=sys.stderr)
        return 1
    print(f"golangci-lint {pin} matches CI")
    return 0


if __name__ == "__main__":
    sys.exit(main())
