# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Contract tests for required CI security-check coverage."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yaml"


def job_block(workflow: str, name: str) -> str:
    """Return one top-level GitHub Actions job without parsing YAML's `on` key."""
    marker = f"  {name}:\n"
    start = workflow.index(marker)
    next_job = re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", workflow[start + len(marker) :])
    end = len(workflow) if next_job is None else start + len(marker) + next_job.start()
    return workflow[start:end]


def step_script(job: str, name: str) -> str:
    """Return the shell body for one literal-block run step."""
    lines = job.splitlines()
    step = next(index for index, line in enumerate(lines) if line.strip() == f"- name: {name}")
    run = next(index for index in range(step + 1, len(lines)) if lines[index].strip() == "run: |")
    run_indent = len(lines[run]) - len(lines[run].lstrip())
    body: list[str] = []
    for line in lines[run + 1 :]:
        indent = len(line) - len(line.lstrip())
        if line.strip() and indent <= run_indent:
            break
        body.append(line)
    return textwrap.dedent("\n".join(body))


class CISecurityWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.govulncheck = job_block(self.workflow, "govulncheck")
        self.build = job_block(self.workflow, "build")

    def assert_govulncheck_contract(self, job: str) -> None:
        self.assertIn(
            "go install golang.org/x/vuln/cmd/govulncheck@v1.1.4",
            job,
        )
        self.assertRegex(job, r"(?m)^\s+govulncheck \./\.\.\. \|\| default_status=\$\?$")
        self.assertRegex(job, r"(?m)^\s+govulncheck -tags enterprise \./\.\.\. \|\| enterprise_status=\$\?$")

    def run_govulncheck_step(self, default_status: int, enterprise_status: int) -> tuple[int, list[str]]:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            calls = temp / "calls"
            executable = temp / "govulncheck"
            executable.write_text(
                """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$CALL_LOG"
if [ "$1" = "-tags" ]; then
  exit "$ENTERPRISE_STATUS"
fi
exit "$DEFAULT_STATUS"
""",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            env = os.environ.copy()
            env.update(
                {
                    "CALL_LOG": str(calls),
                    "DEFAULT_STATUS": str(default_status),
                    "ENTERPRISE_STATUS": str(enterprise_status),
                    "PATH": f"{temp}{os.pathsep}{env['PATH']}",
                }
            )
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", step_script(self.govulncheck, "Run govulncheck")],
                check=False,
                env=env,
                text=True,
                capture_output=True,
            )
            return result.returncode, calls.read_text(encoding="utf-8").splitlines()

    def test_required_govulncheck_covers_default_and_enterprise_reachability(self) -> None:
        # The required job must scan both graphs with the executable installed
        # from the pinned module version. Checking the job block rather than the
        # whole workflow prevents another job's command from satisfying this
        # contract while the required context silently loses coverage.
        self.assert_govulncheck_contract(self.govulncheck)

    def test_govulncheck_contract_rejects_missing_enterprise_scan(self) -> None:
        # A synthetic omission proves the predicate is not merely documenting
        # the desired command: it rejects the exact false-green regression.
        without_enterprise = self.govulncheck.replace(
            "          govulncheck -tags enterprise ./... || enterprise_status=$?\n",
            "",
            1,
        )
        with self.assertRaises(AssertionError):
            self.assert_govulncheck_contract(without_enterprise)

    def test_govulncheck_runs_both_graphs_before_reporting_failure(self) -> None:
        for default_status, enterprise_status, want_status in (
            (0, 0, 0),
            (7, 0, 1),
            (0, 9, 1),
            (7, 9, 1),
        ):
            with self.subTest(default_status=default_status, enterprise_status=enterprise_status):
                got_status, calls = self.run_govulncheck_step(default_status, enterprise_status)
                self.assertEqual(want_status, got_status)
                self.assertEqual(["./...", "-tags enterprise ./..."], calls)

    def test_required_build_keeps_helm_as_a_transitive_gate(self) -> None:
        # `helm` is not an independent required ruleset context. Its result is
        # intentionally carried by required `build`; dropping it would turn a
        # Helm failure into a mergeable advisory without any ruleset change.
        needs_match = re.search(r"(?m)^\s+needs:\s*\[([^]]+)\]$", self.build)
        self.assertIsNotNone(needs_match, "build needs list not found")
        build_needs = {
            dependency.strip()
            for dependency in needs_match.group(1).split(",")
            if dependency.strip()
        }
        self.assertIn("helm", build_needs)
        self.assertIn(
            "the required `build` context\n  # intentionally carries its result through `needs`",
            self.workflow,
        )

    def test_helm_transitive_gate_contract_rejects_removed_dependency(self) -> None:
        needs_match = re.search(r"(?m)^(\s+needs:\s*\[)([^]]+)(\])$", self.build)
        self.assertIsNotNone(needs_match, "build needs list not found")
        without_helm = self.build.replace(
            needs_match.group(0),
            f"{needs_match.group(1)}{','.join(need for need in needs_match.group(2).split(',') if need.strip() != 'helm')}{needs_match.group(3)}",
            1,
        )
        mutated_needs = re.search(r"(?m)^\s+needs:\s*\[([^]]+)\]$", without_helm)
        self.assertIsNotNone(mutated_needs, "mutated build needs list not found")
        with self.assertRaises(AssertionError):
            self.assertIn(
                "helm",
                {dependency.strip() for dependency in mutated_needs.group(1).split(",")},
            )


if __name__ == "__main__":
    unittest.main()
