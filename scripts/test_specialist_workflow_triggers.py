#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Topology contracts for advisory specialist workflow triggers.

These checks deliberately inspect the workflow source. A top-level path filter
means the workflow never starts, so a missing input would otherwise silently
remove an advisory signal rather than fail a job.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def event_block(workflow: str, event: str) -> str:
    marker = f"  {event}:\n"
    start = workflow.index(marker) + len(marker)
    next_event = re.search(r"(?m)^  [a-z_]+:\n", workflow[start:])
    return workflow[start:] if next_event is None else workflow[start : start + next_event.start()]


def event_paths(workflow: str, event: str) -> list[str]:
    block = event_block(workflow, event)
    paths_start = block.index("    paths:\n") + len("    paths:\n")
    paths = []
    for line in block[paths_start:].splitlines():
        if line.startswith("      #"):
            continue
        if not line.startswith("      - "):
            break
        paths.append(line.removeprefix("      - ").strip("'"))
    return paths


def job_block(workflow: str, job: str) -> str:
    marker = f"  {job}:\n"
    start = workflow.index(marker)
    next_job = re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", workflow[start + len(marker) :])
    end = len(workflow) if next_job is None else start + len(marker) + next_job.start()
    return workflow[start:end]


def step_run_script(workflow: str, job: str, step: str) -> str:
    """Return the shell body for one named workflow step."""
    block = job_block(workflow, job)
    step_marker = f"      - name: {step}\n"
    step_start = block.index(step_marker) + len(step_marker)
    run_marker = "        run: |\n"
    run_start = block.index(run_marker, step_start) + len(run_marker)
    lines = []
    for line in block[run_start:].splitlines():
        if line and not line.startswith("          "):
            break
        lines.append(line[10:] if line else "")
    return "\n".join(lines)


def matches(pattern: str, path: str) -> bool:
    """Match the small GitHub Actions glob subset used by these workflows."""
    expression = re.escape(pattern)
    expression = expression.replace(r"\*\*/", r"(?:.*/)?")
    expression = expression.replace(r"\*\*", r".*")
    expression = expression.replace(r"\*", r"[^/]*")
    return re.fullmatch(expression, path) is not None


def is_selected(paths: list[str], changed_path: str) -> bool:
    return any(matches(pattern, changed_path) for pattern in paths)


class SpecialistWorkflowTriggerTest(unittest.TestCase):
    def setUp(self):
        self.verifiers = (WORKFLOWS / "verifiers.yaml").read_text(encoding="utf-8")
        self.examples = (WORKFLOWS / "example-verification.yaml").read_text(encoding="utf-8")
        self.fuzz = (WORKFLOWS / "clusterfuzzlite.yaml").read_text(encoding="utf-8")
        self.hardening = (WORKFLOWS / "hardening.yaml").read_text(encoding="utf-8")
        self.hardening_report = (WORKFLOWS / "hardening-report.yaml").read_text(encoding="utf-8")

    def test_verifier_push_and_pr_inputs_are_identical_and_conservative(self):
        push_paths = event_paths(self.verifiers, "push")
        pull_request_paths = event_paths(self.verifiers, "pull_request")
        self.assertEqual(push_paths, pull_request_paths)
        for expected in (
            "go.mod",
            "go.sum",
            "go.work",
            "go.work.sum",
            "cmd/pipelock/**",
            "cmd/pipelock-verifier/**",
            "internal/**",
            "docs/specs/**",
            "sdk/verifiers/**",
            "sdk/audit-packet/**",
            "sdk/conformance/**",
            ".github/workflows/verifiers.yaml",
        ):
            self.assertIn(expected, push_paths)

        for changed in (
            "cmd/pipelock/main.go",
            "cmd/pipelock-verifier/main.go",
            "internal/receipt/emitter.go",
            "sdk/verifiers/python/requirements.txt",
            "sdk/verifiers/rust/Cargo.lock",
            "sdk/verifiers/ts/package-lock.json",
            "sdk/conformance/corpus-gate.sh",
            "sdk/audit-packet/v0.json",
        ):
            self.assertTrue(is_selected(push_paths, changed), changed)
        for unrelated in (
            "README.md",
            "cmd/license-service/main.go",
            "cmd/pipelock-verifier-wasm/main.go",
            "docs/guides/quickstart.md",
            "website/index.html",
        ):
            self.assertFalse(is_selected(push_paths, unrelated), unrelated)

    def test_example_push_and_pr_inputs_stay_equivalent(self):
        self.assertEqual(
            event_paths(self.examples, "push"),
            event_paths(self.examples, "pull_request"),
        )

    def test_clusterfuzz_selects_actual_fuzzer_inputs_but_not_docs(self):
        paths = event_paths(self.fuzz, "pull_request")
        for expected in (
            "**/*.go",
            "go.mod",
            "go.sum",
            "go.work",
            "go.work.sum",
            "**/testdata/fuzz/**",
            ".clusterfuzzlite/**",
            ".github/workflows/clusterfuzzlite.yaml",
        ):
            self.assertIn(expected, paths)
        for changed in (
            "internal/scanner/scanner_fuzz_test.go",
            "cmd/pipelock/main.go",
            "internal/scanner/testdata/fuzz/FuzzScanURL/seed",
            ".clusterfuzzlite/build.sh",
            "go.mod",
        ):
            self.assertTrue(is_selected(paths, changed), changed)
        for unrelated in ("README.md", "docs/specs/receipt-v2.md", "examples/quickstart/README.md"):
            self.assertFalse(is_selected(paths, unrelated), unrelated)

    def test_warning_only_hardening_report_never_creates_a_pr_check(self):
        trigger = self.hardening[self.hardening.index("on:\n") : self.hardening.index("concurrency:")]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertIn("schedule:", trigger)
        self.assertIn("push:", trigger)
        self.assertIn("pull_request:", trigger)
        self.assertNotIn("hardening-report:", self.hardening)

        report_trigger = self.hardening_report[
            self.hardening_report.index("on:\n") : self.hardening_report.index("concurrency:")
        ]
        self.assertIn("workflow_dispatch:", report_trigger)
        self.assertIn("schedule:", report_trigger)
        self.assertIn("push:", report_trigger)
        self.assertNotIn("pull_request:", report_trigger)
        # A push scoped to main keeps the report off PR head commits. A
        # broadened branch filter would run on the PR's head SHA and post a
        # hardening-report check back onto the PR, which is the check this
        # split exists to suppress.
        self.assertIn("branches: [main]", report_trigger)
        self.assertIn("hardening-report:", self.hardening_report)
        report_job = job_block(self.hardening_report, "hardening-report")
        self.assertIn("continue-on-error: true", report_job)
        self.assertIn("if: always()", report_job)
        self.assertIn("--output.json.path=hardening-debt.json", report_job)
        self.assertIn('case "$DEBT_OUTCOME" in', report_job)
        self.assertIn("incomplete because the lint action failed without producing findings", report_job)
        self.assertIn("incomplete because the lint action ended with outcome", report_job)
        for job in ("workflow-audit", "runtime-policy"):
            self.assertNotIn(
                "github.event_name != 'pull_request'",
                job_block(self.hardening, job),
                job,
            )

    def test_hardening_report_distinguishes_findings_from_incomplete_audits(self):
        script = step_run_script(self.hardening_report, "hardening-report", "Summarize hardening report")
        cases = (
            ("success", None, "clean for configured linters", "incomplete"),
            ("failure", '{"Issues":[{"Text":"duplicate"}]}', "debt findings present", "incomplete"),
            ("failure", None, "incomplete because the lint action failed", "debt findings present"),
            ("cancelled", None, "incomplete because the lint action ended", "clean for configured linters"),
        )
        for outcome, report, expected, forbidden in cases:
            with self.subTest(outcome=outcome, report=report):
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_path = Path(temp_dir)
                    if report is not None:
                        (temp_path / "hardening-debt.json").write_text(report, encoding="utf-8")
                    summary = temp_path / "summary.md"
                    env = os.environ | {
                        "DEBT_OUTCOME": outcome,
                        "GITHUB_STEP_SUMMARY": str(summary),
                    }
                    subprocess.run(
                        ["bash", "-eu", "-o", "pipefail", "-c", script],
                        cwd=temp_path,
                        env=env,
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    summary_text = summary.read_text(encoding="utf-8")
                    self.assertIn(expected, summary_text)
                    self.assertNotIn(forbidden, summary_text)

    def test_job_block_includes_conditions_after_runs_on(self):
        workflow = """jobs:
  workflow-audit:
    runs-on: ubuntu-latest
    if: ${{ github.event_name != 'pull_request' }}
    steps:
      - run: echo audit
  runtime-policy:
    runs-on: ubuntu-latest
"""
        self.assertIn(
            "github.event_name != 'pull_request'",
            job_block(workflow, "workflow-audit"),
        )


if __name__ == "__main__":
    unittest.main()
