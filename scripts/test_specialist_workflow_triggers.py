#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Topology contracts for advisory specialist workflow triggers.

These checks deliberately inspect the workflow source. A top-level path filter
means the workflow never starts, so a missing input would otherwise silently
remove an advisory signal rather than fail a job.
"""

import re
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

    def test_only_warning_only_hardening_report_leaves_prs(self):
        trigger = self.hardening[self.hardening.index("on:\n") : self.hardening.index("concurrency:")]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertIn("schedule:", trigger)
        self.assertIn("push:", trigger)
        self.assertIn("pull_request:", trigger)

        report = self.hardening[self.hardening.index("  hardening-report:\n") :]
        self.assertIn("if: ${{ github.event_name != 'pull_request' }}", report)
        for job in ("workflow-audit", "runtime-policy"):
            job_start = self.hardening.index(f"  {job}:\n")
            next_job = self.hardening.find("\n  ", job_start + 3)
            block = self.hardening[job_start:] if next_job == -1 else self.hardening[job_start:next_job]
            self.assertNotIn("github.event_name != 'pull_request'", block, job)


if __name__ == "__main__":
    unittest.main()
