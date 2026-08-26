# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Contract tests for required CI security-check coverage."""

from __future__ import annotations

import re
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
        self.assertRegex(job, r"(?m)^\s+govulncheck \./\.\.\.$")
        self.assertRegex(job, r"(?m)^\s+govulncheck -tags enterprise \./\.\.\.$")

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
            "          govulncheck -tags enterprise ./...\n",
            "",
            1,
        )
        with self.assertRaises(AssertionError):
            self.assert_govulncheck_contract(without_enterprise)

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
