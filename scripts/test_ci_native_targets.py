#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Regression contract for native CI target evidence."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yaml"
NATIVE_TARGETS = {
    "test-macos": ("macos-latest", "ARM64", "darwin/arm64", "bash"),
    "test-macos-intel": ("macos-15-intel", "X64", "darwin/amd64", "bash"),
    "test-windows": ("windows-latest", "X64", "windows/amd64", "pwsh"),
    "test-windows-arm64": ("windows-11-arm", "ARM64", "windows/arm64", "pwsh"),
    "test-linux-arm64": ("ubuntu-24.04-arm", "ARM64", "linux/arm64", "bash"),
}


def workflow_jobs() -> dict:
    """Load CI jobs from the public workflow."""
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def executable_lines(proof: str) -> list[str]:
    """Return non-comment shell lines with indentation removed."""
    return [
        stripped
        for line in proof.splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]


def expected_proof_lines(shell: str, runner_arch: str, go_target: str) -> list[str]:
    """Return the exact straight-line proof required for one native lane."""
    if shell == "pwsh":
        return [
            'Write-Output "runner architecture: $env:RUNNER_ARCH"',
            '$goTarget = "$(go env GOOS)/$(go env GOARCH)"',
            'Write-Output "Go target: $goTarget"',
            f'if ($env:RUNNER_ARCH -ne "{runner_arch}") '
            f'{{ throw "expected {runner_arch} runner, got $env:RUNNER_ARCH" }}',
            f'if ($goTarget -ne "{go_target}") '
            f'{{ throw "expected {go_target} Go target, got $goTarget" }}',
        ]
    return [
        "set -euo pipefail",
        'echo "runner architecture: $RUNNER_ARCH"',
        'go_target="$(go env GOOS)/$(go env GOARCH)"',
        'echo "Go target: $go_target"',
        f'test "$RUNNER_ARCH" = "{runner_arch}"',
        f'test "$go_target" = "{go_target}"',
    ]


def native_target_errors(jobs: dict) -> list[str]:
    """Return violations of the native target and architecture contract."""
    errors = []
    for job_name, (runner, runner_arch, go_target, shell) in NATIVE_TARGETS.items():
        job = jobs.get(job_name)
        if job is None:
            errors.append(f"missing {job_name}")
            continue
        if job.get("runs-on") != runner:
            errors.append(f"{job_name} does not use {runner}")
        steps = job.get("steps", [])
        proof_steps = [
            step
            for step in steps
            if step.get("name") == f"Verify native target is {go_target}"
        ]
        if len(proof_steps) != 1:
            errors.append(f"{job_name} does not have one architecture proof step")
            continue
        proof = proof_steps[0].get("run", "")
        actual_lines = executable_lines(proof)
        expected_lines = expected_proof_lines(shell, runner_arch, go_target)
        if shell == "pwsh":
            runner_predicate = f'if ($env:RUNNER_ARCH -ne "{runner_arch}")'
            target_predicate = f'if ($goTarget -ne "{go_target}")'
            target_source = '$goTarget = "$(go env GOOS)/$(go env GOARCH)"'
        else:
            runner_predicate = f'test "$RUNNER_ARCH" = "{runner_arch}"'
            target_predicate = f'test "$go_target" = "{go_target}"'
            target_source = 'go_target="$(go env GOOS)/$(go env GOARCH)"'
        if not any(line.startswith(runner_predicate) for line in actual_lines):
            errors.append(f"{job_name} does not verify runner architecture {runner_arch}")
        if target_source not in actual_lines or not any(
            line.startswith(target_predicate) for line in actual_lines
        ):
            errors.append(f"{job_name} does not verify native Go target {go_target}")
        if actual_lines != expected_lines:
            errors.append(f"{job_name} does not use the straight-line architecture proof")
    return errors


class NativeTargetWorkflowTest(unittest.TestCase):
    """Protect native job labels and their runtime architecture assertions."""

    def setUp(self):
        """Load a fresh workflow model for each mutation test."""
        self.jobs = workflow_jobs()

    def test_native_targets_have_pinned_architecture_evidence(self):
        """Accept the checked-in native target contract."""
        self.assertEqual(native_target_errors(self.jobs), [])

    def test_runner_label_drift_fails_the_contract(self):
        """Reject a runner label that no longer proves the claimed pair."""
        broken = copy.deepcopy(self.jobs)
        broken["test-macos-intel"]["runs-on"] = "macos-latest"
        self.assertIn(
            "test-macos-intel does not use macos-15-intel",
            native_target_errors(broken),
        )

    def test_missing_runtime_architecture_check_fails_the_contract(self):
        """Reject a proof step replaced with inert output."""
        broken = copy.deepcopy(self.jobs)
        proof = next(
            step
            for step in broken["test-windows-arm64"]["steps"]
            if step.get("name") == "Verify native target is windows/arm64"
        )
        proof["run"] = 'Write-Output "windows/arm64"'
        self.assertIn(
            "test-windows-arm64 does not verify runner architecture ARM64",
            native_target_errors(broken),
        )

    def test_inverted_predicates_fail_the_contract(self):
        """Reject success predicates whose direction is reversed."""
        broken = copy.deepcopy(self.jobs)
        mac_proof = next(
            step
            for step in broken["test-macos-intel"]["steps"]
            if step.get("name") == "Verify native target is darwin/amd64"
        )
        mac_proof["run"] = mac_proof["run"].replace(
            'test "$RUNNER_ARCH" = "X64"',
            'test "$RUNNER_ARCH" != "X64"',
        )
        windows_proof = next(
            step
            for step in broken["test-windows-arm64"]["steps"]
            if step.get("name") == "Verify native target is windows/arm64"
        )
        windows_proof["run"] = windows_proof["run"].replace(
            'if ($goTarget -ne "windows/arm64")',
            'if ($goTarget -eq "windows/arm64")',
        )
        errors = native_target_errors(broken)
        self.assertIn(
            "test-macos-intel does not verify runner architecture X64",
            errors,
        )
        self.assertIn(
            "test-windows-arm64 does not verify native Go target windows/arm64",
            errors,
        )

    def test_commented_and_echoed_predicates_fail_the_contract(self):
        """Reject predicates that exist only as comments or log text."""
        broken = copy.deepcopy(self.jobs)
        mac_proof = next(
            step
            for step in broken["test-macos-intel"]["steps"]
            if step.get("name") == "Verify native target is darwin/amd64"
        )
        mac_proof["run"] = mac_proof["run"].replace(
            'test "$RUNNER_ARCH" = "X64"',
            '# test "$RUNNER_ARCH" = "X64"',
        )
        windows_proof = next(
            step
            for step in broken["test-windows-arm64"]["steps"]
            if step.get("name") == "Verify native target is windows/arm64"
        )
        windows_proof["run"] = windows_proof["run"].replace(
            'if ($goTarget -ne "windows/arm64")',
            'Write-Output \'if ($goTarget -ne "windows/arm64")\'; if ($false)',
        )
        errors = native_target_errors(broken)
        self.assertIn(
            "test-macos-intel does not verify runner architecture X64",
            errors,
        )
        self.assertIn(
            "test-windows-arm64 does not use the straight-line architecture proof",
            errors,
        )

    def test_dead_control_flow_fails_the_contract(self):
        """Reject valid predicates wrapped in unreachable shell control flow."""
        broken = copy.deepcopy(self.jobs)
        proof = next(
            step
            for step in broken["test-linux-arm64"]["steps"]
            if step.get("name") == "Verify native target is linux/arm64"
        )
        proof["run"] = f"if false; then\n{proof['run']}fi\n"
        self.assertIn(
            "test-linux-arm64 does not use the straight-line architecture proof",
            native_target_errors(broken),
        )


if __name__ == "__main__":
    unittest.main()
