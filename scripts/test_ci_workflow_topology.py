#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Regression contract for CI's required-test topology.

The required check display names are a public merge contract. More importantly,
each Go-minor aggregate must only consume evidence from that minor; otherwise a
failure in one matrix cell is reported as a failure in both required checks.
"""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yaml"
SHARDS = {"proxy", "scanner", "mcp", "rest-0", "rest-1", "rest-2"}
MINORS = ("125", "126")
SCAN_SUCCESS_CONDITION = "${{ needs.security-scan.result == 'success' }}"
ALWAYS_CONDITION = "${{ always() }}"
REQUIRED_PRODUCERS = {
    "security-scan",
    "test-go125",
    "test-go126",
    "test-macos",
    "lint",
    "build",
    "govulncheck",
}


def step_runs_unconditionally(step: dict) -> bool:
    """Return True when a step cannot skip after its job has already started.

    A skipped compatibility or summary step turns `if: always()` into success:
    prior steps were skipped, not failed, so GitHub reports the job green.
    """
    return step.get("if") in (None, ALWAYS_CONDITION, "always()")


def workflow_jobs():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def topology_errors(jobs: dict) -> list[str]:
    """Return every broken topology invariant for useful negative fixtures."""
    errors = []
    standalone_replay_jobs = [job for job in jobs if job.startswith("test-replay-go")]
    if standalone_replay_jobs:
        errors.append(f"standalone replay jobs remain: {sorted(standalone_replay_jobs)}")
    for minor in MINORS:
        oss = f"test-oss-go{minor}"
        enterprise = f"test-enterprise-go{minor}"
        aggregate = f"test-go{minor}"
        for producer in (oss, enterprise, aggregate):
            if producer not in jobs:
                errors.append(f"missing {producer}")
        if any(producer not in jobs for producer in (oss, enterprise, aggregate)):
            continue

        if set(jobs[oss]["strategy"]["matrix"]["shard"]) != SHARDS:
            errors.append(f"{oss} does not preserve six shards")
        if set(jobs[enterprise]["strategy"]["matrix"]["shard"]) != SHARDS:
            errors.append(f"{enterprise} does not preserve six shards")

        aggregate_needs = set(jobs[aggregate].get("needs", []))
        expected = {"security-scan", oss, enterprise}
        if minor == "125":
            expected.add("test-subprocess-coverage")
        if aggregate_needs != expected:
            errors.append(f"{aggregate} needs {sorted(aggregate_needs)}, expected {sorted(expected)}")
        opposite = "126" if minor == "125" else "125"
        if any(f"go{opposite}" in dependency for dependency in aggregate_needs):
            errors.append(f"{aggregate} consumes Go {opposite} evidence")
        if jobs[aggregate].get("name") != f"test (1.{minor[1:]})":
            errors.append(f"{aggregate} changed its required display name")
        if jobs[aggregate].get("if") != ALWAYS_CONDITION:
            errors.append(f"{aggregate} is skipped instead of failing when a dependency fails")

        aggregate_steps = jobs[aggregate].get("steps", [])
        if sum(step.get("run") == "make test-replay-harness" for step in aggregate_steps) != 1:
            errors.append(f"{aggregate} is not a singleton replay producer")
        setup_steps = [step for step in aggregate_steps if step.get("name") == "Set up Go"]
        if len(setup_steps) != 1 or setup_steps[0].get("with", {}).get("go-version") != f"1.{minor[1:]}":
            errors.append(f"{aggregate} does not run replay under Go 1.{minor[1:]}")
        execution_steps = [
            step
            for step in aggregate_steps
            if step.get("name") in {"Set up Go", "Replay harness (deterministic regression)"}
            or "uses" in step
        ]
        if len(execution_steps) != 3 or any(
            step.get("if") != SCAN_SUCCESS_CONDITION for step in execution_steps
        ):
            errors.append(f"{aggregate} can execute PR code after a failed security scan")
        gate_steps = [
            step for step in aggregate_steps if step.get("name") == "Required check compatibility gate"
        ]
        if len(gate_steps) != 1 or 'test "${{ needs.security-scan.result }}" = "success"' not in gate_steps[0].get("run", ""):
            errors.append(f"{aggregate} does not red on a failed security scan")
        elif not step_runs_unconditionally(gate_steps[0]):
            errors.append(f"{aggregate} compatibility gate can skip and green after failed evidence")
        for producer in (oss, enterprise):
            if any(step.get("run") == "make test-replay-harness" for step in jobs[producer].get("steps", [])):
                errors.append(f"{producer} runs replay inside every shard")

    missing_required = REQUIRED_PRODUCERS - jobs.keys()
    if missing_required:
        errors.append(f"missing required producers: {sorted(missing_required)}")

    summary = jobs.get("pipelock-ci-summary")
    if summary is None:
        errors.append("missing advisory summary")
    else:
        if summary.get("name") != "Pipelock CI Summary":
            errors.append("summary changed its operator-facing name")
        if summary.get("if") != ALWAYS_CONDITION:
            errors.append("summary must run after failed or cancelled evidence")
        summary_needs = set(summary.get("needs", []))
        if not REQUIRED_PRODUCERS <= summary_needs:
            errors.append("summary does not consume every in-workflow required producer")
        summary_steps = summary.get("steps", [])
        if not summary_steps:
            errors.append("summary has no reporting step")
            return errors
        report_step = summary_steps[0]
        if not step_runs_unconditionally(report_step):
            errors.append("summary reporting step can skip and green after failed evidence")
        summary_run = report_step.get("run", "")
        for required_context in (
            "security-scan",
            "test (1.25)",
            "test (1.26)",
            "test-macos",
            "lint",
            "build",
            "govulncheck",
        ):
            if f"record_result '{required_context}'" not in summary_run:
                errors.append(f"summary does not report {required_context}")
        if "*) failed=1 ;;" not in summary_run:
            errors.append("summary does not fail closed on non-success evidence")
        if "CodeQL is separately required" not in summary_run:
            errors.append("summary does not explain its CodeQL boundary")
    return errors


class CIWorkflowTopologyTest(unittest.TestCase):
    def setUp(self):
        self.jobs = workflow_jobs()

    def test_topology_is_truthful_and_complete(self):
        self.assertEqual(topology_errors(self.jobs), [])

    def test_go126_failure_cannot_red_go125_aggregate(self):
        aggregate_needs = set(self.jobs["test-go125"]["needs"])
        self.assertFalse(
            any("go126" in dependency for dependency in aggregate_needs),
            "a Go 1.26-only failure must not reach test (1.25)",
        )

    def test_cross_minor_wiring_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        broken["test-go125"]["needs"].append("test-oss-go126")
        self.assertIn("test-go125 consumes Go 126 evidence", topology_errors(broken))

    def test_missing_replay_step_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        broken["test-go126"]["steps"] = [
            step
            for step in broken["test-go126"]["steps"]
            if step.get("run") != "make test-replay-harness"
        ]
        errors = topology_errors(broken)
        self.assertIn("test-go126 is not a singleton replay producer", errors)

    def test_replay_inside_a_shard_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        broken["test-oss-go125"]["steps"].append(
            {"name": "Replay harness", "run": "make test-replay-harness"}
        )
        self.assertIn("test-oss-go125 runs replay inside every shard", topology_errors(broken))

    def test_unguarded_replay_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        for step in broken["test-go126"]["steps"]:
            if step.get("run") == "make test-replay-harness":
                del step["if"]
        self.assertIn(
            "test-go126 can execute PR code after a failed security scan",
            topology_errors(broken),
        )

    def test_aggregate_without_always_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        del broken["test-go125"]["if"]
        self.assertIn(
            "test-go125 is skipped instead of failing when a dependency fails",
            topology_errors(broken),
        )

    def test_skip_gated_compatibility_gate_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        for step in broken["test-go126"]["steps"]:
            if step.get("name") == "Required check compatibility gate":
                step["if"] = SCAN_SUCCESS_CONDITION
        self.assertIn(
            "test-go126 compatibility gate can skip and green after failed evidence",
            topology_errors(broken),
        )

    def test_skip_gated_summary_step_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        broken["pipelock-ci-summary"]["steps"][0]["if"] = SCAN_SUCCESS_CONDITION
        self.assertIn(
            "summary reporting step can skip and green after failed evidence",
            topology_errors(broken),
        )


if __name__ == "__main__":
    unittest.main()
