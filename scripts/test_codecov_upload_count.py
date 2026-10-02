#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Contracts for the Codecov upload topology checker."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

import yaml

from check_codecov_upload_count import TopologyError, check, main, upload_count


ROOT = Path(__file__).resolve().parents[1]
ACTION = "codecov/codecov-action@0123456789abcdef"


class UploadCountTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = {
            "jobs": {
                "first": {"strategy": {"matrix": {"shard": ["a", "b"]}}, "steps": [{"name": "Renamed", "uses": ACTION}]},
                "second": {"strategy": {"matrix": {"shard": ["c", "d", "e"]}}, "steps": [{"uses": ACTION}]},
                "single": {"steps": [{"uses": ACTION}]},
                "unrelated": {"steps": [{"uses": "actions/checkout@abc"}]},
            }
        }

    def test_renamed_steps_and_unequal_matrices(self) -> None:
        self.assertEqual(upload_count(self.workflow), 6)

    def test_static_axes_exclusion_and_include(self) -> None:
        job = self.workflow["jobs"]["first"]
        job["strategy"]["matrix"] = {
            "shard": ["a", "b"], "os": ["linux", "mac"],
            "exclude": [{"shard": "b", "os": "mac"}],
            "include": [{"shard": "extra", "os": "linux"}, {"shard": "a", "os": "linux", "flag": "yes"}],
        }
        self.assertEqual(upload_count(self.workflow), 8)

    def test_static_conditions(self) -> None:
        self.workflow["jobs"]["first"]["if"] = False
        self.workflow["jobs"]["single"]["steps"][0]["if"] = False
        self.assertEqual(upload_count(self.workflow), 3)

    def test_action_name_case(self) -> None:
        self.workflow["jobs"]["single"]["steps"][0]["uses"] = ACTION.upper()
        self.assertEqual(upload_count(self.workflow), 6)

    def test_strategy_without_matrix_is_one_run(self) -> None:
        for strategy in ({}, {"fail-fast": False}, {"max-parallel": 1}):
            with self.subTest(strategy=strategy):
                self.workflow["jobs"]["single"]["strategy"] = strategy
                self.assertEqual(upload_count(self.workflow), 6)
        for matrix in (None, [], "invalid"):
            with self.subTest(matrix=matrix):
                self.workflow["jobs"]["single"]["strategy"] = {"matrix": matrix}
                with self.assertRaises(TopologyError):
                    upload_count(self.workflow)

    def test_dry_run_does_not_upload(self) -> None:
        step = self.workflow["jobs"]["first"]["steps"][0]
        for value in (True, "true"):
            step["with"] = {"dry_run": value}
            self.assertEqual(upload_count(self.workflow), 4)
        for value in (False, "false"):
            step["with"] = {"dry_run": value}
            self.assertEqual(upload_count(self.workflow), 6)

    def test_unsupported_upload_modes_fail(self) -> None:
        step = self.workflow["jobs"]["single"]["steps"][0]
        for settings in (
            {"dry_run": "${{ inputs.dry_run }}"}, {"dry_run": "maybe"},
            {"run_command": "send-notifications"}, {"run_command": "empty-upload"},
            {"report_type": "test_results"}, "malformed",
        ):
            with self.subTest(settings=settings):
                step["with"] = settings
                with self.assertRaises(TopologyError):
                    upload_count(self.workflow)

    def test_include_only_rows_remain_distinct(self) -> None:
        self.workflow["jobs"]["first"]["strategy"]["matrix"] = {
            "include": [{"shard": "a"}, {"shard": "b"}],
        }
        self.assertEqual(upload_count(self.workflow), 6)
        self.workflow["jobs"]["first"]["strategy"]["matrix"] = {
            "include": [{"shard": "a"}, {"flag": "x"}],
        }
        self.assertEqual(upload_count(self.workflow), 6)

    def test_github_documented_include_expansion(self) -> None:
        # GitHub's run-job-variations example produces six independent jobs.
        self.workflow["jobs"]["first"]["strategy"]["matrix"] = {
            "fruit": ["apple", "pear"], "animal": ["cat", "dog"],
            "include": [
                {"color": "green"}, {"color": "pink", "animal": "cat"},
                {"fruit": "apple", "shape": "circle"}, {"fruit": "banana"},
                {"fruit": "banana", "animal": "cat"},
            ],
        }
        self.assertEqual(upload_count(self.workflow), 10)

    def test_unsupported_conditions_and_dynamic_matrix(self) -> None:
        for mutation in (
            lambda w: w["jobs"]["first"].update({"if": "${{ github.ref == 'main' }}"}),
            lambda w: w["jobs"]["first"]["steps"][0].update({"if": "${{ matrix.shard == 'a' }}"}),
            lambda w: w["jobs"]["first"]["strategy"].update({"matrix": "${{ fromJSON(needs.x.outputs.matrix) }}"}),
        ):
            with self.subTest(mutation=mutation):
                workflow = copy.deepcopy(self.workflow)
                mutation(workflow)
                with self.assertRaises(TopologyError):
                    upload_count(workflow)

    def test_malformed_and_missing_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workflow, codecov = Path(temp) / "ci.yaml", Path(temp) / "codecov.yml"
            with self.assertRaises(TopologyError):
                check(workflow, codecov)
            workflow.write_text("jobs: [")
            codecov.write_text("codecov: {notify: {after_n_builds: 1}}")
            with self.assertRaises(TopologyError):
                check(workflow, codecov)
            workflow.write_text(yaml.safe_dump(self.workflow))
            codecov.write_text("codecov: {notify: {after_n_builds: nope}}")
            with self.assertRaises(TopologyError):
                check(workflow, codecov)

    def test_duplicate_keys_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workflow, codecov = Path(temp) / "ci.yaml", Path(temp) / "codecov.yml"
            workflow.write_text(yaml.safe_dump(self.workflow))
            codecov.write_text("codecov: {notify: {after_n_builds: 6, after_n_builds: 6}}")
            with self.assertRaisesRegex(TopologyError, "duplicate YAML key"):
                check(workflow, codecov)
            codecov.write_text("codecov: {notify: {after_n_builds: 6}}")
            workflow.write_text("jobs: {}\njobs: {}\n")
            with self.assertRaisesRegex(TopologyError, "duplicate YAML key"):
                check(workflow, codecov)

    def test_mismatch_exit_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workflow, codecov = Path(temp) / "ci.yaml", Path(temp) / "codecov.yml"
            workflow.write_text(yaml.safe_dump(self.workflow))
            codecov.write_text("codecov: {notify: {after_n_builds: 5}}")
            self.assertEqual(main(["checker", str(workflow), str(codecov)]), 1)

    def test_current_workflow(self) -> None:
        expected, actual = check(ROOT / ".github/workflows/ci.yaml", ROOT / "codecov.yml")
        self.assertEqual(expected, actual)

    def test_go126_variants_upload_their_own_profiles(self) -> None:
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yaml").read_text())["jobs"]
        for variant, profile in (("oss", "coverage-oss-"), ("enterprise", "coverage-")):
            with self.subTest(variant=variant):
                steps = jobs[f"test-{variant}-go126"]["steps"]
                uploads = [step for step in steps if str(step.get("uses", "")).startswith("codecov/codecov-action@")]
                self.assertEqual(len(uploads), 1)
                self.assertEqual(uploads[0]["with"]["files"], f"./{profile}${{{{ matrix.shard }}}}.out")
                commands = [line.strip() for step in steps for line in step.get("run", "").splitlines() if line.strip().startswith("go test ")]
                self.assertEqual(len(commands), 1)
                self.assertIn(f'-coverprofile="{profile}${{TEST_SHARD}}.out"', commands[0])


if __name__ == "__main__":
    unittest.main()
