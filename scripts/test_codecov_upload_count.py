#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Contracts for the Codecov upload topology checker."""

from __future__ import annotations

import copy
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from check_codecov_upload_count import DOCS_ONLY_SKIP, MatrixBudget, TopologyError, cells, check, main, upload_count


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

    def test_documentation_only_skip_counts_as_a_full_run(self) -> None:
        self.workflow["jobs"]["first"]["if"] = DOCS_ONLY_SKIP
        self.assertEqual(upload_count(self.workflow), 6)
        # The classifier runs only on pull requests; the docs condition's
        # !cancelled() runs past it on a push, so it must not gate the count.
        self.workflow["jobs"]["changed-files"] = {
            "if": "${{ github.event_name == 'pull_request' }}",
            "steps": [{"run": "true"}],
        }
        self.workflow["jobs"]["first"]["needs"] = ["changed-files"]
        self.assertEqual(upload_count(self.workflow), 6)
        # Any other dynamic condition, including a broadened docs skip, is
        # refused rather than guessed at.
        self.workflow["jobs"]["first"]["if"] = DOCS_ONLY_SKIP.replace("}}", "&& github.actor != 'x' }}")
        with self.assertRaisesRegex(TopologyError, "unsupported condition"):
            upload_count(self.workflow)

    def test_boolean_numeric_matching_is_explicitly_unsupported(self) -> None:
        for operation in ("include", "exclude"):
            for left, right in ((False, 0), (True, 1), (0, False), (1.0, True)):
                for nested in (False, True):
                    a = {"value": left} if nested else left
                    b = {"value": right} if nested else right
                    matrix = {"a": [a], operation: [{"a": b}]}
                    with self.subTest(operation=operation, left=left, nested=nested):
                        with self.assertRaisesRegex(TopologyError, "mixed boolean/number"):
                            cells({"strategy": {"matrix": matrix}}, "mixed")
        self.assertTrue(MatrixBudget("bool").equal(True, True))
        self.assertFalse(MatrixBudget("bool").equal(True, False))
        self.assertTrue(MatrixBudget("numeric").equal(1, 1.0))

    def test_workflow_matrix_preserves_core_string_values(self) -> None:
        from yaml_contracts import WorkflowLoader
        workflow = yaml.load("""jobs:
  upload:
    strategy:
      matrix:
        flag: [on, true]
        exclude: [{flag: true}]
    steps:
      - uses: codecov/codecov-action@0123456789abcdef
""", Loader=WorkflowLoader)
        self.assertEqual(upload_count(workflow), 1)

    def test_dependency_reachability(self) -> None:
        jobs = self.workflow["jobs"]
        jobs["single"]["needs"] = "prepare"
        jobs["prepare"] = {"needs": ["unrelated"]}
        self.assertEqual(upload_count(self.workflow), 6)
        jobs["unrelated"]["if"] = False
        self.assertEqual(upload_count(self.workflow), 5)
        jobs["unrelated"]["if"] = "${{ inputs.enabled }}"
        with self.assertRaises(TopologyError):
            upload_count(self.workflow)
        jobs["unrelated"].pop("if")
        jobs["prepare"]["needs"] = ["single"]
        with self.assertRaisesRegex(TopologyError, "cyclic"):
            upload_count(self.workflow)
        for dependencies in (["missing"], None, 3, [3]):
            jobs["prepare"]["needs"] = dependencies
            with self.subTest(dependencies=dependencies), self.assertRaises(TopologyError):
                upload_count(self.workflow)

    def test_documented_object_axis(self) -> None:
        matrix = {"os": ["ubuntu-latest", "macos-latest"],
                  "node": [{"version": 14}, {"version": 20, "env": "NODE_OPTIONS=--openssl-legacy-provider"}]}
        self.assertEqual(len(cells({"strategy": {"matrix": matrix}}, "example")), 4)
        matrix["exclude"] = [{"os": "macos-latest", "node": {"version": 14}}]
        self.assertEqual(len(cells({"strategy": {"matrix": matrix}}, "example")), 3)
        matrix["node"][0]["version"] = "${{ inputs.version }}"
        with self.assertRaises(TopologyError):
            cells({"strategy": {"matrix": matrix}}, "example")

    def test_effective_matrix_limit(self) -> None:
        matrix = {"a": list(range(16)), "b": list(range(16))}
        self.assertEqual(len(cells({"strategy": {"matrix": matrix}}, "limit")), 256)
        matrix["b"] = list(range(17))
        with self.assertRaisesRegex(TopologyError, "256"):
            cells({"strategy": {"matrix": matrix}}, "limit")
        matrix["exclude"] = [{"a": 0}]
        self.assertEqual(len(cells({"strategy": {"matrix": matrix}}, "limit")), 255)
        matrix["include"] = [{"a": 0, "b": 0}]
        self.assertEqual(len(cells({"strategy": {"matrix": matrix}}, "limit")), 256)
        matrix["include"].append({"a": 0, "b": 1})
        with self.assertRaisesRegex(TopologyError, "256"):
            cells({"strategy": {"matrix": matrix}}, "limit")
        with self.assertRaisesRegex(TopologyError, "256"):
            cells({"strategy": {"matrix": {"include": [{"a": n} for n in range(257)]}}}, "limit")

    def test_cyclic_or_dynamic_object_is_rejected(self) -> None:
        cycle = {}
        cycle["self"] = cycle
        for value in (cycle, {"nested": {"version": "${{ inputs.version }}"}}, {"items": [1, 2]}):
            with self.subTest(value=repr(value)), self.assertRaises(TopologyError):
                cells({"strategy": {"matrix": {"node": [value]}}}, "object")

    def test_expansion_stops_at_first_excess_job(self) -> None:
        def combinations(*_):
            for number in range(257):
                yield (number,)
            self.fail("expanded beyond the first excess job")
        with patch("check_codecov_upload_count.itertools.product", combinations):
            with self.assertRaisesRegex(TopologyError, "256"):
                cells({"strategy": {"matrix": {"a": list(range(300))}}}, "limit")

    def test_nested_matching_consumes_validation_budget(self) -> None:
        matrices = [
            ({"a": [0, 1], "exclude": [{"a": n} for n in range(2, 12)]}, 140),
            ({"a": [0, 1], "include": [{"flag": str(n)} for n in range(10)]}, 160),
        ]
        for matrix, limit in matrices:
            with self.subTest(matrix=matrix):
                with patch("check_codecov_upload_count.MAX_MATRIX_WORK", 1000):
                    self.assertEqual(len(cells({"strategy": {"matrix": matrix}}, "budget")), 2)
                with patch("check_codecov_upload_count.MAX_MATRIX_WORK", limit):
                    # The input alone fits; repeated matching across rows does not.
                    single = dict(matrix, a=[0])
                    self.assertEqual(len(cells({"strategy": {"matrix": single}}, "budget")), 1)
                    with self.assertRaisesRegex(TopologyError, "validation work budget"):
                        cells({"strategy": {"matrix": matrix}}, "budget")

    def test_nested_objects_consume_comparison_budget(self) -> None:
        left = {"outer": {"a": "value", "b": "other"}}
        right = copy.deepcopy(left)
        with patch("check_codecov_upload_count.MAX_MATRIX_WORK", 100):
            self.assertTrue(MatrixBudget("nested").equal(left, right))
            right["outer"]["b"] = "different"
            self.assertFalse(MatrixBudget("nested").equal(left, right))
        with patch("check_codecov_upload_count.MAX_MATRIX_WORK", 10):
            with self.assertRaisesRegex(TopologyError, "validation work budget"):
                MatrixBudget("nested").equal(left, copy.deepcopy(left))

    def test_excluded_candidates_still_consume_work(self) -> None:
        matrix = {"a": [0, 1, 2], "b": [0, 1, 2],
                  "exclude": [{"a": n} for n in range(3)], "include": [{"a": 3}]}
        with patch("check_codecov_upload_count.MAX_MATRIX_WORK", 1000):
            self.assertEqual(cells({"strategy": {"matrix": matrix}}, "budget"), [{"a": 3}])
        with patch("check_codecov_upload_count.MAX_MATRIX_WORK", 80):
            with self.assertRaisesRegex(TopologyError, "validation work budget"):
                cells({"strategy": {"matrix": matrix}}, "budget")

    def test_binary_values_consume_validation_and_comparison_budget(self) -> None:
        value = yaml.safe_load('!!binary "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="')
        self.assertIsInstance(value, bytes)
        job = {"strategy": {"matrix": {"a": [value]}}}
        with patch("check_codecov_upload_count.MAX_MATRIX_WORK", 1000):
            self.assertEqual(cells(job, "binary"), [{"a": value}])
            self.assertTrue(MatrixBudget("binary").equal(value, bytes(bytearray(value))))
        with patch("check_codecov_upload_count.MAX_MATRIX_WORK", 20):
            with self.assertRaisesRegex(TopologyError, "validation work budget"):
                cells(job, "binary")
            with self.assertRaisesRegex(TopologyError, "validation work budget"):
                MatrixBudget("binary").equal(value, bytes(bytearray(value)))

    def test_other_yaml_value_types_fail_explicitly(self) -> None:
        for source in ('!!set {a: null}', '2026-01-01', '!!binary "JHt7"'):
            with self.subTest(source=source), self.assertRaises(TopologyError):
                cells({"strategy": {"matrix": {"a": [yaml.safe_load(source)]}}}, "typed")

    def test_integer_cost_scales_without_text_conversion(self) -> None:
        value = 1 << 1000
        job = {"strategy": {"matrix": {"a": [value]}}}
        with patch("check_codecov_upload_count.MAX_MATRIX_WORK", 1000):
            self.assertEqual(cells(job, "integer"), [{"a": value}])
        with patch("check_codecov_upload_count.MAX_MATRIX_WORK", 20):
            with self.assertRaisesRegex(TopologyError, "validation work budget"):
                cells(job, "integer")

    def test_utf8_files_in_ascii_locale(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workflow, codecov = Path(temp) / "ci.yaml", Path(temp) / "codecov.yml"
            workflow.write_text("# caf\u00e9\n" + yaml.safe_dump(self.workflow), encoding="utf-8")
            codecov.write_text("# caf\u00e9\ncodecov: {notify: {after_n_builds: 6}}", encoding="utf-8")
            env = dict(os.environ, LC_ALL="C", PYTHONUTF8="0", PYTHONCOERCECLOCALE="0")
            result = subprocess.run([sys.executable, str(ROOT / "scripts/check_codecov_upload_count.py"),
                                     str(workflow), str(codecov)], env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

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

    def test_go126_coverage_comes_from_the_no_race_lane(self) -> None:
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yaml").read_text(encoding="utf-8"))["jobs"]
        unit = jobs["test-unit-go126"]
        # Both build variants upload: enterprise profiles exclude Apache-only stubs.
        self.assertEqual(unit["strategy"]["matrix"]["variant"], ["oss", "enterprise"])
        steps = unit["steps"]
        uploads = [step for step in steps if str(step.get("uses", "")).startswith("codecov/codecov-action@")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["with"]["files"], "./coverage.out")
        run = "\n".join(step.get("run", "") for step in steps)
        commands = [line.strip() for line in run.splitlines() if line.strip().startswith("go test ")]
        # A fresh pass for go-tool packages and a cached pass for the rest,
        # merged into the one profile the upload names.
        self.assertEqual(len(commands), 2)
        for command, profile in zip(commands, ("coverage-fresh.out", "coverage-cached.out")):
            self.assertNotIn("-race", command)
            self.assertIn(f"-covermode=set -coverprofile={profile}", command)
        self.assertIn('echo "mode: set" > coverage.out', run)
        self.assertIn('tail -n +2 "$profile" >> coverage.out', run)
        verify = [step for step in steps if step.get("name") == "Verify coverage profile"]
        self.assertEqual(len(verify), 1)
        self.assertEqual(verify[0]["run"], "bash scripts/check-coverage-profile.sh coverage.out")
        self.assertLess(steps.index(verify[0]), steps.index(uploads[0]))
        # The race lane runs on main only; an upload there would make Codecov's
        # expected count differ between pull requests and main.
        for race in ("test-oss-go126", "test-enterprise-go126"):
            with self.subTest(race=race):
                race_uploads = [
                    step for step in jobs[race]["steps"]
                    if str(step.get("uses", "")).startswith("codecov/codecov-action@")
                ]
                self.assertEqual(race_uploads, [])


if __name__ == "__main__":
    unittest.main()
