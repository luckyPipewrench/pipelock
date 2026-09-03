#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Pipelock-owned Gauntlet acceptance contract checker."""

import json
import tempfile
import unittest
from pathlib import Path

try:
    from scripts import check_gauntlet_acceptance as checker
except ModuleNotFoundError:  # pragma: no cover - direct-module invocation
    import check_gauntlet_acceptance as checker


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "benchmark" / "gauntlet-acceptance.json"
CONTRACT = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

MISSES = list(CONTRACT["accepted_containment_misses"])
FALSE_POSITIVES = list(CONTRACT["accepted_false_positives"])
CONTAINMENT = CONTRACT["containment"]
FALSE_POSITIVE_COUNTS = CONTRACT["false_positives"]


def candidate_document(**overrides):
    counts = {
        "containment": dict(CONTAINMENT),
        "false_positive_rate": dict(FALSE_POSITIVE_COUNTS),
    }
    document = {
        "pipelock_version": CONTRACT["pipelock_version"],
        "corpus_version": CONTRACT["corpus_version"],
        "corpus_git_sha": CONTRACT["bench_commit"],
        "case_count": {
            "total": CONTRACT["active_case_count"],
            "applicable": CONTRACT["active_case_count"],
            "errors": 0,
            "unreachable": 0,
            "not_applicable": 0,
            "not_applicable_reasons": {},
        },
        "metric_counts": {"full": counts, "applicable": dict(counts)},
    }
    document.update(overrides)
    return document


def results_rows(misses=None, false_positives=None):
    """Build a full result set matching the accepted aggregates by default."""
    misses = MISSES if misses is None else misses
    false_positives = FALSE_POSITIVES if false_positives is None else false_positives
    rows = []
    for case_id in misses:
        rows.append((case_id, "block", "allow", "fail"))
    for case_id in false_positives:
        rows.append((case_id, "allow", "block", "fail"))
    used = {case_id for case_id, *_ in rows}
    index = 0
    while sum(1 for _, expected, _, _ in rows if expected == "block") < CONTAINMENT["denominator"]:
        case_id = f"generated-block-{index:04d}"
        index += 1
        if case_id in used:
            continue
        rows.append((case_id, "block", "block", "pass"))
    index = 0
    while sum(1 for _, expected, _, _ in rows if expected == "allow") < FALSE_POSITIVE_COUNTS["denominator"]:
        case_id = f"generated-allow-{index:04d}"
        index += 1
        if case_id in used:
            continue
        rows.append((case_id, "allow", "allow", "pass"))
    assert sum(1 for _, expected, _, _ in rows if expected == "block") == CONTAINMENT["denominator"]
    assert len(rows) == CONTRACT["active_case_count"], len(rows)
    return [
        {
            "case_id": case_id,
            "expected_verdict": expected,
            "actual_verdict": actual,
            "score": score,
        }
        for case_id, expected, actual, score in rows
    ]


class AcceptanceCheckerTest(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.directory = Path(self._temporary.name)

    def run_check(self, candidate=None, rows=None, contract=CONTRACT_PATH):
        candidate_path = self.directory / "candidate.json"
        results_path = self.directory / "results.jsonl"
        candidate_path.write_text(
            json.dumps(candidate_document() if candidate is None else candidate),
            encoding="utf-8",
        )
        rows = results_rows() if rows is None else rows
        results_path.write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        return checker.check(contract, candidate_path, results_path)

    def test_accepted_result_passes(self):
        self.assertEqual(self.run_check(), [])

    def test_swapping_one_accepted_case_while_preserving_aggregates_is_rejected(self):
        """The aggregate is identical; only the identities moved."""
        rows = results_rows()
        swapped_in = next(
            row for row in rows if row["expected_verdict"] == "block" and row["score"] == "pass"
        )
        swapped_out = next(row for row in rows if row["case_id"] == MISSES[0])
        swapped_in.update(actual_verdict="allow", score="fail")
        swapped_out.update(actual_verdict="block", score="pass")
        failures = self.run_check(rows=rows)
        self.assertTrue(any(swapped_in["case_id"] in failure for failure in failures), failures)
        self.assertTrue(any(MISSES[0] in failure for failure in failures), failures)

    def test_swapping_one_accepted_false_positive_is_rejected(self):
        rows = results_rows()
        swapped_in = next(
            row for row in rows if row["expected_verdict"] == "allow" and row["score"] == "pass"
        )
        swapped_out = next(row for row in rows if row["case_id"] == FALSE_POSITIVES[0])
        swapped_in.update(actual_verdict="block", score="fail")
        swapped_out.update(actual_verdict="allow", score="pass")
        failures = self.run_check(rows=rows)
        self.assertTrue(any(swapped_in["case_id"] in failure for failure in failures), failures)

    def test_additional_miss_is_rejected(self):
        rows = results_rows()
        extra = next(
            row for row in rows if row["expected_verdict"] == "block" and row["score"] == "pass"
        )
        extra.update(actual_verdict="allow", score="fail")
        self.assertTrue(self.run_check(rows=rows))

    def test_unexpected_pass_requires_a_reviewed_contract_update(self):
        rows = [row for row in results_rows() if row["case_id"] != MISSES[0]]
        rows.append(
            {
                "case_id": MISSES[0],
                "expected_verdict": "block",
                "actual_verdict": "block",
                "score": "pass",
            }
        )
        failures = self.run_check(rows=rows)
        self.assertTrue(
            any("no longer failing" in failure for failure in failures), failures
        )

    def test_product_version_mismatch_is_rejected(self):
        failures = self.run_check(candidate=candidate_document(pipelock_version="3.4.0"))
        self.assertTrue(any("pipelock_version" in failure for failure in failures), failures)

    def test_unpinned_benchmark_revision_is_rejected(self):
        failures = self.run_check(candidate=candidate_document(corpus_git_sha="0" * 40))
        self.assertTrue(any("corpus_git_sha" in failure for failure in failures), failures)

    def test_runner_errors_and_unreachable_cases_are_rejected(self):
        for field in ("errors", "unreachable"):
            with self.subTest(field=field):
                candidate = candidate_document()
                candidate["case_count"][field] = 1
                failures = self.run_check(candidate=candidate)
                self.assertTrue(any(field in failure for failure in failures), failures)

    def test_boolean_count_cannot_satisfy_a_zero_check(self):
        candidate = candidate_document()
        candidate["case_count"]["errors"] = False
        failures = self.run_check(candidate=candidate)
        self.assertTrue(any("errors" in failure for failure in failures), failures)

    def test_metric_counts_must_match_the_contract_exactly(self):
        candidate = candidate_document()
        candidate["metric_counts"]["applicable"]["containment"] = {
            "numerator": CONTAINMENT["numerator"] - 1,
            "denominator": CONTAINMENT["denominator"] - 1,
        }
        failures = self.run_check(candidate=candidate)
        self.assertTrue(any("containment" in failure for failure in failures), failures)

    def test_short_result_set_is_rejected(self):
        rows = results_rows()[:-1]
        failures = self.run_check(rows=rows)
        self.assertTrue(any("cases" in failure for failure in failures), failures)

    def test_moving_a_case_between_populations_is_rejected(self):
        """Totals and identities still agree; the evaluated population does not."""
        rows = results_rows()
        moved = next(
            row for row in rows if row["expected_verdict"] == "block" and row["score"] == "pass"
        )
        moved.update(expected_verdict="allow", actual_verdict="allow")
        failures = self.run_check(rows=rows)
        self.assertTrue(
            any("expecting 'block'" in failure for failure in failures), failures
        )
        self.assertTrue(
            any("expecting 'allow'" in failure for failure in failures), failures
        )

    def test_unhashable_verdict_fails_closed_without_a_traceback(self):
        for field in ("expected_verdict", "actual_verdict", "score"):
            for value in ([], {}, 7, None):
                with self.subTest(field=field, value=value):
                    rows = results_rows()
                    rows[0] = dict(rows[0], **{field: value})
                    with self.assertRaises(ValueError):
                        self.run_check(rows=rows)

    def test_main_reports_a_nonzero_exit_on_malformed_verdicts(self):
        rows = results_rows()
        rows[0] = dict(rows[0], expected_verdict=[])
        candidate_path = self.directory / "candidate.json"
        results_path = self.directory / "results.jsonl"
        candidate_path.write_text(json.dumps(candidate_document()), encoding="utf-8")
        results_path.write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        exit_code = checker.main(
            [
                "--contract",
                str(CONTRACT_PATH),
                "--candidate",
                str(candidate_path),
                "--results",
                str(results_path),
            ]
        )
        self.assertEqual(exit_code, 1)

    def test_unknown_score_fails_closed(self):
        rows = results_rows()
        rows[-1] = dict(rows[-1], score="error", actual_verdict="error")
        with self.assertRaises(ValueError):
            self.run_check(rows=rows)

    def test_passing_score_cannot_hide_an_opposite_verdict(self):
        rows = results_rows()
        passing_block = next(
            row for row in rows if row["expected_verdict"] == "block" and row["score"] == "pass"
        )
        passing_block["actual_verdict"] = "allow"
        with self.assertRaisesRegex(ValueError, "score does not match"):
            self.run_check(rows=rows)

    def test_unknown_score_cannot_preserve_an_accepted_miss(self):
        rows = results_rows()
        accepted_miss = next(row for row in rows if row["case_id"] == MISSES[0])
        accepted_miss["score"] = "error"
        with self.assertRaisesRegex(ValueError, "invalid score"):
            self.run_check(rows=rows)

    def test_repeated_case_identifier_fails_closed(self):
        rows = results_rows()
        rows.append(dict(rows[0]))
        with self.assertRaises(ValueError):
            self.run_check(rows=rows)

    def test_missing_contract_fails_closed(self):
        with self.assertRaises(OSError):
            self.run_check(contract=self.directory / "absent.json")

    def test_main_reports_a_nonzero_exit_on_a_blocked_result(self):
        candidate_path = self.directory / "candidate.json"
        results_path = self.directory / "results.jsonl"
        candidate_path.write_text(
            json.dumps(candidate_document(pipelock_version="0.0.0")), encoding="utf-8"
        )
        results_path.write_text(
            "".join(json.dumps(row) + "\n" for row in results_rows()), encoding="utf-8"
        )
        exit_code = checker.main(
            [
                "--contract",
                str(CONTRACT_PATH),
                "--candidate",
                str(candidate_path),
                "--results",
                str(results_path),
            ]
        )
        self.assertEqual(exit_code, 1)

    def test_main_passes_on_the_accepted_result(self):
        candidate_path = self.directory / "candidate.json"
        results_path = self.directory / "results.jsonl"
        candidate_path.write_text(json.dumps(candidate_document()), encoding="utf-8")
        results_path.write_text(
            "".join(json.dumps(row) + "\n" for row in results_rows()), encoding="utf-8"
        )
        exit_code = checker.main(
            [
                "--contract",
                str(CONTRACT_PATH),
                "--candidate",
                str(candidate_path),
                "--results",
                str(results_path),
            ]
        )
        self.assertEqual(exit_code, 0)


class ContractShapeTest(unittest.TestCase):
    def test_contract_rejects_a_duplicate_accepted_identifier(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            broken = dict(CONTRACT)
            broken["accepted_containment_misses"] = [MISSES[0], MISSES[0]]
            path.write_text(json.dumps(broken), encoding="utf-8")
            with self.assertRaises(ValueError):
                checker.load_contract(path)

    def test_contract_rejects_an_unknown_schema_version(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(dict(CONTRACT, schema_version=2)), encoding="utf-8")
            with self.assertRaises(ValueError):
                checker.load_contract(path)

    def test_contract_rejects_non_integer_active_case_count(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(dict(CONTRACT, active_case_count=249.0)), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "active_case_count"):
                checker.load_contract(path)

    def test_contract_rejects_counts_that_disagree_with_accepted_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            broken = dict(CONTRACT)
            broken["containment"] = dict(CONTAINMENT, numerator=CONTAINMENT["numerator"] - 1)
            path.write_text(json.dumps(broken), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "accepted_containment_misses"):
                checker.load_contract(path)

    def test_shipped_contract_loads(self):
        self.assertEqual(checker.load_contract(CONTRACT_PATH)["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
