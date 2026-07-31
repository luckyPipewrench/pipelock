#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for scripts/pr-convergence.py."""

from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import tempfile
import unittest


SCRIPT_PATH = pathlib.Path(__file__).with_name("pr-convergence.py")
SPEC = importlib.util.spec_from_file_location("pr_convergence", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load {SCRIPT_PATH}")
pr_convergence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pr_convergence)

TESTDATA = pathlib.Path(__file__).with_name("testdata")


def load_fixture(name: str = "pr_convergence_clean.json") -> dict:
    with (TESTDATA / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def classify(data: dict, previous: dict | None = None, snapshot_requested: bool = False) -> dict:
    return pr_convergence.classify_pr_state(
        copy.deepcopy(data),
        previous_snapshot=copy.deepcopy(previous),
        snapshot_requested=snapshot_requested,
    )


class PrConvergenceStatusTest(unittest.TestCase):
    def test_every_status_value_has_explicit_test_coverage(self) -> None:
        covered = {
            "BEHIND_BASE",
            "CHANGED_DURING_WINDOW",
            "CHECKS_FAILING",
            "CHECKS_PENDING",
            "CONFLICTED",
            "DATA_SOURCE_UNAVAILABLE",
            "MERGE_BLOCKED",
            "READY",
            "REVIEW_CHANGES_REQUESTED",
            "SNAPSHOT_MISSING",
            "STALE_CHECK",
            "STALE_REVIEW",
            "UNRESOLVED_THREADS",
            "UNREVIEWED_AI_FINDINGS",
        }
        self.assertEqual(set(pr_convergence.STATUS_DOCS), covered)

    def test_gh_invocation_guard_rejects_mutating_api_calls(self) -> None:
        self.assertTrue(
            pr_convergence.gh_args_are_read_only(
                ["api", "graphql", "-f", "query=query { viewer { login } }"]
            )
        )
        self.assertFalse(
            pr_convergence.gh_args_are_read_only(["api", "repos/owner/repo/issues/1", "-X", "POST"])
        )
        self.assertFalse(
            pr_convergence.gh_args_are_read_only(
                ["api", "graphql", "-f", "query=mutation { addComment(input: {}) { clientMutationId } }"]
            )
        )

    def test_clean_state_without_snapshot_is_ready(self) -> None:
        result = classify(load_fixture())
        self.assertEqual(result["status"], "READY")
        self.assertTrue(result["ready"])

    def test_two_consecutive_clean_snapshots_are_ready(self) -> None:
        data = load_fixture()
        first = classify(data, snapshot_requested=True)
        self.assertEqual(first["status"], "SNAPSHOT_MISSING")

        second = classify(data, previous=first["snapshot"], snapshot_requested=True)
        self.assertEqual(second["status"], "READY")
        self.assertFalse(second["change_detection"]["changed"])

    def test_snapshot_path_round_trips_ready_after_second_clean_run(self) -> None:
        data = load_fixture()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "snapshot.json"
            first = classify(data, snapshot_requested=True)
            pr_convergence.write_snapshot(path, first["snapshot"])

            previous = pr_convergence.load_snapshot(path)
            second = classify(data, previous=previous, snapshot_requested=True)
            pr_convergence.write_snapshot(path, second["snapshot"])

        self.assertEqual(second["status"], "READY")

    def test_ai_review_top_level_comment_is_explicitly_blocking(self) -> None:
        result = classify(load_fixture("pr_convergence_ai_review.json"))
        self.assertEqual(result["status"], "UNREVIEWED_AI_FINDINGS")
        self.assertEqual(result["top_level_comments"]["ai_review_count"], 1)
        self.assertEqual(result["top_level_comments"]["unreviewed_ai_finding_count"], 1)

    def test_clean_ai_review_comment_does_not_block(self) -> None:
        data = load_fixture("pr_convergence_ai_review.json")
        data["issue_comments"][0]["body"] = (
            "## AI Review\n\nNo material security or correctness issues found in this diff."
        )
        result = classify(data)
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["top_level_comments"]["ai_review_count"], 1)
        self.assertEqual(result["top_level_comments"]["unreviewed_ai_finding_count"], 0)

    def test_multiple_review_bodies_sum_actionable_counts(self) -> None:
        data = load_fixture()
        data["reviews"].append(
            {
                "body": "Actionable comments posted: 2\nActionable comments posted: 3",
                "commit_id": "head222",
                "html_url": "https://github.com/owner/repo/pull/7#pullrequestreview-2",
                "id": 2,
                "state": "COMMENTED",
                "submitted_at": "2026-01-01T10:06:00Z",
                "user": {"login": "reviewer-b"},
            }
        )
        data["reviews"].append(
            {
                "body": "Actionable comments posted: 4",
                "commit_id": "head222",
                "html_url": "https://github.com/owner/repo/pull/7#pullrequestreview-3",
                "id": 3,
                "state": "COMMENTED",
                "submitted_at": "2026-01-01T10:07:00Z",
                "user": {"login": "reviewer-c"},
            }
        )
        result = classify(data)
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["review_summaries"]["actionable_comments_total"], 9)

    def test_outside_diff_null_line_unresolved_thread_blocks(self) -> None:
        data = load_fixture()
        data["review_threads"] = [
            {
                "comments": {
                    "nodes": [
                        {
                            "author": {"login": "reviewer-a"},
                            "createdAt": "2026-01-01T10:10:00Z",
                            "id": "comment-1",
                            "line": None,
                            "originalLine": None,
                            "path": "scripts/example.py",
                            "updatedAt": "2026-01-01T10:10:00Z",
                            "url": "https://github.com/owner/repo/pull/7#discussion_r1",
                        }
                    ]
                },
                "id": "thread-1",
                "isOutdated": False,
                "isResolved": False,
                "line": None,
                "originalLine": None,
                "path": "scripts/example.py",
            }
        ]
        result = classify(data)
        self.assertEqual(result["status"], "UNRESOLVED_THREADS")
        self.assertEqual(result["review_threads"]["outside_diff_or_null_line_count"], 1)

    def test_rest_inline_null_line_is_reported(self) -> None:
        data = load_fixture()
        data["review_comments"] = [
            {
                "html_url": "https://github.com/owner/repo/pull/7#discussion_r2",
                "id": 10,
                "line": None,
                "original_line": None,
                "path": "scripts/example.py",
                "position": None,
                "user": {"login": "reviewer-a"},
            }
        ]
        result = classify(data)
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["inline_comments"]["outside_diff_or_null_line_count"], 1)

    def test_stale_review_against_older_head_blocks(self) -> None:
        data = load_fixture()
        data["reviews"][0]["commit_id"] = "old111"
        result = classify(data)
        self.assertEqual(result["status"], "STALE_REVIEW")
        self.assertEqual(result["review_summaries"]["stale_count"], 1)

    def test_current_head_changes_requested_blocks(self) -> None:
        data = load_fixture()
        data["reviews"][0]["state"] = "CHANGES_REQUESTED"
        result = classify(data)
        self.assertEqual(result["status"], "REVIEW_CHANGES_REQUESTED")

    def test_pending_check_blocks(self) -> None:
        data = load_fixture()
        data["check_runs"]["check_runs"][0]["status"] = "in_progress"
        data["check_runs"]["check_runs"][0]["conclusion"] = None
        result = classify(data)
        self.assertEqual(result["status"], "CHECKS_PENDING")

    def test_failing_check_blocks(self) -> None:
        data = load_fixture()
        data["check_runs"]["check_runs"][0]["conclusion"] = "failure"
        result = classify(data)
        self.assertEqual(result["status"], "CHECKS_FAILING")

    def test_stale_check_is_not_counted_as_current_head_check(self) -> None:
        data = load_fixture()
        data["check_runs"]["check_runs"][0]["head_sha"] = "old111"
        result = classify(data)
        self.assertEqual(result["status"], "STALE_CHECK")
        self.assertEqual(result["required_checks"]["passing_count"], 1)
        self.assertEqual(result["required_checks"]["stale_count"], 1)

    def test_behind_base_blocks(self) -> None:
        data = load_fixture()
        data["compare"]["behind_by"] = 2
        data["compare"]["status"] = "diverged"
        result = classify(data)
        self.assertEqual(result["status"], "BEHIND_BASE")
        self.assertTrue(result["stack"]["head_behind_base"])

    def test_conflicted_blocks(self) -> None:
        data = load_fixture()
        data["pull"]["mergeable"] = False
        data["pull"]["mergeable_state"] = "dirty"
        result = classify(data)
        self.assertEqual(result["status"], "CONFLICTED")

    def test_merge_blocked_blocks(self) -> None:
        data = load_fixture()
        data["pull"]["mergeable_state"] = "blocked"
        result = classify(data)
        self.assertEqual(result["status"], "MERGE_BLOCKED")

    def test_data_source_error_fails_closed(self) -> None:
        data = load_fixture()
        data["errors"] = [{"source": "review_threads", "message": "rate limited"}]
        result = classify(data)
        self.assertEqual(result["status"], "DATA_SOURCE_UNAVAILABLE")
        self.assertFalse(result["ready"])

    def test_new_comment_since_snapshot_reports_changed_window(self) -> None:
        data = load_fixture()
        previous = classify(data)["snapshot"]
        data["issue_comments"].append(
            {
                "body": "Please check this case.",
                "created_at": "2026-01-01T10:20:00Z",
                "html_url": "https://github.com/owner/repo/pull/7#issuecomment-23",
                "id": 23,
                "updated_at": "2026-01-01T10:20:00Z",
                "user": {"login": "reviewer-a"},
            }
        )
        result = classify(data, previous=previous, snapshot_requested=True)
        self.assertEqual(result["status"], "CHANGED_DURING_WINDOW")
        self.assertEqual(result["change_detection"]["categories"]["comments"], ["23"])

    def test_new_inline_comment_since_snapshot_reports_changed_window(self) -> None:
        data = load_fixture()
        previous = classify(data)["snapshot"]
        data["review_comments"].append(
            {
                "html_url": "https://github.com/owner/repo/pull/7#discussion_r3",
                "id": 33,
                "line": 12,
                "original_line": 12,
                "path": "scripts/example.py",
                "position": 4,
                "updated_at": "2026-01-01T10:21:00Z",
                "user": {"login": "reviewer-a"},
            }
        )
        result = classify(data, previous=previous, snapshot_requested=True)
        self.assertEqual(result["status"], "CHANGED_DURING_WINDOW")
        self.assertEqual(result["change_detection"]["categories"]["comments"], ["33"])

    def test_new_review_since_snapshot_reports_changed_window(self) -> None:
        data = load_fixture()
        previous = classify(data)["snapshot"]
        data["reviews"].append(
            {
                "body": "Looks good.",
                "commit_id": "head222",
                "html_url": "https://github.com/owner/repo/pull/7#pullrequestreview-4",
                "id": 4,
                "state": "APPROVED",
                "submitted_at": "2026-01-01T10:20:00Z",
                "user": {"login": "reviewer-d"},
            }
        )
        result = classify(data, previous=previous, snapshot_requested=True)
        self.assertEqual(result["status"], "CHANGED_DURING_WINDOW")
        self.assertEqual(result["change_detection"]["categories"]["reviews"], ["4"])

    def test_new_commit_since_snapshot_reports_changed_window(self) -> None:
        data = load_fixture()
        previous = classify(data)["snapshot"]
        data["pull"]["head"]["sha"] = "head333"
        data["check_runs"]["check_runs"][0]["head_sha"] = "head333"
        data["status"]["statuses"][0]["sha"] = "head333"
        data["commits"].append(
            {
                "commit": {"committer": {"date": "2026-01-01T10:30:00Z"}},
                "sha": "head333",
            }
        )
        result = classify(data, previous=previous, snapshot_requested=True)
        self.assertEqual(result["status"], "CHANGED_DURING_WINDOW")
        self.assertEqual(result["change_detection"]["categories"]["commits"], ["head333"])

    def test_check_change_since_snapshot_reports_changed_window(self) -> None:
        data = load_fixture()
        previous = classify(data)["snapshot"]
        data["check_runs"]["check_runs"][0]["conclusion"] = "failure"
        result = classify(data, previous=previous, snapshot_requested=True)
        self.assertEqual(result["status"], "CHANGED_DURING_WINDOW")
        self.assertEqual(result["change_detection"]["categories"]["checks"], ["unit"])

    def test_stacked_pr_base_is_distinct_from_main_base(self) -> None:
        data = load_fixture()
        data["pull"]["base"]["ref"] = "feature-base"
        data["base_pull_candidates"] = [
            {
                "head": {"ref": "feature-base"},
                "html_url": "https://github.com/owner/repo/pull/6",
                "number": 6,
                "state": "open",
                "title": "Base PR",
            }
        ]
        result = classify(data)
        self.assertEqual(result["status"], "READY")
        self.assertTrue(result["stack"]["base_is_open_pr"])
        self.assertEqual(result["stack"]["base_pr"]["number"], 6)

if __name__ == "__main__":
    unittest.main()
