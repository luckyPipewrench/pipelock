#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for scripts/pr-convergence.py."""

from __future__ import annotations

import copy
import ast
import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock


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


def recording_base_candidate_client(
    fixture: dict[str, object],
    candidates: list[dict[str, object]],
    calls: list[str],
    head_ref_reads: list[str],
) -> type:
    class RecordingGhClient:
        def __init__(self, repo: str) -> None:
            self.repo = repo
            self.owner, self.name = pr_convergence.parse_repo(repo)

        def api(self, path: str, *, paginate: bool = False, accept: str | None = None) -> object:
            del paginate, accept
            calls.append(path)
            if path == "repos/owner/repo/pulls/7":
                return fixture["pull"]
            if path.endswith("/check-runs?per_page=100"):
                return {"check_runs": []}
            if path.endswith("/status"):
                return {"statuses": []}
            if path.endswith("/compare/base111...head222"):
                return {"behind_by": 0, "ahead_by": 1, "status": "ahead"}
            return []

        def graphql_review_threads(self, pr_number: int) -> list[dict[str, object]]:
            del pr_number
            return []

        def graphql_open_pulls_by_head_ref(self, head_ref_name: str) -> list[dict[str, object]]:
            head_ref_reads.append(head_ref_name)
            return candidates

    return RecordingGhClient


class PrConvergenceStatusTest(unittest.TestCase):
    def asserted_status_values(self) -> set[str]:
        source = pathlib.Path(__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        statuses: set[str] = set()

        def is_status_lookup(node: ast.AST) -> bool:
            return (
                isinstance(node, ast.Subscript)
                and isinstance(node.slice, ast.Constant)
                and node.slice.value == "status"
            )

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute) or node.func.attr != "assertEqual":
                continue
            if len(node.args) < 2:
                continue
            left, right = node.args[0], node.args[1]
            if is_status_lookup(left) and isinstance(right, ast.Constant) and isinstance(right.value, str):
                statuses.add(right.value)
            if is_status_lookup(right) and isinstance(left, ast.Constant) and isinstance(left.value, str):
                statuses.add(left.value)
        return statuses

    def test_every_status_value_has_explicit_test_coverage(self) -> None:
        self.assertEqual(set(pr_convergence.STATUS_DOCS), self.asserted_status_values())

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
                ["api", "repos/owner/repo/issues/7/comments", "-f", "body=hi"]
            )
        )
        self.assertFalse(
            pr_convergence.gh_args_are_read_only(
                ["api", "repos/owner/repo/issues/7/comments", "--input", "body.json"]
            )
        )
        self.assertFalse(
            pr_convergence.gh_args_are_read_only(
                ["api", "repos/owner/repo/issues/7/comments", "--field=body=hi"]
            )
        )
        self.assertFalse(
            pr_convergence.gh_args_are_read_only(
                ["api", "graphql", "-f", "query=mutation { addComment(input: {}) { clientMutationId } }"]
            )
        )
        self.assertFalse(
            pr_convergence.gh_args_are_read_only(["api", "graphql", "-f", "query=@file.graphql"])
        )
        self.assertFalse(pr_convergence.gh_args_are_read_only(["pr", "merge", "7"]))
        self.assertFalse(pr_convergence.gh_args_are_read_only(["pr", "comment", "7"]))
        self.assertFalse(pr_convergence.gh_args_are_read_only(["pr", "close", "7"]))
        self.assertFalse(pr_convergence.gh_args_are_read_only(["pr", "edit", "7"]))
        self.assertFalse(pr_convergence.gh_args_are_read_only(["pr", "review", "7", "--approve"]))

    def test_gh_invocation_guard_allows_plain_reads(self) -> None:
        self.assertTrue(pr_convergence.gh_args_are_read_only(["api", "repos/owner/repo/pulls/7"]))
        self.assertTrue(
            pr_convergence.gh_args_are_read_only(
                ["api", "repos/owner/repo/pulls/7", "--paginate", "--slurp"]
            )
        )
        self.assertTrue(
            pr_convergence.gh_args_are_read_only(
                ["api", "repos/owner/repo/pulls/7", "-H", "Accept: application/vnd.github+json"]
            )
        )
        self.assertTrue(
            pr_convergence.gh_args_are_read_only(["api", "repos/owner/repo/pulls/7", "-X", "GET"])
        )
        self.assertTrue(
            pr_convergence.gh_args_are_read_only(["api", "repos/owner/repo/pulls/7", "-XGET"])
        )
        self.assertTrue(
            pr_convergence.gh_args_are_read_only(
                ["api", "repos/owner/repo/pulls/7", "--method=GET"]
            )
        )
        self.assertTrue(
            pr_convergence.gh_args_are_read_only(
                [
                    "api",
                    "graphql",
                    "-f",
                    "query=query($owner: String!) { repository(owner: $owner, name: \"repo\") { id } }",
                    "-F",
                    "owner=owner",
                    "-F",
                    "headRefName=feature-base",
                ]
            )
        )

    def test_gh_client_api_constructs_plain_read_call(self) -> None:
        calls: list[list[str]] = []

        class RecordingGhClient(pr_convergence.GhClient):
            def run(self, args: list[str]) -> object:
                calls.append(args)
                return {"number": 7}

        payload = RecordingGhClient("owner/repo").api("repos/owner/repo/pulls/7")
        self.assertEqual(payload, {"number": 7})
        self.assertEqual(calls, [["api", "repos/owner/repo/pulls/7"]])
        self.assertTrue(pr_convergence.gh_args_are_read_only(calls[0]))

    def test_gh_client_blocks_mutation_before_executing_gh(self) -> None:
        with mock.patch.object(pr_convergence.subprocess, "run") as run:
            with self.assertRaises(pr_convergence.GhReadError):
                pr_convergence.GhClient("owner/repo").run(
                    ["api", "repos/owner/repo/issues/7/comments", "-X", "POST"]
                )
        run.assert_not_called()

    def test_gh_client_timeout_becomes_read_error(self) -> None:
        with mock.patch.object(
            pr_convergence.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["gh"], pr_convergence.GH_READ_TIMEOUT_SECONDS),
        ):
            with self.assertRaises(pr_convergence.GhReadError):
                pr_convergence.GhClient("owner/repo").run(["api", "repos/owner/repo/pulls/7"])

    def test_gh_client_uses_read_timeout(self) -> None:
        completed = subprocess.CompletedProcess(["gh"], 0, "{}", "")
        with mock.patch.object(pr_convergence.subprocess, "run", return_value=completed) as run:
            pr_convergence.GhClient("owner/repo").run(["api", "repos/owner/repo/pulls/7"])

        self.assertEqual(run.call_args.kwargs["timeout"], pr_convergence.GH_READ_TIMEOUT_SECONDS)

    def test_clean_state_without_snapshot_is_ready(self) -> None:
        result = classify(load_fixture())
        self.assertEqual(result["status"], "READY")
        self.assertTrue(result["ready"])

    def test_no_checks_is_ready_when_other_sources_are_clean(self) -> None:
        data = load_fixture()
        data["check_runs"] = {"check_runs": []}
        data["status"] = {"statuses": []}
        result = classify(data)
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["required_checks"]["passing_count"], 0)

    def test_compact_summary_reports_zero_unavailable_sources(self) -> None:
        result = classify(load_fixture())
        self.assertIn("errors: 0 source(s) unavailable", pr_convergence.compact_summary(result))

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

    def test_snapshot_write_uses_owner_only_permissions(self) -> None:
        data = load_fixture()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "snapshot.json"
            pr_convergence.write_snapshot(path, classify(data)["snapshot"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_snapshot_write_is_private_during_json_dump(self) -> None:
        data = load_fixture()
        observed_modes: list[int] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "snapshot.json"
            old_umask = os.umask(0)
            real_dump = pr_convergence.json.dump

            def record_mode(obj: object, handle: object, **kwargs: object) -> None:
                temp_files = list(pathlib.Path(tmpdir).glob(f".{path.name}.*"))
                self.assertEqual(len(temp_files), 1)
                observed_modes.append(temp_files[0].stat().st_mode & 0o777)
                real_dump(obj, handle, **kwargs)

            try:
                with mock.patch.object(pr_convergence.json, "dump", side_effect=record_mode):
                    pr_convergence.write_snapshot(path, classify(data)["snapshot"])
            finally:
                os.umask(old_umask)

        self.assertEqual(observed_modes, [0o600])

    def test_snapshot_schema_version_is_current(self) -> None:
        result = classify(load_fixture())
        self.assertEqual(result["snapshot"]["schema_version"], pr_convergence.SNAPSHOT_SCHEMA_VERSION)

    def test_corrupt_snapshot_fails_closed_as_data_source_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "snapshot.json"
            path.write_text("{bad", encoding="utf-8")
            with self.assertRaises(pr_convergence.DataSourceError) as raised:
                pr_convergence.load_snapshot(path)

        self.assertEqual(raised.exception.source, "snapshot")

    def test_group_accessible_snapshot_is_refused(self) -> None:
        data = classify(load_fixture())["snapshot"]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "snapshot.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            path.chmod(0o640)
            with self.assertRaises(pr_convergence.DataSourceError) as raised:
                pr_convergence.load_snapshot(path)

        self.assertEqual(raised.exception.source, "snapshot")

    def test_unsupported_snapshot_schema_is_refused(self) -> None:
        data = classify(load_fixture())["snapshot"]
        data["schema_version"] = 999
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "snapshot.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(pr_convergence.DataSourceError) as raised:
                pr_convergence.load_snapshot(path)

        self.assertEqual(raised.exception.source, "snapshot")

    def test_hand_edited_snapshot_collection_type_is_refused(self) -> None:
        data = classify(load_fixture())["snapshot"]
        data["comments"] = "not a list"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "snapshot.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(pr_convergence.DataSourceError) as raised:
                pr_convergence.load_snapshot(path)

        self.assertEqual(raised.exception.source, "snapshot")

    def test_ai_review_top_level_comment_is_explicitly_blocking(self) -> None:
        result = classify(load_fixture("pr_convergence_ai_review.json"))
        self.assertEqual(result["status"], "UNREVIEWED_AI_FINDINGS")
        self.assertEqual(result["top_level_comments"]["ai_review_count"], 1)
        self.assertEqual(result["top_level_comments"]["unreviewed_ai_finding_count"], 1)

    def test_ai_review_mid_body_heading_is_explicitly_blocking(self) -> None:
        data = load_fixture("pr_convergence_ai_review.json")
        data["issue_comments"][0]["body"] = (
            "Review summary\n\n## AI Review\n\n1. medium: scripts/example.py - fix this finding."
        )
        result = classify(data)
        self.assertEqual(result["status"], "UNREVIEWED_AI_FINDINGS")
        self.assertEqual(result["top_level_comments"]["ai_review_count"], 1)

    def test_clean_ai_review_comment_does_not_block(self) -> None:
        data = load_fixture("pr_convergence_ai_review.json")
        data["issue_comments"][0]["body"] = (
            "## AI Review\n\nNo material security or correctness issues found in this diff."
        )
        result = classify(data)
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["top_level_comments"]["ai_review_count"], 1)
        self.assertEqual(result["top_level_comments"]["unreviewed_ai_finding_count"], 0)

    def test_ai_review_actionable_count_overrides_clean_marker(self) -> None:
        data = load_fixture("pr_convergence_ai_review.json")
        data["issue_comments"][0]["body"] = (
            "## AI Review\n\n"
            "Actionable comments posted: 1\n\n"
            "Test coverage is adequate.\n\n"
            "1. high: scripts/example.py - fix this finding."
        )
        result = classify(data)
        self.assertEqual(result["status"], "UNREVIEWED_AI_FINDINGS")
        self.assertEqual(result["top_level_comments"]["unreviewed_ai_finding_count"], 1)

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

    def test_multiple_unresolved_threads_block(self) -> None:
        data = load_fixture()
        data["review_threads"] = [
            {
                "comments": {"nodes": []},
                "id": "thread-1",
                "isOutdated": False,
                "isResolved": False,
                "line": 12,
                "originalLine": 12,
                "path": "scripts/example.py",
            },
            {
                "comments": {"nodes": []},
                "id": "thread-2",
                "isOutdated": False,
                "isResolved": False,
                "line": 20,
                "originalLine": 20,
                "path": "scripts/example.py",
            },
        ]
        result = classify(data)
        self.assertEqual(result["status"], "UNRESOLVED_THREADS")
        self.assertEqual(result["review_threads"]["unresolved_count"], 2)

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

    def test_null_check_suite_app_does_not_crash(self) -> None:
        data = load_fixture()
        data["check_runs"]["check_runs"][0].pop("name")
        data["check_runs"]["check_runs"][0]["check_suite"] = None
        result = classify(data)
        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["required_checks"]["passing_count"], 2)

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

    def test_draft_closed_and_merged_prs_block(self) -> None:
        for state_patch in (
            {"draft": True},
            {"state": "closed"},
            {"state": "closed", "merged": True},
        ):
            with self.subTest(state_patch=state_patch):
                data = load_fixture()
                data["pull"].update(state_patch)
                result = classify(data)
                self.assertEqual(result["status"], "MERGE_BLOCKED")

    def test_data_source_error_fails_closed(self) -> None:
        data = load_fixture()
        data["errors"] = [{"source": "review_threads", "message": "rate limited"}]
        result = classify(data)
        self.assertEqual(result["status"], "DATA_SOURCE_UNAVAILABLE")
        self.assertFalse(result["ready"])

    def test_pull_read_error_fails_closed_for_missing_or_unauthenticated_pr(self) -> None:
        class FailingGhClient:
            def __init__(self, repo: str) -> None:
                self.repo = repo
                self.owner, self.name = pr_convergence.parse_repo(repo)

            def api(self, path: str, *, paginate: bool = False, accept: str | None = None) -> object:
                del path, paginate, accept
                raise pr_convergence.GhReadError("not found or unauthenticated")

            def graphql_review_threads(self, pr_number: int) -> list[dict[str, object]]:
                del pr_number
                raise pr_convergence.GhReadError("not found or unauthenticated")

        with mock.patch.object(pr_convergence, "GhClient", FailingGhClient):
            result = classify(pr_convergence.gather_pr_state("owner/repo", 7))

        self.assertEqual(result["status"], "DATA_SOURCE_UNAVAILABLE")
        self.assertFalse(result["ready"])

    def test_graphql_null_data_becomes_gh_read_error(self) -> None:
        client = pr_convergence.GhClient("owner/repo")
        with mock.patch.object(client, "run", return_value={"data": None}):
            with self.assertRaises(pr_convergence.GhReadError):
                client.graphql_review_threads(7)

    def test_graphql_open_pulls_paginates_and_maps_nodes(self) -> None:
        client = pr_convergence.GhClient("owner/repo")
        pages = [
            {
                "data": {
                    "repository": {
                        "pullRequests": {
                            "nodes": [
                                {
                                    "number": 6,
                                    "state": "OPEN",
                                    "title": "Base PR",
                                    "url": "https://github.com/owner/repo/pull/6",
                                    "headRefName": "feature-base",
                                    "headRepository": {"nameWithOwner": "contributor/repo"},
                                }
                            ],
                            "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                        }
                    }
                }
            },
            {
                "data": {
                    "repository": {
                        "pullRequests": {
                            "nodes": [
                                {
                                    "number": 8,
                                    "state": "OPEN",
                                    "title": "Other Base PR",
                                    "url": "https://github.com/owner/repo/pull/8",
                                    "headRefName": "feature-base",
                                    "headRepository": {"nameWithOwner": "fork/repo"},
                                }
                            ],
                            "pageInfo": {"hasNextPage": False},
                        }
                    }
                }
            },
        ]

        with mock.patch.object(client, "run", side_effect=pages) as run:
            pulls = client.graphql_open_pulls_by_head_ref("feature-base")

        self.assertEqual([pull["number"] for pull in pulls], [6, 8])
        self.assertEqual(pulls[0]["state"], "open")
        self.assertEqual(pulls[1]["head"]["repo"]["full_name"], "fork/repo")
        first_args = run.call_args_list[0].args[0]
        second_args = run.call_args_list[1].args[0]
        self.assertEqual(first_args[first_args.index("headRefName=feature-base") - 1], "-f")
        self.assertEqual(second_args[second_args.index("after=cursor-1") - 1], "-f")

    def test_graphql_open_pulls_rejects_non_list_nodes(self) -> None:
        client = pr_convergence.GhClient("owner/repo")
        response = {
            "data": {
                "repository": {
                    "pullRequests": {
                        "nodes": {"number": 6},
                        "pageInfo": {"hasNextPage": False},
                    }
                }
            }
        }

        with mock.patch.object(client, "run", return_value=response), self.assertRaises(
            pr_convergence.GhReadError
        ):
            client.graphql_open_pulls_by_head_ref("feature-base")

    def test_graphql_open_pulls_rejects_repeated_cursor(self) -> None:
        client = pr_convergence.GhClient("owner/repo")
        response = {
            "data": {
                "repository": {
                    "pullRequests": {
                        "nodes": [],
                        "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                    }
                }
            }
        }

        with mock.patch.object(client, "run", return_value=response), self.assertRaises(
            pr_convergence.GhReadError
        ):
            client.graphql_open_pulls_by_head_ref("feature-base")

    def test_graphql_open_pulls_rejects_page_limit_overflow(self) -> None:
        client = pr_convergence.GhClient("owner/repo")

        def page(index: int) -> dict[str, object]:
            return {
                "data": {
                    "repository": {
                        "pullRequests": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": True, "endCursor": f"cursor-{index}"},
                        }
                    }
                }
            }

        pages = [page(index) for index in range(pr_convergence.GRAPHQL_MAX_PAGES + 1)]
        with mock.patch.object(client, "run", side_effect=pages) as run, self.assertRaises(
            pr_convergence.GhReadError
        ):
            client.graphql_open_pulls_by_head_ref("feature-base")

        self.assertEqual(run.call_count, pr_convergence.GRAPHQL_MAX_PAGES)

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
        self.assertEqual(
            result["change_detection"]["categories"]["comments"],
            ["added:issue_comment:23"],
        )

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
        self.assertEqual(
            result["change_detection"]["categories"]["comments"],
            ["added:review_comment:33"],
        )

    def test_removed_comment_since_snapshot_reports_changed_window(self) -> None:
        data = load_fixture()
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
        previous = classify(data)["snapshot"]
        data["issue_comments"] = []
        result = classify(data, previous=previous, snapshot_requested=True)
        self.assertEqual(result["status"], "CHANGED_DURING_WINDOW")
        self.assertEqual(
            result["change_detection"]["categories"]["comments"],
            ["removed:issue_comment:23"],
        )

    def test_issue_and_review_comment_id_collision_reports_changed_window(self) -> None:
        data = load_fixture()
        data["issue_comments"] = [
            {
                "body": "Please check this case.",
                "created_at": "2026-01-01T10:20:00Z",
                "html_url": "https://github.com/owner/repo/pull/7#issuecomment-33",
                "id": 33,
                "updated_at": "2026-01-01T10:20:00Z",
                "user": {"login": "reviewer-a"},
            }
        ]
        previous = classify(data)["snapshot"]
        data["issue_comments"] = []
        data["review_comments"] = [
            {
                "html_url": "https://github.com/owner/repo/pull/7#discussion_r33",
                "id": 33,
                "line": 12,
                "original_line": 12,
                "path": "scripts/example.py",
                "position": 4,
                "updated_at": "2026-01-01T10:20:00Z",
                "user": {"login": "reviewer-a"},
            }
        ]
        result = classify(data, previous=previous, snapshot_requested=True)
        self.assertEqual(result["status"], "CHANGED_DURING_WINDOW")
        self.assertEqual(
            result["change_detection"]["categories"]["comments"],
            ["added:review_comment:33", "removed:issue_comment:33"],
        )

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
        self.assertEqual(result["change_detection"]["categories"]["reviews"], ["added:4"])

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
        self.assertEqual(result["change_detection"]["categories"]["checks"], ["modified:unit"])

    def test_new_thread_since_snapshot_reports_changed_window(self) -> None:
        data = load_fixture()
        previous = classify(data)["snapshot"]
        data["review_threads"] = [
            {
                "comments": {
                    "nodes": [
                        {
                            "createdAt": "2026-01-01T10:20:00Z",
                            "id": "comment-1",
                            "updatedAt": "2026-01-01T10:20:00Z",
                        }
                    ]
                },
                "id": "thread-1",
                "isOutdated": False,
                "isResolved": True,
                "line": 12,
                "originalLine": 12,
                "path": "scripts/example.py",
            }
        ]
        result = classify(data, previous=previous, snapshot_requested=True)
        self.assertEqual(result["status"], "CHANGED_DURING_WINDOW")
        self.assertEqual(
            result["change_detection"]["categories"]["threads"],
            ["added:review_thread:thread-1"],
        )

    def test_removed_thread_since_snapshot_reports_changed_window(self) -> None:
        data = load_fixture()
        data["review_threads"] = [
            {
                "comments": {"nodes": []},
                "id": "thread-1",
                "isOutdated": False,
                "isResolved": True,
                "line": 12,
                "originalLine": 12,
                "path": "scripts/example.py",
            }
        ]
        previous = classify(data)["snapshot"]
        data["review_threads"] = []
        result = classify(data, previous=previous, snapshot_requested=True)
        self.assertEqual(result["status"], "CHANGED_DURING_WINDOW")
        self.assertEqual(
            result["change_detection"]["categories"]["threads"],
            ["removed:review_thread:thread-1"],
        )

    def test_thread_reply_since_snapshot_reports_changed_window(self) -> None:
        data = load_fixture()
        data["review_threads"] = [
            {
                "comments": {
                    "nodes": [
                        {
                            "createdAt": "2026-01-01T10:20:00Z",
                            "id": "comment-1",
                            "updatedAt": "2026-01-01T10:20:00Z",
                        }
                    ]
                },
                "id": "thread-1",
                "isOutdated": False,
                "isResolved": True,
                "line": 12,
                "originalLine": 12,
                "path": "scripts/example.py",
            }
        ]
        previous = classify(data)["snapshot"]
        data["review_threads"][0]["comments"]["nodes"].append(
            {
                "createdAt": "2026-01-01T10:21:00Z",
                "id": "comment-2",
                "updatedAt": "2026-01-01T10:21:00Z",
            }
        )
        result = classify(data, previous=previous, snapshot_requested=True)
        self.assertEqual(result["status"], "CHANGED_DURING_WINDOW")
        self.assertEqual(
            result["change_detection"]["categories"]["threads"],
            ["modified:review_thread:thread-1"],
        )

    def test_resolved_thread_since_snapshot_reports_changed_window(self) -> None:
        data = load_fixture()
        data["review_threads"] = [
            {
                "comments": {"nodes": []},
                "id": "thread-1",
                "isOutdated": False,
                "isResolved": False,
                "line": 12,
                "originalLine": 12,
                "path": "scripts/example.py",
            }
        ]
        previous = classify(data)["snapshot"]
        data["review_threads"][0]["isResolved"] = True
        result = classify(data, previous=previous, snapshot_requested=True)
        self.assertEqual(result["status"], "CHANGED_DURING_WINDOW")
        self.assertEqual(
            result["change_detection"]["categories"]["threads"],
            ["modified:review_thread:thread-1"],
        )

    def test_stacked_pr_base_is_distinct_from_main_base(self) -> None:
        data = load_fixture()
        data["pull"]["base"]["ref"] = "feature-base"
        data["base_pull_candidates"] = [
            {
                "head": {"ref": "feature-base", "repo": {"full_name": "contributor/repo"}},
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
        self.assertEqual(result["stack"]["base_pr"]["head_repo"], "contributor/repo")

    def test_default_branch_base_is_not_treated_as_stacked_pr(self) -> None:
        data = load_fixture()
        data["pull"]["base"]["repo"]["default_branch"] = "main"
        data["base_pull_candidates"] = [
            {
                "head": {"ref": "main", "repo": {"full_name": "contributor/repo"}},
                "html_url": "https://github.com/owner/repo/pull/6",
                "number": 6,
                "state": "open",
                "title": "Unrelated PR from a branch named main",
            }
        ]
        result = classify(data)
        self.assertEqual(result["status"], "READY")
        self.assertFalse(result["stack"]["base_is_open_pr"])

    def test_base_pull_candidate_read_uses_head_ref_graphql_without_owner_filter(self) -> None:
        fixture = load_fixture()
        fixture["pull"]["base"]["ref"] = "feature-base"
        calls: list[str] = []
        head_ref_reads: list[str] = []
        candidates = [
            {
                "head": {"ref": "feature-base", "repo": {"full_name": "contributor/repo"}},
                "html_url": "https://github.com/owner/repo/pull/6",
                "number": 6,
                "state": "open",
                "title": "Base PR",
            }
        ]

        client = recording_base_candidate_client(fixture, candidates, calls, head_ref_reads)
        with mock.patch.object(pr_convergence, "GhClient", client):
            data = pr_convergence.gather_pr_state("owner/repo", 7)

        self.assertEqual(head_ref_reads, ["feature-base"])
        self.assertEqual(data["base_pull_candidates"][0]["head"]["repo"]["full_name"], "contributor/repo")
        self.assertNotIn("repos/owner/repo/pulls?state=open&per_page=100", calls)
        self.assertNotIn("repos/owner/repo/pulls?state=open&head=owner:feature-base&per_page=100", calls)

    def test_default_branch_base_skips_base_pull_candidate_read(self) -> None:
        fixture = load_fixture()
        fixture["pull"]["base"]["repo"]["default_branch"] = "main"
        calls: list[str] = []
        head_ref_reads: list[str] = []

        client = recording_base_candidate_client(fixture, [], calls, head_ref_reads)
        with mock.patch.object(pr_convergence, "GhClient", client):
            data = pr_convergence.gather_pr_state("owner/repo", 7)

        self.assertEqual(data["base_pull_candidates"], [])
        self.assertEqual(head_ref_reads, [])
        self.assertNotIn("repos/owner/repo/pulls?state=open&per_page=100", calls)

if __name__ == "__main__":
    unittest.main()
