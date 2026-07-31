#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Report whether a GitHub pull request has converged.

The command is read-only. It gathers PR metadata, review threads, top-level
comments, review summaries, commits, and current-head checks through the `gh`
CLI, then emits one structured convergence result.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


STATUS_DOCS: dict[str, str] = {
    "READY": "Current head has no detected blockers after an unchanged snapshot window.",
    "CHECKS_PENDING": "At least one current-head check or status context is queued or in progress.",
    "CHECKS_FAILING": "At least one current-head check or status context failed, errored, or was cancelled.",
    "UNRESOLVED_THREADS": "At least one review thread is unresolved, including outside-diff/null-line comments.",
    "UNREVIEWED_AI_FINDINGS": "A current-head top-level AI Review comment appears to contain findings.",
    "STALE_REVIEW": "The only approval evidence is tied to an older head SHA.",
    "STALE_CHECK": "A collected check run or status context is tied to an older head SHA.",
    "REVIEW_CHANGES_REQUESTED": "A current-head review requested changes.",
    "CONFLICTED": "GitHub reports merge conflicts or a dirty merge state.",
    "BEHIND_BASE": "The PR head is behind its base branch or stacked base PR.",
    "MERGE_BLOCKED": "GitHub reports a blocked, draft, closed, or unknown merge state.",
    "CHANGED_DURING_WINDOW": "A comment, review, check, or commit changed since the prior snapshot.",
    "SNAPSHOT_MISSING": "A snapshot path was requested but no prior snapshot existed yet.",
    "DATA_SOURCE_UNAVAILABLE": "At least one required read source failed, so readiness is unknown.",
}

ACTIONABLE_RE = re.compile(
    r"Actionable\s+comments\s+posted:\s*(\d+)",
    re.IGNORECASE,
)
AI_REVIEW_RE = re.compile(r"^\s*##\s+AI Review\b", re.IGNORECASE)
CLEAN_AI_MARKERS = (
    "No material security or correctness issues found",
    "Test coverage is adequate",
    "Documentation accurately reflects the codebase in this diff",
    "No actionable comments posted",
)
PENDING_CHECK_STATES = {"queued", "requested", "waiting", "pending", "in_progress"}
FAILING_CHECK_CONCLUSIONS = {
    "action_required",
    "cancelled",
    "failure",
    "startup_failure",
    "timed_out",
}
PASSING_CHECK_CONCLUSIONS = {"neutral", "skipped", "success"}
CONFLICT_MERGE_STATES = {"DIRTY"}
BLOCKED_MERGE_STATES = {"BLOCKED", "DRAFT", "UNKNOWN"}
FINAL_REVIEW_STATES = {"APPROVED", "CHANGES_REQUESTED"}


class DataSourceError(RuntimeError):
    """Raised when a required read source cannot be gathered."""

    def __init__(self, source: str, message: str) -> None:
        super().__init__(message)
        self.source = source


class GhReadError(DataSourceError):
    """Raised when a read-only GitHub source cannot be gathered."""

    def __init__(self, message: str) -> None:
        super().__init__("gh", message)


def parse_iso8601(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.UTC)
    return parsed.astimezone(dt.UTC)


def parse_repo(repo: str) -> tuple[str, str]:
    parts = repo.split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("repo must use owner/name format")
    return parts[0], parts[1]


def sorted_dict_list(values: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    return sorted(values, key=lambda item: str(item.get(key, "")))


def gh_args_are_read_only(args: list[str]) -> bool:
    if not args:
        return False
    if args[0] in {"pr", "repo"}:
        return len(args) > 1 and args[1] == "view"
    if args[0] != "api":
        return False
    if len(args) > 1 and args[1] == "graphql":
        query_args = [arg for arg in args if arg.startswith("query=") or arg.startswith("-fquery=")]
        query_text = " ".join(query_args).lower()
        if "mutation" in query_text:
            return False
    for idx, arg in enumerate(args):
        if arg in {"-X", "--method"}:
            if idx + 1 >= len(args) or args[idx + 1].upper() != "GET":
                return False
        if arg.startswith("-X") and arg != "-X":
            if arg[2:].upper() != "GET":
                return False
        if arg.startswith("--method=") and arg.split("=", 1)[1].upper() != "GET":
            return False
    return True


class GhClient:
    def __init__(self, repo: str) -> None:
        self.repo = repo
        self.owner, self.name = parse_repo(repo)

    def run(self, args: list[str]) -> Any:
        if not gh_args_are_read_only(args):
            raise GhReadError(f"refusing non-read-only gh invocation: gh {' '.join(args)}")
        try:
            proc = subprocess.run(
                ["gh", *args],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as exc:
            raise GhReadError(f"failed to execute gh: {exc}") from exc
        if proc.returncode != 0:
            message = proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}"
            raise GhReadError(message)
        output = proc.stdout.strip()
        if not output:
            return None
        try:
            return json.loads(output)
        except json.JSONDecodeError as exc:
            raise GhReadError(f"gh returned invalid JSON: {exc}") from exc

    def api(self, path: str, *, paginate: bool = False, accept: str | None = None) -> Any:
        args = ["api", path]
        if accept:
            args.extend(["-H", f"Accept: {accept}"])
        if paginate:
            args.extend(["--paginate", "--slurp"])
            pages = self.run(args)
            if pages is None:
                return []
            if isinstance(pages, list) and all(isinstance(page, list) for page in pages):
                flattened: list[Any] = []
                for page in pages:
                    flattened.extend(page)
                return flattened
            return pages
        return self.run(args)

    def graphql_review_threads(self, pr_number: int) -> list[dict[str, Any]]:
        query = """
query($owner: String!, $name: String!, $number: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          isResolved
          isOutdated
          path
          line
          originalLine
          comments(first: 50) {
            nodes {
              id
              author { login }
              body
              createdAt
              updatedAt
              url
              path
              line
              originalLine
              commit { oid }
              originalCommit { oid }
            }
          }
        }
      }
    }
  }
}
"""
        after: str | None = None
        nodes: list[dict[str, Any]] = []
        while True:
            args = [
                "api",
                "graphql",
                "-f",
                f"query={query}",
                "-F",
                f"owner={self.owner}",
                "-F",
                f"name={self.name}",
                "-F",
                f"number={pr_number}",
            ]
            if after:
                args.extend(["-F", f"after={after}"])
            data = self.run(args)
            if not isinstance(data, dict):
                raise GhReadError("GraphQL response was not an object")
            pull = (
                data.get("data", {})
                .get("repository", {})
                .get("pullRequest")
            )
            if not isinstance(pull, dict):
                raise GhReadError("GraphQL response did not include pullRequest")
            threads = pull.get("reviewThreads")
            if not isinstance(threads, dict):
                raise GhReadError("GraphQL response did not include reviewThreads")
            page_nodes = threads.get("nodes") or []
            if not isinstance(page_nodes, list):
                raise GhReadError("GraphQL reviewThreads nodes was not a list")
            nodes.extend(page_nodes)
            page_info = threads.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                return nodes
            after = page_info.get("endCursor")
            if not after:
                raise GhReadError("GraphQL pagination omitted endCursor")


def gather_pr_state(repo: str, pr_number: int) -> dict[str, Any]:
    client = GhClient(repo)
    data: dict[str, Any] = {"repo": repo, "pr_number": pr_number, "errors": []}

    def read_source(name: str, fn: Any) -> Any:
        try:
            return fn()
        except GhReadError as exc:
            data["errors"].append({"source": name, "message": str(exc)})
            return None

    pull = read_source(
        "pull",
        lambda: client.api(f"repos/{repo}/pulls/{pr_number}"),
    )
    data["pull"] = pull or {}
    base_ref = data["pull"].get("base", {}).get("ref", "")
    head_sha = data["pull"].get("head", {}).get("sha", "")
    base_sha = data["pull"].get("base", {}).get("sha", "")

    data["issue_comments"] = read_source(
        "issue_comments",
        lambda: client.api(
            f"repos/{repo}/issues/{pr_number}/comments?per_page=100",
            paginate=True,
        ),
    ) or []
    data["reviews"] = read_source(
        "reviews",
        lambda: client.api(f"repos/{repo}/pulls/{pr_number}/reviews?per_page=100", paginate=True),
    ) or []
    data["review_comments"] = read_source(
        "review_comments",
        lambda: client.api(f"repos/{repo}/pulls/{pr_number}/comments?per_page=100", paginate=True),
    ) or []
    data["commits"] = read_source(
        "commits",
        lambda: client.api(f"repos/{repo}/pulls/{pr_number}/commits?per_page=100", paginate=True),
    ) or []
    data["review_threads"] = read_source(
        "review_threads",
        lambda: client.graphql_review_threads(pr_number),
    ) or []

    if head_sha:
        data["check_runs"] = read_source(
            "check_runs",
            lambda: client.api(
                f"repos/{repo}/commits/{head_sha}/check-runs?per_page=100",
                paginate=True,
                accept="application/vnd.github+json",
            ),
        ) or {"check_runs": []}
        data["status"] = read_source(
            "status",
            lambda: client.api(f"repos/{repo}/commits/{head_sha}/status"),
        ) or {"statuses": []}
    else:
        data["errors"].append({"source": "checks", "message": "pull head SHA unavailable"})
        data["check_runs"] = {"check_runs": []}
        data["status"] = {"statuses": []}

    if base_ref:
        owner, _ = parse_repo(repo)
        data["base_pull_candidates"] = read_source(
            "base_pull_candidates",
            lambda: client.api(
                f"repos/{repo}/pulls?state=open&head={owner}:{base_ref}&per_page=100",
                paginate=True,
            ),
        ) or []
    else:
        data["base_pull_candidates"] = []

    if base_sha and head_sha:
        data["compare"] = read_source(
            "compare",
            lambda: client.api(f"repos/{repo}/compare/{base_sha}...{head_sha}"),
        ) or {}
    else:
        data["errors"].append({"source": "compare", "message": "base or head SHA unavailable"})
        data["compare"] = {}

    return data


def head_commit_time(commits: list[dict[str, Any]], head_sha: str) -> dt.datetime | None:
    for commit in commits:
        if commit.get("sha") != head_sha:
            continue
        raw_commit = commit.get("commit") or {}
        committer = raw_commit.get("committer") or {}
        author = raw_commit.get("author") or {}
        return parse_iso8601(committer.get("date")) or parse_iso8601(author.get("date"))
    if commits:
        raw_commit = (commits[-1].get("commit") or {})
        committer = raw_commit.get("committer") or {}
        author = raw_commit.get("author") or {}
        return parse_iso8601(committer.get("date")) or parse_iso8601(author.get("date"))
    return None


def normalize_review_threads(threads: list[dict[str, Any]]) -> dict[str, Any]:
    unresolved: list[dict[str, Any]] = []
    null_line_comments: list[dict[str, Any]] = []
    for thread in threads:
        comments = ((thread.get("comments") or {}).get("nodes") or [])
        normalized_comments: list[dict[str, Any]] = []
        for comment in comments:
            line = comment.get("line")
            original_line = comment.get("originalLine")
            item = {
                "id": comment.get("id"),
                "author": (comment.get("author") or {}).get("login"),
                "path": comment.get("path") or thread.get("path"),
                "line": line,
                "original_line": original_line,
                "url": comment.get("url"),
                "created_at": comment.get("createdAt"),
                "updated_at": comment.get("updatedAt"),
            }
            normalized_comments.append(item)
            if line is None or original_line is None:
                null_line_comments.append(item)
        if not thread.get("isResolved", False):
            unresolved.append(
                {
                    "id": thread.get("id"),
                    "path": thread.get("path"),
                    "line": thread.get("line"),
                    "original_line": thread.get("originalLine"),
                    "is_outdated": bool(thread.get("isOutdated", False)),
                    "comments": normalized_comments,
                }
            )
    return {
        "total_count": len(threads),
        "unresolved_count": len(unresolved),
        "threads": unresolved,
        "outside_diff_or_null_line_count": len(null_line_comments),
        "outside_diff_or_null_line_comments": null_line_comments,
    }


def normalize_review_comments(comments: list[dict[str, Any]]) -> dict[str, Any]:
    null_line_comments: list[dict[str, Any]] = []
    for comment in comments:
        if comment.get("line") is not None and comment.get("original_line") is not None:
            continue
        null_line_comments.append(
            {
                "id": comment.get("id"),
                "author": (comment.get("user") or {}).get("login"),
                "path": comment.get("path"),
                "line": comment.get("line"),
                "original_line": comment.get("original_line"),
                "position": comment.get("position"),
                "url": comment.get("html_url"),
                "created_at": comment.get("created_at"),
                "updated_at": comment.get("updated_at"),
            }
        )
    return {
        "total_count": len(comments),
        "outside_diff_or_null_line_count": len(null_line_comments),
        "outside_diff_or_null_line_comments": null_line_comments,
    }


def ai_review_has_findings(body: str) -> bool:
    if not AI_REVIEW_RE.search(body):
        return False
    return not any(marker in body for marker in CLEAN_AI_MARKERS)


def normalize_issue_comments(
    comments: list[dict[str, Any]],
    latest_head_commit_at: dt.datetime | None,
) -> dict[str, Any]:
    ai_comments: list[dict[str, Any]] = []
    unreviewed: list[dict[str, Any]] = []
    for comment in comments:
        body = str(comment.get("body") or "")
        created_at = parse_iso8601(comment.get("created_at"))
        if not AI_REVIEW_RE.search(body):
            continue
        item = {
            "id": comment.get("id"),
            "author": (comment.get("user") or {}).get("login"),
            "created_at": comment.get("created_at"),
            "updated_at": comment.get("updated_at"),
            "url": comment.get("html_url"),
            "has_findings": ai_review_has_findings(body),
        }
        ai_comments.append(item)
        is_current_head_comment = (
            latest_head_commit_at is None
            or created_at is None
            or created_at >= latest_head_commit_at
        )
        if item["has_findings"] and is_current_head_comment:
            unreviewed.append(item)
    return {
        "count": len(comments),
        "ai_review_count": len(ai_comments),
        "ai_review_comments": ai_comments,
        "unreviewed_ai_finding_count": len(unreviewed),
        "unreviewed_ai_findings": unreviewed,
    }


def actionable_count(body: str) -> int:
    total = 0
    for match in ACTIONABLE_RE.finditer(body):
        total += int(match.group(1))
    return total


def normalize_reviews(reviews: list[dict[str, Any]], head_sha: str) -> dict[str, Any]:
    normalized: list[dict[str, Any]] = []
    actionable_total = 0
    current_head_reviews: list[dict[str, Any]] = []
    stale_reviews: list[dict[str, Any]] = []
    approvals_current = 0
    approvals_stale = 0
    current_changes_requested = 0

    for review in reviews:
        body = str(review.get("body") or "")
        count = actionable_count(body)
        actionable_total += count
        state = str(review.get("state") or "").upper()
        commit_id = review.get("commit_id")
        item = {
            "id": review.get("id"),
            "author": (review.get("user") or {}).get("login"),
            "state": state,
            "commit_id": commit_id,
            "submitted_at": review.get("submitted_at"),
            "html_url": review.get("html_url"),
            "actionable_comments_posted": count,
            "is_current_head": commit_id == head_sha,
        }
        normalized.append(item)
        if commit_id == head_sha:
            current_head_reviews.append(item)
            if state == "APPROVED":
                approvals_current += 1
            if state == "CHANGES_REQUESTED":
                current_changes_requested += 1
        elif commit_id:
            stale_reviews.append(item)
            if state == "APPROVED":
                approvals_stale += 1

    latest_final_state = ""
    final_reviews = [item for item in normalized if item["state"] in FINAL_REVIEW_STATES]
    if final_reviews:
        final_reviews.sort(key=lambda item: str(item.get("submitted_at") or ""))
        latest_final_state = str(final_reviews[-1]["state"])

    return {
        "count": len(reviews),
        "current_head_count": len(current_head_reviews),
        "stale_count": len(stale_reviews),
        "stale_reviews": stale_reviews,
        "actionable_comments_total": actionable_total,
        "approvals_current_head": approvals_current,
        "approvals_stale": approvals_stale,
        "stale_approval_without_current_approval": approvals_stale > 0 and approvals_current == 0,
        "current_head_changes_requested_count": current_changes_requested,
        "latest_final_state": latest_final_state,
        "reviews": normalized,
    }


def check_runs_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        runs = payload.get("check_runs") or []
        return runs if isinstance(runs, list) else []
    if isinstance(payload, list):
        runs: list[dict[str, Any]] = []
        for item in payload:
            if isinstance(item, dict) and "check_runs" in item:
                page_runs = item.get("check_runs") or []
                if isinstance(page_runs, list):
                    runs.extend(page_runs)
            elif isinstance(item, dict):
                runs.append(item)
        return runs
    return []


def classify_check(name: str, status: str, conclusion: str) -> tuple[str, dict[str, str]]:
    item = {"name": name, "status": status, "conclusion": conclusion}
    normalized_status = status.lower()
    normalized_conclusion = conclusion.lower()
    if normalized_status in PENDING_CHECK_STATES or (
        normalized_status != "completed" and not normalized_conclusion
    ):
        return "pending", item
    if normalized_conclusion in FAILING_CHECK_CONCLUSIONS:
        return "failing", item
    if normalized_conclusion in PASSING_CHECK_CONCLUSIONS:
        return "passing", item
    if normalized_conclusion:
        return "failing", item
    return "pending", item


def normalize_checks(check_runs_payload: Any, status_payload: Any, head_sha: str) -> dict[str, Any]:
    pending: list[dict[str, str]] = []
    failing: list[dict[str, str]] = []
    passing: list[dict[str, str]] = []
    stale: list[dict[str, Any]] = []

    for run in check_runs_from_payload(check_runs_payload):
        name = str(run.get("name") or run.get("check_suite", {}).get("app", {}).get("slug") or "")
        item_sha = run.get("head_sha")
        if item_sha and item_sha != head_sha:
            stale.append({"type": "check_run", "name": name, "head_sha": item_sha})
            continue
        bucket, item = classify_check(
            name,
            str(run.get("status") or ""),
            str(run.get("conclusion") or ""),
        )
        {"pending": pending, "failing": failing, "passing": passing}[bucket].append(item)

    statuses = []
    if isinstance(status_payload, dict):
        statuses = status_payload.get("statuses") or []
    for status in statuses:
        name = str(status.get("context") or "")
        item_sha = status.get("sha")
        if item_sha and item_sha != head_sha:
            stale.append({"type": "status", "name": name, "head_sha": item_sha})
            continue
        state = str(status.get("state") or "")
        if state == "success":
            passing.append({"name": name, "status": state, "conclusion": "success"})
        elif state in {"pending", "expected"}:
            pending.append({"name": name, "status": state, "conclusion": ""})
        else:
            failing.append({"name": name, "status": state, "conclusion": state})

    return {
        "head_sha": head_sha,
        "pending": sorted_dict_list(pending, "name"),
        "failing": sorted_dict_list(failing, "name"),
        "passing": sorted_dict_list(passing, "name"),
        "stale": sorted_dict_list(stale, "name"),
        "pending_count": len(pending),
        "failing_count": len(failing),
        "passing_count": len(passing),
        "stale_count": len(stale),
    }


def normalize_stack(data: dict[str, Any], pr_number: int) -> dict[str, Any]:
    pull = data.get("pull") or {}
    base = pull.get("base") or {}
    head = pull.get("head") or {}
    candidates = data.get("base_pull_candidates") or []
    base_pr = None
    for candidate in candidates:
        if candidate.get("number") == pr_number:
            continue
        base_pr = {
            "number": candidate.get("number"),
            "state": candidate.get("state"),
            "title": candidate.get("title"),
            "head_ref": (candidate.get("head") or {}).get("ref"),
            "url": candidate.get("html_url"),
        }
        break
    compare = data.get("compare") or {}
    behind_by = int(compare.get("behind_by") or 0)
    return {
        "base_ref": base.get("ref"),
        "base_sha": base.get("sha"),
        "base_repo": (base.get("repo") or {}).get("full_name"),
        "head_ref": head.get("ref"),
        "head_sha": head.get("sha"),
        "head_repo": (head.get("repo") or {}).get("full_name"),
        "base_is_open_pr": base_pr is not None,
        "base_pr": base_pr,
        "head_behind_base": behind_by > 0,
        "compare_status": compare.get("status"),
        "behind_by": behind_by,
        "ahead_by": int(compare.get("ahead_by") or 0),
    }


def build_snapshot(result: dict[str, Any]) -> dict[str, Any]:
    comments = result["top_level_comments"]
    reviews = result["review_summaries"]
    checks = result["required_checks"]
    raw_review_comments = result.get("_raw_review_comments", [])
    raw_review_threads = result.get("_raw_review_threads", [])
    thread_fingerprints = []
    for thread in raw_review_threads:
        thread_comments = ((thread.get("comments") or {}).get("nodes") or [])
        thread_fingerprints.append(
            {
                "id": thread.get("id"),
                "is_resolved": thread.get("isResolved"),
                "comments": [
                    {
                        "id": comment.get("id"),
                        "updated_at": comment.get("updatedAt") or comment.get("createdAt"),
                    }
                    for comment in thread_comments
                ],
            }
        )
    return {
        "schema_version": 1,
        "repo": result["repo"],
        "pr_number": result["pr"]["number"],
        "head_sha": result["pr"]["head_sha"],
        "comments": [
            {"id": item.get("id"), "updated_at": item.get("updated_at")}
            for item in result.get("_raw_issue_comments", [])
        ]
        + [
            {"id": item.get("id"), "updated_at": item.get("updated_at")}
            for item in raw_review_comments
        ],
        "reviews": [
            {
                "id": item.get("id"),
                "state": item.get("state"),
                "commit_id": item.get("commit_id"),
                "submitted_at": item.get("submitted_at"),
            }
            for item in reviews["reviews"]
        ],
        "threads": thread_fingerprints,
        "checks": checks["pending"] + checks["failing"] + checks["passing"] + checks["stale"],
        "commits": [item.get("sha") for item in result.get("_raw_commits", [])],
        "ai_review_comments": comments["ai_review_comments"],
    }


def indexed(items: list[dict[str, Any]], key: str = "id") -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for idx, item in enumerate(items):
        value = item.get(key)
        output[str(value if value is not None else idx)] = item
    return output


def changed_keys(previous: list[dict[str, Any]], current: list[dict[str, Any]], key: str = "id") -> list[str]:
    prev = indexed(previous, key)
    cur = indexed(current, key)
    changed = sorted(set(cur) - set(prev))
    for item_key in sorted(set(cur) & set(prev)):
        if cur[item_key] != prev[item_key]:
            changed.append(item_key)
    return changed


def compare_snapshots(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    if previous is None:
        return {
            "enabled": False,
            "previous_snapshot_found": False,
            "changed": False,
            "categories": {},
        }

    categories = {
        "comments": changed_keys(previous.get("comments", []), current.get("comments", [])),
        "reviews": changed_keys(previous.get("reviews", []), current.get("reviews", [])),
        "checks": changed_keys(previous.get("checks", []), current.get("checks", []), "name"),
        "commits": sorted(
            set(str(item) for item in current.get("commits", []))
            - set(str(item) for item in previous.get("commits", []))
        ),
    }
    changed = any(categories.values()) or previous.get("head_sha") != current.get("head_sha")
    if previous.get("head_sha") != current.get("head_sha"):
        categories["head_sha"] = [str(current.get("head_sha"))]
    return {
        "enabled": True,
        "previous_snapshot_found": True,
        "changed": changed,
        "categories": categories,
    }


def choose_status(result: dict[str, Any], snapshot_missing: bool) -> str:
    merge = result["merge"]
    merge_state = str(merge.get("merge_state_status") or "").upper()
    if result["errors"]:
        return "DATA_SOURCE_UNAVAILABLE"
    if result["change_detection"]["changed"]:
        return "CHANGED_DURING_WINDOW"
    if merge.get("mergeable") is False or merge_state in CONFLICT_MERGE_STATES:
        return "CONFLICTED"
    if result["stack"]["head_behind_base"]:
        return "BEHIND_BASE"
    if result["required_checks"]["stale_count"] > 0:
        return "STALE_CHECK"
    if result["required_checks"]["failing_count"] > 0:
        return "CHECKS_FAILING"
    if result["required_checks"]["pending_count"] > 0:
        return "CHECKS_PENDING"
    if result["review_summaries"]["stale_approval_without_current_approval"]:
        return "STALE_REVIEW"
    if result["review_summaries"]["current_head_changes_requested_count"] > 0:
        return "REVIEW_CHANGES_REQUESTED"
    if result["review_threads"]["unresolved_count"] > 0:
        return "UNRESOLVED_THREADS"
    if result["top_level_comments"]["unreviewed_ai_finding_count"] > 0:
        return "UNREVIEWED_AI_FINDINGS"
    if merge_state in BLOCKED_MERGE_STATES or merge.get("is_draft") or merge.get("state") != "open":
        return "MERGE_BLOCKED"
    if snapshot_missing:
        return "SNAPSHOT_MISSING"
    return "READY"


def classify_pr_state(
    data: dict[str, Any],
    *,
    previous_snapshot: dict[str, Any] | None = None,
    snapshot_requested: bool = False,
) -> dict[str, Any]:
    pull = data.get("pull") or {}
    pr_number = int(data.get("pr_number") or pull.get("number") or 0)
    head_sha = (pull.get("head") or {}).get("sha") or ""
    commits = data.get("commits") or []
    latest_head_commit_at = head_commit_time(commits, head_sha)

    result: dict[str, Any] = {
        "repo": data.get("repo"),
        "pr": {
            "number": pr_number,
            "url": pull.get("html_url"),
            "title": pull.get("title"),
            "base_ref": (pull.get("base") or {}).get("ref"),
            "head_ref": (pull.get("head") or {}).get("ref"),
            "base_sha": (pull.get("base") or {}).get("sha"),
            "head_sha": head_sha,
        },
        "stack": normalize_stack(data, pr_number),
        "review_threads": normalize_review_threads(data.get("review_threads") or []),
        "inline_comments": normalize_review_comments(data.get("review_comments") or []),
        "top_level_comments": normalize_issue_comments(
            data.get("issue_comments") or [],
            latest_head_commit_at,
        ),
        "review_summaries": normalize_reviews(data.get("reviews") or [], head_sha),
        "required_checks": normalize_checks(data.get("check_runs") or {}, data.get("status") or {}, head_sha),
        "merge": {
            "mergeable": pull.get("mergeable"),
            "merge_state_status": pull.get("mergeable_state") or pull.get("merge_state_status"),
            "is_draft": bool(pull.get("draft", False)),
            "state": str(pull.get("state") or "").lower(),
        },
        "errors": data.get("errors") or [],
        "_raw_issue_comments": data.get("issue_comments") or [],
        "_raw_review_comments": data.get("review_comments") or [],
        "_raw_review_threads": data.get("review_threads") or [],
        "_raw_commits": commits,
    }
    current_snapshot = build_snapshot(result)
    snapshot_missing = snapshot_requested and previous_snapshot is None
    result["change_detection"] = compare_snapshots(previous_snapshot, current_snapshot)
    result["snapshot"] = current_snapshot
    status = choose_status(result, snapshot_missing)
    result["status"] = status
    result["ready"] = status == "READY"
    result["status_reason"] = STATUS_DOCS[status]
    result.pop("_raw_issue_comments", None)
    result.pop("_raw_review_comments", None)
    result.pop("_raw_review_threads", None)
    result.pop("_raw_commits", None)
    return result


def load_snapshot(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        if path.stat().st_mode & 0o022:
            raise DataSourceError("snapshot", f"snapshot is group/other writable: {path}")
        with path.open("r", encoding="utf-8") as handle:
            snapshot = json.load(handle)
    except DataSourceError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise DataSourceError("snapshot", f"failed to read snapshot {path}: {exc}") from exc
    if not isinstance(snapshot, dict):
        raise DataSourceError("snapshot", "snapshot root was not an object")
    return snapshot


def write_snapshot(path: Path, snapshot: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=2, sort_keys=True)
        handle.write("\n")
    path.chmod(0o600)


def compact_summary(result: dict[str, Any]) -> str:
    checks = result["required_checks"]
    threads = result["review_threads"]
    comments = result["top_level_comments"]
    reviews = result["review_summaries"]
    stack = result["stack"]
    change = result["change_detection"]
    lines = [
        f"status: {result['status']} - {result['status_reason']}",
        f"pr: #{result['pr']['number']} head={result['pr']['head_sha']} base={result['pr']['base_ref']}",
        (
            "stack: "
            f"base_is_open_pr={stack['base_is_open_pr']} "
            f"behind_base={stack['head_behind_base']} "
            f"compare={stack['compare_status']}"
        ),
        (
            "reviews: "
            f"unresolved_threads={threads['unresolved_count']} "
            f"stale={reviews['stale_count']} "
            f"actionable_summary_total={reviews['actionable_comments_total']} "
            f"ai_findings={comments['unreviewed_ai_finding_count']}"
        ),
        (
            "checks: "
            f"passing={checks['passing_count']} "
            f"pending={checks['pending_count']} "
            f"failing={checks['failing_count']} "
            f"stale={checks['stale_count']}"
        ),
        (
            "change_detection: "
            f"enabled={change['enabled']} "
            f"changed={change['changed']} "
            f"previous_snapshot_found={change['previous_snapshot_found']}"
        ),
    ]
    if result["errors"]:
        lines.append(f"errors: {len(result['errors'])} source(s) unavailable")
    return "\n".join(lines)


def status_epilog() -> str:
    lines = ["Status values:"]
    for name, description in STATUS_DOCS.items():
        lines.append(f"  {name}: {description}")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Return one structured PR convergence result.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=status_epilog(),
    )
    parser.add_argument("pr", nargs="?", help="pull request number; defaults to PR_NUMBER")
    parser.add_argument("--repo", default=os.environ.get("REPO", ""), help="owner/repo")
    parser.add_argument("--json", action="store_true", help="print a single JSON object")
    parser.add_argument(
        "--snapshot",
        type=Path,
        help="read a previous snapshot if present, then write the current snapshot",
    )
    return parser.parse_args(argv)


def infer_repo() -> str:
    data = GhClient("owner/repo").run(["repo", "view", "--json", "nameWithOwner"])
    if not isinstance(data, dict) or not data.get("nameWithOwner"):
        raise GhReadError("could not infer repository from gh repo view")
    return str(data["nameWithOwner"])


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    repo = args.repo or infer_repo()
    pr_raw = args.pr or os.environ.get("PR_NUMBER")
    if not pr_raw:
        raise SystemExit("PR number required as argument or PR_NUMBER")
    try:
        pr_number = int(pr_raw)
    except ValueError as exc:
        raise SystemExit("PR number must be an integer") from exc

    previous_snapshot = load_snapshot(args.snapshot) if args.snapshot else None
    data = gather_pr_state(repo, pr_number)
    result = classify_pr_state(
        data,
        previous_snapshot=previous_snapshot,
        snapshot_requested=args.snapshot is not None,
    )
    if args.snapshot:
        write_snapshot(args.snapshot, result["snapshot"])
    output = json.dumps(result, indent=2, sort_keys=True) if args.json else compact_summary(result)
    print(output)
    return 0 if result["status"] == "READY" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except DataSourceError as exc:
        error_result = {
            "status": "DATA_SOURCE_UNAVAILABLE",
            "ready": False,
            "status_reason": STATUS_DOCS["DATA_SOURCE_UNAVAILABLE"],
            "errors": [{"source": exc.source, "message": str(exc)}],
        }
        print(json.dumps(error_result, indent=2, sort_keys=True))
        raise SystemExit(1) from exc
