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
import tempfile
from collections.abc import Callable
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
AI_REVIEW_RE = re.compile(r"^\s*##\s+AI Review\b", re.IGNORECASE | re.MULTILINE)
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
GH_READ_TIMEOUT_SECONDS = 30
GRAPHQL_MAX_PAGES = 100
SNAPSHOT_SCHEMA_VERSION = 2
GRAPHQL_ALLOWED_FIELDS = {"query", "owner", "name", "number", "after", "headRefName"}
GH_API_FIELD_FLAGS = {"-f", "-F", "--field", "--raw-field"}
GH_API_HEADER_FLAGS = {"-H", "--header"}


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


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def dotted_get(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        current = as_dict(current).get(key)
    return current


def map_open_pull_node(node_value: Any) -> dict[str, Any]:
    node = as_dict(node_value)
    return {
        "number": node.get("number"),
        "state": str(node.get("state") or "").lower(),
        "title": node.get("title"),
        "html_url": node.get("url"),
        "head": {
            "ref": node.get("headRefName"),
            "repo": {
                "full_name": dotted_get(node, "headRepository", "nameWithOwner"),
            },
        },
    }


def option_value(args: list[str], idx: int, names: set[str]) -> tuple[str | None, int] | None:
    arg = args[idx]
    if arg in names:
        if idx + 1 >= len(args):
            return None
        return args[idx + 1], idx + 2
    for name in names:
        if arg.startswith(f"{name}="):
            return arg.split("=", 1)[1], idx + 1
        if name.startswith("-") and len(name) == 2 and arg.startswith(name) and arg != name:
            return arg[len(name):], idx + 1
    return None


def field_name(value: str) -> str | None:
    if "=" not in value:
        return None
    name, _ = value.split("=", 1)
    return name or None


def graphql_query_is_read_only(query: str) -> bool:
    stripped = query.lstrip()
    if not stripped:
        return False
    if stripped.startswith("{"):
        return True
    match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\b", stripped)
    if not match:
        return False
    return match.group(1).lower() == "query"


def gh_args_are_read_only(args: list[str]) -> bool:
    if not args:
        return False
    if args[0] in {"pr", "repo"}:
        return len(args) > 1 and args[1] == "view"
    if args[0] != "api":
        return False
    if len(args) < 2:
        return False
    is_graphql = args[1] == "graphql"
    graphql_query = ""
    if not is_graphql and args[1].startswith("-"):
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
        if arg == "--input" or arg.startswith("--input="):
            return False
    idx = 2
    while idx < len(args):
        arg = args[idx]
        if arg in {"--paginate", "--slurp"}:
            idx += 1
            continue
        header = option_value(args, idx, GH_API_HEADER_FLAGS)
        if header is not None:
            if header[0] is None:
                return False
            idx = header[1]
            continue
        method = option_value(args, idx, {"-X", "--method"})
        if method is not None:
            if method[0] is None or method[0].upper() != "GET":
                return False
            idx = method[1]
            continue
        field = option_value(args, idx, GH_API_FIELD_FLAGS)
        if field is not None:
            if not is_graphql or field[0] is None:
                return False
            name = field_name(field[0])
            if name not in GRAPHQL_ALLOWED_FIELDS:
                return False
            if name == "query":
                graphql_query = field[0].split("=", 1)[1]
            idx = field[1]
            continue
        if arg.startswith("-"):
            return False
        return False
    if is_graphql and not graphql_query_is_read_only(graphql_query):
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
                timeout=GH_READ_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise GhReadError(f"gh timed out after {GH_READ_TIMEOUT_SECONDS}s") from exc
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

    def graphql_paginated_nodes(
        self,
        *,
        query: str,
        variables: dict[str, Any],
        connection_path: tuple[str, ...],
        connection_name: str,
        nodes_name: str,
        node_mapper: Callable[[Any], dict[str, Any]],
    ) -> list[dict[str, Any]]:
        after: str | None = None
        nodes: list[dict[str, Any]] = []
        seen_cursors: set[str] = set()
        for _ in range(GRAPHQL_MAX_PAGES):
            args = [
                "api",
                "graphql",
                "-f",
                f"query={query}",
                "-f",
                f"owner={self.owner}",
                "-f",
                f"name={self.name}",
            ]
            for name, value in variables.items():
                flag = "-F" if isinstance(value, int) else "-f"
                args.extend([flag, f"{name}={value}"])
            if after:
                args.extend(["-f", f"after={after}"])
            data = self.run(args)
            if not isinstance(data, dict):
                raise GhReadError("GraphQL response was not an object")
            repository = as_dict(dotted_get(data, "data", "repository"))
            connection = dotted_get(repository, *connection_path)
            if not isinstance(connection, dict):
                raise GhReadError(f"GraphQL response did not include {connection_name}")
            page_nodes = connection.get("nodes") or []
            if not isinstance(page_nodes, list):
                raise GhReadError(f"GraphQL {nodes_name} nodes was not a list")
            nodes.extend(node_mapper(node_value) for node_value in page_nodes)
            page_info = as_dict(connection.get("pageInfo"))
            if not page_info.get("hasNextPage"):
                return nodes
            after = page_info.get("endCursor")
            if not after:
                raise GhReadError("GraphQL pagination omitted endCursor")
            if after in seen_cursors:
                raise GhReadError(f"GraphQL pagination repeated cursor for {connection_name}")
            seen_cursors.add(after)
        raise GhReadError(f"GraphQL pagination exceeded {GRAPHQL_MAX_PAGES} pages for {connection_name}")

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
        return self.graphql_paginated_nodes(
            query=query,
            variables={"number": pr_number},
            connection_path=("pullRequest", "reviewThreads"),
            connection_name="reviewThreads",
            nodes_name="reviewThreads",
            node_mapper=as_dict,
        )

    def graphql_open_pulls_by_head_ref(self, head_ref_name: str) -> list[dict[str, Any]]:
        query = """
query($owner: String!, $name: String!, $headRefName: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(first: 100, states: OPEN, headRefName: $headRefName, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number
        state
        title
        url
        headRefName
        headRepository { nameWithOwner }
      }
    }
  }
}
"""
        return self.graphql_paginated_nodes(
            query=query,
            variables={"headRefName": head_ref_name},
            connection_path=("pullRequests",),
            connection_name="pullRequests",
            nodes_name="pullRequests",
            node_mapper=map_open_pull_node,
        )


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
    pull_data = as_dict(data["pull"])
    base_ref = str(dotted_get(pull_data, "base", "ref") or "")
    default_branch = str(dotted_get(pull_data, "base", "repo", "default_branch") or "")
    head_sha = str(dotted_get(pull_data, "head", "sha") or "")
    base_sha = str(dotted_get(pull_data, "base", "sha") or "")

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

    if base_ref and base_ref != default_branch:
        data["base_pull_candidates"] = read_source(
            "base_pull_candidates",
            lambda: client.graphql_open_pulls_by_head_ref(base_ref),
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
        raw_commit = as_dict(commit.get("commit"))
        committer = as_dict(raw_commit.get("committer"))
        author = as_dict(raw_commit.get("author"))
        return parse_iso8601(committer.get("date")) or parse_iso8601(author.get("date"))
    if commits:
        raw_commit = as_dict(commits[-1].get("commit"))
        committer = as_dict(raw_commit.get("committer"))
        author = as_dict(raw_commit.get("author"))
        return parse_iso8601(committer.get("date")) or parse_iso8601(author.get("date"))
    return None


def normalize_review_threads(threads: list[dict[str, Any]]) -> dict[str, Any]:
    unresolved: list[dict[str, Any]] = []
    null_line_comments: list[dict[str, Any]] = []
    for thread in threads:
        comments = as_list(dotted_get(thread, "comments", "nodes"))
        normalized_comments: list[dict[str, Any]] = []
        for comment_value in comments:
            comment = as_dict(comment_value)
            line = comment.get("line")
            original_line = comment.get("originalLine")
            item = {
                "id": comment.get("id"),
                "author": dotted_get(comment, "author", "login"),
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
    for comment_value in comments:
        comment = as_dict(comment_value)
        if comment.get("line") is not None and comment.get("original_line") is not None:
            continue
        null_line_comments.append(
            {
                "id": comment.get("id"),
                "author": dotted_get(comment, "user", "login"),
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
    if actionable_count(body) > 0:
        return True
    return not any(marker in body for marker in CLEAN_AI_MARKERS)


def normalize_issue_comments(
    comments: list[dict[str, Any]],
    latest_head_commit_at: dt.datetime | None,
) -> dict[str, Any]:
    ai_comments: list[dict[str, Any]] = []
    unreviewed: list[dict[str, Any]] = []
    for comment_value in comments:
        comment = as_dict(comment_value)
        body = str(comment.get("body") or "")
        created_at = parse_iso8601(comment.get("created_at"))
        if not AI_REVIEW_RE.search(body):
            continue
        item = {
            "id": comment.get("id"),
            "author": dotted_get(comment, "user", "login"),
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

    for review_value in reviews:
        review = as_dict(review_value)
        body = str(review.get("body") or "")
        count = actionable_count(body)
        actionable_total += count
        state = str(review.get("state") or "").upper()
        commit_id = review.get("commit_id")
        item = {
            "id": review.get("id"),
            "author": dotted_get(review, "user", "login"),
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

    for run_value in check_runs_from_payload(check_runs_payload):
        run = as_dict(run_value)
        name = str(run.get("name") or dotted_get(run, "check_suite", "app", "slug") or "")
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
    for status_value in statuses:
        status = as_dict(status_value)
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
    pull = as_dict(data.get("pull"))
    base = as_dict(pull.get("base"))
    head = as_dict(pull.get("head"))
    candidates = as_list(data.get("base_pull_candidates"))
    base_ref = base.get("ref")
    default_branch = dotted_get(base, "repo", "default_branch")
    base_pr = None
    if base_ref and base_ref != default_branch:
        for candidate_value in candidates:
            candidate = as_dict(candidate_value)
            candidate_head = as_dict(candidate.get("head"))
            if candidate.get("number") == pr_number or candidate_head.get("ref") != base_ref:
                continue
            base_pr = {
                "number": candidate.get("number"),
                "state": candidate.get("state"),
                "title": candidate.get("title"),
                "head_ref": candidate_head.get("ref"),
                "head_repo": dotted_get(candidate_head, "repo", "full_name"),
                "url": candidate.get("html_url"),
            }
            break
    compare = as_dict(data.get("compare"))
    behind_by = int(compare.get("behind_by") or 0)
    return {
        "base_ref": base_ref,
        "base_sha": base.get("sha"),
        "base_repo": dotted_get(base, "repo", "full_name"),
        "head_ref": head.get("ref"),
        "head_sha": head.get("sha"),
        "head_repo": dotted_get(head, "repo", "full_name"),
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
    for thread_value in raw_review_threads:
        thread = as_dict(thread_value)
        thread_comments = as_list(dotted_get(thread, "comments", "nodes"))
        thread_fingerprints.append(
            {
                "id": thread.get("id"),
                "kind": "review_thread",
                "is_resolved": thread.get("isResolved"),
                "comments": [
                    {
                        "id": as_dict(comment).get("id"),
                        "kind": "thread_comment",
                        "updated_at": as_dict(comment).get("updatedAt") or as_dict(comment).get("createdAt"),
                    }
                    for comment in thread_comments
                ],
            }
        )
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "repo": result["repo"],
        "pr_number": result["pr"]["number"],
        "head_sha": result["pr"]["head_sha"],
        "comments": [
            {"kind": "issue_comment", "id": item.get("id"), "updated_at": item.get("updated_at")}
            for item in result.get("_raw_issue_comments", [])
        ]
        + [
            {"kind": "review_comment", "id": item.get("id"), "updated_at": item.get("updated_at")}
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
    for idx, item_value in enumerate(items):
        item = as_dict(item_value)
        value = item.get(key)
        item_key = str(value if value is not None else idx)
        kind = item.get("kind")
        if kind:
            item_key = f"{kind}:{item_key}"
        output[item_key] = item
    return output


def changed_keys(previous: list[dict[str, Any]], current: list[dict[str, Any]], key: str = "id") -> list[str]:
    prev = indexed(previous, key)
    cur = indexed(current, key)
    changed = [f"added:{item_key}" for item_key in sorted(set(cur) - set(prev))]
    changed.extend(f"removed:{item_key}" for item_key in sorted(set(prev) - set(cur)))
    for item_key in sorted(set(cur) & set(prev)):
        if cur[item_key] != prev[item_key]:
            changed.append(f"modified:{item_key}")
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
        "comments": changed_keys(as_list(previous.get("comments")), as_list(current.get("comments"))),
        "reviews": changed_keys(as_list(previous.get("reviews")), as_list(current.get("reviews"))),
        "threads": changed_keys(as_list(previous.get("threads")), as_list(current.get("threads"))),
        "checks": changed_keys(as_list(previous.get("checks")), as_list(current.get("checks")), "name"),
        "commits": sorted(
            set(str(item) for item in current.get("commits", []))
            - set(str(item) for item in previous.get("commits", []))
        ),
    }
    if previous.get("schema_version") != current.get("schema_version"):
        categories["schema_version"] = [
            f"modified:{previous.get('schema_version')}->{current.get('schema_version')}"
        ]
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
    pull = as_dict(data.get("pull"))
    pr_number = int(data.get("pr_number") or pull.get("number") or 0)
    head_sha = dotted_get(pull, "head", "sha") or ""
    commits = data.get("commits") or []
    latest_head_commit_at = head_commit_time(commits, head_sha)

    result: dict[str, Any] = {
        "repo": data.get("repo"),
        "pr": {
            "number": pr_number,
            "url": pull.get("html_url"),
            "title": pull.get("title"),
            "base_ref": dotted_get(pull, "base", "ref"),
            "head_ref": dotted_get(pull, "head", "ref"),
            "base_sha": dotted_get(pull, "base", "sha"),
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
        if path.is_symlink():
            raise DataSourceError("snapshot", f"snapshot must not be a symlink: {path}")
        stat_result = path.stat()
        if stat_result.st_uid != os.geteuid():
            raise DataSourceError("snapshot", f"snapshot is not owned by the current user: {path}")
        if stat_result.st_mode & 0o077:
            raise DataSourceError("snapshot", f"snapshot is group/other accessible: {path}")
        parent_stat = path.parent.stat()
        parent_is_sticky = bool(parent_stat.st_mode & 0o1000)
        if parent_stat.st_mode & 0o022 and not parent_is_sticky:
            raise DataSourceError("snapshot", f"snapshot directory is group/other writable: {path.parent}")
        with path.open("r", encoding="utf-8") as handle:
            snapshot = json.load(handle)
    except DataSourceError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise DataSourceError("snapshot", f"failed to read snapshot {path}: {exc}") from exc
    if not isinstance(snapshot, dict):
        raise DataSourceError("snapshot", "snapshot root was not an object")
    schema_version = snapshot.get("schema_version")
    if schema_version not in {1, SNAPSHOT_SCHEMA_VERSION}:
        raise DataSourceError("snapshot", f"unsupported snapshot schema_version: {schema_version}")
    for key in ("repo", "pr_number", "head_sha"):
        if key not in snapshot:
            raise DataSourceError("snapshot", f"snapshot missing required field: {key}")
    for key in ("comments", "reviews", "threads", "checks", "commits", "ai_review_comments"):
        if key in snapshot and not isinstance(snapshot[key], list):
            raise DataSourceError("snapshot", f"snapshot field must be a list: {key}")
    return snapshot


def write_snapshot(path: Path, snapshot: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(snapshot, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_path, path)
        path.chmod(0o600)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


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
