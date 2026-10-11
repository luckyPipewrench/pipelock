#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Check Codecov's expected uploads against static CI upload jobs."""

from __future__ import annotations

import itertools
import re
import sys
from pathlib import Path

from yaml_contracts import UniqueKeyLoader, WorkflowLoader, yaml


ACTION = re.compile(r"^codecov/codecov-action@[^\s]+$", re.IGNORECASE)
EXPRESSION = re.compile(r"\$\{\{")
# GitHub Actions' documented maximum number of generated jobs per matrix.
MAX_MATRIX_JOBS = 256
# Local analysis budget, not a GitHub job limit. Permit substantial exclusion
# filtering while bounding validation, traversal, matching, and row updates.
MAX_MATRIX_WORK = MAX_MATRIX_JOBS ** 2


class TopologyError(ValueError):
    pass


def scalar_cost(value: object) -> int:
    if isinstance(value, (str, bytes)):
        return len(value)
    if isinstance(value, int):
        return max(1, (value.bit_length() + 7) // 8)
    if value is None or isinstance(value, float):
        return 1
    raise TopologyError("matrix has an unsupported scalar type")


class MatrixBudget:
    def __init__(self, label: str) -> None:
        self.label = label
        self.remaining = MAX_MATRIX_WORK

    def spend(self, amount: int = 1) -> None:
        self.remaining -= amount
        if self.remaining < 0:
            raise TopologyError(
                f"{self.label}.matrix exceeds validation work budget; "
                "simplify matrix axes, exclusions, or includes"
            )

    def equal(self, left: object, right: object) -> bool:
        pending = [(left, right)]
        while pending:
            left, right = pending.pop()
            self.spend()
            if isinstance(left, dict) and isinstance(right, dict):
                if len(left) != len(right):
                    return False
                self.spend(len(left))
                for key, value in left.items():
                    self.spend(scalar_cost(key))
                    if key not in right:
                        return False
                    pending.append((value, right[key]))
            elif isinstance(left, dict) or isinstance(right, dict):
                return False
            else:
                self.spend(scalar_cost(left) + scalar_cost(right))
                if isinstance(left, (int, float)) and isinstance(right, (int, float)) and isinstance(left, bool) != isinstance(right, bool):
                    raise TopologyError("mixed boolean/number matrix matching is unsupported; use consistent value types")
                if left != right:
                    return False
        return True


def mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise TopologyError(f"{label} must be a mapping")
    return value


# The one dynamic condition the count understands. A documentation-only pull
# request skips every coverage producer, so it uploads nothing and Codecov posts
# nothing; every other run uploads the full count. The exact text is pinned so a
# broader condition cannot silently shrink the count on ordinary runs.
DOCS_ONLY_SKIP = (
    "${{ !cancelled() && needs.security-scan.result == 'success' "
    "&& needs.changed-files.outputs.docs_only != 'true' }}"
)


def is_docs_only_skip(value: object) -> bool:
    return isinstance(value, str) and " ".join(value.split()) == DOCS_ONLY_SKIP


def enabled(value: object, label: str) -> bool:
    if value is None or value is True:
        return True
    if value is False:
        return False
    if is_docs_only_skip(value):
        return True
    raise TopologyError(f"{label} has unsupported condition {value!r}")


def static(value: object, label: str, budget: MatrixBudget) -> None:
    pending = [(value, frozenset())]
    while pending:
        item, ancestors = pending.pop()
        budget.spend()
        if isinstance(item, dict):
            if id(item) in ancestors:
                raise TopologyError(f"{label} has a cyclic object")
            budget.spend(len(ancestors) + 2 * len(item))
            branch = ancestors | {id(item)}
            for key, member in item.items():
                pending.extend(((key, branch), (member, branch)))
        else:
            budget.spend(scalar_cost(item))
            if (isinstance(item, str) and EXPRESSION.search(item)) or (isinstance(item, bytes) and b"${{" in item):
                raise TopologyError(f"{label} has a dynamic or unsupported list value")


def uploads_coverage(step: dict, label: str) -> bool:
    settings = mapping(step.get("with", {}), f"{label}.with")
    dry_run = settings.get("dry_run", False)
    if dry_run is True or dry_run == "true":
        return False
    if dry_run is not False and dry_run != "false":
        raise TopologyError(f"{label}.dry_run must be a static boolean")
    for key, default in (("run_command", "upload-coverage"), ("report_type", "coverage")):
        if settings.get(key, default) != default:
            raise TopologyError(f"{label}.{key} has an unsupported upload mode")
    return True


def cells(job: dict, label: str) -> list[dict]:
    if "strategy" not in job:
        return [{}]
    strategy = mapping(job["strategy"], f"{label}.strategy")
    if "matrix" not in strategy:
        return [{}]
    matrix = mapping(strategy["matrix"], f"{label}.matrix")
    budget = MatrixBudget(label)
    budget.spend(len(matrix))
    axes = {key: value for key, value in matrix.items() if key not in ("include", "exclude")}
    for key, values in axes.items():
        static(key, f"{label}.matrix axis", budget)
        if not isinstance(values, list) or not values:
            raise TopologyError(f"{label}.matrix.{key} must be a nonempty static list")
        for value in values:
            static(value, f"{label}.matrix.{key}", budget)
    for name in ("exclude", "include"):
        entries = matrix.get(name, [])
        if not isinstance(entries, list):
            raise TopologyError(f"{label}.matrix.{name} must be a static list")
        for entry in entries:
            budget.spend()
            mapping(entry, f"{label}.matrix.{name} entry")
            if not entry:
                raise TopologyError(f"{label}.matrix.{name} entry cannot be empty")
            for key, value in entry.items():
                static(key, f"{label}.matrix.{name} key", budget)
                static(value, f"{label}.matrix.{name}.{key}", budget)
    for entry in matrix.get("exclude", []):
        budget.spend(len(entry))
        if not set(entry) <= axes.keys():
            raise TopologyError(f"{label}.matrix.exclude references unknown axis")
    # Filter lazily: excluded combinations do not consume the generated-job
    # allowance, and an oversized matrix never becomes an unbounded list.
    result = []
    combinations = itertools.product(*axes.values()) if axes else ()
    def matches(cell: dict, entry: dict, axes_only: bool = False) -> bool:
        budget.spend()
        for key, value in entry.items():
            budget.spend(scalar_cost(key))
            if axes_only and key not in axes:
                continue
            if not budget.equal(cell.get(key), value):
                return False
        return True

    for values in combinations:
        budget.spend(1 + len(axes))
        cell = dict(zip(axes, values, strict=True))
        if any(matches(cell, entry) for entry in matrix.get("exclude", [])):
            continue
        if len(result) == MAX_MATRIX_JOBS:
            raise TopologyError(f"{label}.matrix exceeds {MAX_MATRIX_JOBS} generated jobs")
        result.append(cell)
    # Includes can extend original combinations, never another include-only row.
    # Keep the two sets separate, including for an include-only matrix.
    additions = []
    for entry in matrix.get("include", []):
        matching = [cell for cell in result if matches(cell, entry, axes_only=True)]
        if matching:
            for cell in matching:
                budget.spend(len(entry))
                cell.update(entry)
        else:
            if len(result) + len(additions) == MAX_MATRIX_JOBS:
                raise TopologyError(f"{label}.matrix exceeds {MAX_MATRIX_JOBS} generated jobs")
            budget.spend(len(entry))
            additions.append(dict(entry))
    result.extend(additions)
    if not result:
        raise TopologyError(f"{label}.matrix has no cells")
    return result


def upload_count(workflow: dict) -> int:
    jobs = mapping(workflow.get("jobs"), "workflow.jobs")
    reachable = {}
    visiting = set()

    def can_run(name: str) -> bool:
        if name in visiting:
            raise TopologyError(f"job {name} has cyclic needs")
        if name in reachable:
            return reachable[name]
        if name not in jobs:
            raise TopologyError(f"needs references missing job {name}")
        job = mapping(jobs[name], f"job {name}")
        if not enabled(job.get("if"), f"job {name}"):
            reachable[name] = False
            return False
        dependencies = job.get("needs", [])
        if isinstance(dependencies, str):
            dependencies = [dependencies]
        if not isinstance(dependencies, list) or any(not isinstance(dep, str) for dep in dependencies):
            raise TopologyError(f"job {name}.needs must name jobs")
        if is_docs_only_skip(job.get("if")):
            # !cancelled() runs past a skipped classifier (it skips on pushes),
            # so only the dependencies the condition does not test still gate.
            dependencies = [dep for dep in dependencies if dep != "changed-files"]
        visiting.add(name)
        ready = all([can_run(dep) for dep in dependencies])
        visiting.remove(name)
        if ready:
            cells(job, f"job {name}")
        reachable[name] = ready
        return ready

    count = 0
    for name, raw in jobs.items():
        job = mapping(raw, f"job {name}")
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            raise TopologyError(f"job {name}.steps must be a list")
        uploads = [step for step in steps if isinstance(step, dict) and ACTION.fullmatch(str(step.get("uses", "")))]
        if not uploads:
            continue
        if not can_run(name):
            continue
        expansion = cells(job, f"job {name}")
        for step in uploads:
            if enabled(step.get("if"), f"job {name} upload step") and uploads_coverage(step, f"job {name} upload step"):
                count += len(expansion)
    if count == 0:
        raise TopologyError("workflow has no reachable Codecov uploads")
    return count


def check(workflow_path: Path, codecov_path: Path) -> tuple[int, int]:
    try:
        workflow = mapping(yaml.load(workflow_path.read_text(encoding="utf-8"), Loader=WorkflowLoader), "workflow")
        codecov = mapping(yaml.load(codecov_path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader), "codecov config")
    except (OSError, ValueError, TypeError, yaml.YAMLError) as error:
        raise TopologyError(str(error)) from error
    expected = upload_count(workflow)
    actual = mapping(mapping(codecov.get("codecov"), "codecov").get("notify"), "codecov.notify").get("after_n_builds")
    if type(actual) is not int or actual < 1:
        raise TopologyError("codecov.notify.after_n_builds must be a positive integer")
    return expected, actual


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: check_codecov_upload_count.py WORKFLOW CODECOV", file=sys.stderr)
        return 2
    try:
        expected, actual = check(Path(argv[1]), Path(argv[2]))
    except TopologyError as error:
        print(f"codecov-upload-count: {error}", file=sys.stderr)
        return 2
    if actual != expected:
        print(f"codecov-upload-count: MISMATCH: after_n_builds={actual}, CI uploads={expected}", file=sys.stderr)
        return 1
    print(f"codecov-upload-count: OK (after_n_builds={actual}, CI uploads={expected})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
