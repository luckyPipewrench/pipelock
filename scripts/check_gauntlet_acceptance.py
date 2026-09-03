#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Enforce the Pipelock-owned Gauntlet acceptance contract.

The neutral benchmark evaluator compares aggregate rates. An equal aggregate
built from a different set of failures is a different product result, so this
check binds the exact case identities Pipelock accepts. It fails closed: any
unreadable, malformed, or unexpected input is a failure, never a pass.
"""

import argparse
import json
import sys
from pathlib import Path

REQUIRED_CONTRACT_KEYS = (
    "schema_version",
    "pipelock_version",
    "bench_commit",
    "corpus_version",
    "active_case_count",
    "containment",
    "false_positives",
    "accepted_containment_misses",
    "accepted_false_positives",
)


def load_object(path):
    """Read a JSON object from path, refusing any other JSON shape."""
    with Path(path).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def load_contract(path):
    """Load the acceptance contract, refusing one that contradicts itself."""
    contract = load_object(path)
    missing = [key for key in REQUIRED_CONTRACT_KEYS if key not in contract]
    if missing:
        raise ValueError(f"acceptance contract missing required keys: {missing!r}")
    if contract["schema_version"] != 1:
        raise ValueError("acceptance contract schema_version must be 1")
    for key in ("pipelock_version", "corpus_version"):
        if not isinstance(contract[key], str) or not contract[key]:
            raise ValueError(f"acceptance contract {key} must be a non-empty string")
    bench_commit = contract["bench_commit"]
    if (
        not isinstance(bench_commit, str)
        or len(bench_commit) != 40
        or any(character not in "0123456789abcdef" for character in bench_commit)
    ):
        raise ValueError("acceptance contract bench_commit must be a lower-case Git SHA")
    active_case_count = contract["active_case_count"]
    if (
        isinstance(active_case_count, bool)
        or not isinstance(active_case_count, int)
        or active_case_count < 1
    ):
        raise ValueError("acceptance contract active_case_count must be a positive integer")
    for key in ("accepted_containment_misses", "accepted_false_positives"):
        identifiers = contract[key]
        if not isinstance(identifiers, list) or not all(
            isinstance(item, str) and item for item in identifiers
        ):
            raise ValueError(f"acceptance contract {key} must be a list of non-empty strings")
        if len(set(identifiers)) != len(identifiers):
            raise ValueError(f"acceptance contract {key} must not repeat a case identifier")
    for key in ("containment", "false_positives"):
        fraction = contract[key]
        if not isinstance(fraction, dict) or set(fraction) != {"numerator", "denominator"}:
            raise ValueError(
                f"acceptance contract {key} must be an object with numerator and denominator"
            )
        for field, value in fraction.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(
                    f"acceptance contract {key}.{field} must be a non-negative integer"
                )
        if fraction["denominator"] < 1:
            raise ValueError(f"acceptance contract {key}.denominator must be positive")
        if fraction["numerator"] > fraction["denominator"]:
            raise ValueError(
                f"acceptance contract {key}.numerator cannot exceed its denominator"
            )
    if len(contract["accepted_containment_misses"]) != (
        contract["containment"]["denominator"] - contract["containment"]["numerator"]
    ):
        raise ValueError(
            "acceptance contract accepted_containment_misses must match containment counts"
        )
    if len(contract["accepted_false_positives"]) != contract["false_positives"]["numerator"]:
        raise ValueError(
            "acceptance contract accepted_false_positives must match false-positive counts"
        )
    if (
        contract["containment"]["denominator"]
        + contract["false_positives"]["denominator"]
        != active_case_count
    ):
        raise ValueError(
            "acceptance contract metric denominators must equal active_case_count"
        )
    return contract


def read_results(path):
    """Return the observed misses, false positives, and per-expectation counts.

    Every record must be classifiable. An unrecognized verdict pair is a
    failure rather than an ignored row, so a runner change cannot silently
    drop a failing case out of the comparison, and the counts let the caller
    check that the result file evaluated the population the contract names.
    """
    misses = set()
    false_positives = set()
    seen = set()
    expected_counts = {"block": 0, "allow": 0}
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{line_number} must contain a JSON object")
            case_id = record.get("case_id")
            if not isinstance(case_id, str) or not case_id:
                raise ValueError(f"{path}:{line_number} has no case_id")
            if case_id in seen:
                raise ValueError(f"{path}:{line_number} repeats case_id {case_id!r}")
            seen.add(case_id)
            expected = record.get("expected_verdict")
            actual = record.get("actual_verdict")
            score = record.get("score")
            # A JSON array or object is unhashable, so the string check must
            # come first or set membership raises TypeError and escapes the
            # fail-closed diagnostic in main().
            if not isinstance(expected, str) or expected not in {"block", "allow"}:
                raise ValueError(f"{path}:{line_number} has invalid expected_verdict")
            if not isinstance(actual, str) or actual not in {"block", "allow"}:
                raise ValueError(f"{path}:{line_number} has invalid actual_verdict")
            if not isinstance(score, str) or score not in {"pass", "fail"}:
                raise ValueError(f"{path}:{line_number} has invalid score")
            expected_counts[expected] += 1
            if (score == "pass") != (actual == expected):
                raise ValueError(
                    f"{path}:{line_number} score does not match expected and actual verdicts"
                )
            if score == "pass":
                continue
            # The checks above admit only "block" and "allow", and require a
            # failing score to disagree with its expectation, so a failing row
            # is exactly one of the two classes.
            if expected == "block":
                misses.add(case_id)
            else:
                false_positives.add(case_id)
    return misses, false_positives, len(seen), expected_counts


def compare_identities(label, observed, accepted):
    """Report failing cases that are unaccepted, and accepted cases that now pass."""
    failures = []
    unexpected = sorted(observed - accepted)
    resolved = sorted(accepted - observed)
    if unexpected:
        failures.append(f"unaccepted {label}: {unexpected}")
    if resolved:
        failures.append(
            f"accepted {label} no longer failing: {resolved}; "
            "update benchmark/gauntlet-acceptance.json and benchmark/gauntlet-baseline.json "
            "in the same reviewed change"
        )
    return failures


def check(contract_path, candidate_path, results_path):
    """Return every way the candidate and its results depart from the contract."""
    failures = []
    contract = load_contract(contract_path)
    candidate = load_object(candidate_path)

    for field in ("pipelock_version", "corpus_version"):
        if candidate.get(field) != contract[field]:
            failures.append(
                f"candidate {field}={candidate.get(field)!r}, contract accepts "
                f"{contract[field]!r}"
            )
    if candidate.get("corpus_git_sha") != contract["bench_commit"]:
        failures.append(
            f"candidate corpus_git_sha={candidate.get('corpus_git_sha')!r}, contract accepts "
            f"{contract['bench_commit']!r}"
        )

    case_count = candidate.get("case_count")
    if not isinstance(case_count, dict):
        failures.append(f"candidate case_count={case_count!r}, want an object")
        case_count = {}
    for field, want in (
        ("total", contract["active_case_count"]),
        ("applicable", contract["active_case_count"]),
        ("errors", 0),
        ("unreachable", 0),
        ("not_applicable", 0),
    ):
        value = case_count.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value != want:
            failures.append(f"candidate case_count.{field}={value!r}, want {want}")

    metric_counts = candidate.get("metric_counts")
    if not isinstance(metric_counts, dict):
        failures.append(f"candidate metric_counts={metric_counts!r}, want an object")
        metric_counts = {}
    for scope in ("full", "applicable"):
        scope_counts = metric_counts.get(scope)
        if not isinstance(scope_counts, dict):
            failures.append(f"candidate metric_counts.{scope} must be an object")
            continue
        for metric, expected in (
            ("containment", contract["containment"]),
            ("false_positive_rate", contract["false_positives"]),
        ):
            observed = scope_counts.get(metric)
            if not isinstance(observed, dict):
                failures.append(f"candidate metric_counts.{scope}.{metric} must be an object")
                continue
            for field in ("numerator", "denominator"):
                value = observed.get(field)
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value != expected[field]
                ):
                    failures.append(
                        f"candidate metric_counts.{scope}.{metric}.{field}={value!r}, "
                        f"contract accepts {expected[field]}"
                    )

    misses, false_positives, observed_cases, expected_counts = read_results(results_path)
    if observed_cases != contract["active_case_count"]:
        failures.append(
            f"results carry {observed_cases} cases, contract accepts "
            f"{contract['active_case_count']}"
        )
    # The row total alone cannot see a case moved between populations, which
    # would evaluate a different corpus while every other number still agrees.
    for verdict, metric in (("block", "containment"), ("allow", "false_positives")):
        observed_population = expected_counts[verdict]
        accepted_population = contract[metric]["denominator"]
        if observed_population != accepted_population:
            failures.append(
                f"results carry {observed_population} cases expecting {verdict!r}, "
                f"contract accepts {accepted_population}"
            )
    failures.extend(
        compare_identities(
            "containment misses", misses, set(contract["accepted_containment_misses"])
        )
    )
    failures.extend(
        compare_identities(
            "false positives", false_positives, set(contract["accepted_false_positives"])
        )
    )
    return failures


def main(argv=None):
    """Run the acceptance check and return the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        failures = check(args.contract, args.candidate, args.results)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"::error::Gauntlet acceptance check failed closed: {exc}", file=sys.stderr)
        return 1
    if failures:
        for failure in failures:
            print(f"::error::{failure}", file=sys.stderr)
        print(f"Gauntlet acceptance: BLOCKED ({len(failures)} failure(s))")
        return 1
    print("Gauntlet acceptance: PASS (exact accepted result reproduced)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
