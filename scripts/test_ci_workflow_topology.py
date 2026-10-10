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
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yaml"
SHARDS = {
    "proxy-0", "proxy-1", "proxy-2", "proxy-3", "proxy-4", "scanner-0", "scanner-1", "scanner-2",
    "mcp-0", "mcp-1", "mcp-2", "mcp-3", "mcp-4",
    "runtime-0", "runtime-1", "rest-0", "rest-1", "rest-2", "rest-3",
}
MINORS = ("126", "127")
POLICY_OUTPUT = "${{ needs.changed-files.outputs.ci_policy }}"
DOCS_OUTPUT = "${{ needs.changed-files.outputs.docs_only }}"
SCAN_SUCCESS_CONDITION = "${{ needs.security-scan.result == 'success' }}"
ALWAYS_CONDITION = "${{ always() }}"
NEEDS_RESULT_RE = re.compile(r"\$\{\{\s*needs\.([A-Za-z0-9_-]+)\.result\s*\}\}")

# The one aggregate gate that tolerates a skipped producer, the producers it
# tolerates, and the producer-side condition that makes tolerating them correct.
# Named once so the gate's expectation and its justification cannot drift apart.
EVENT_NAMES = ("push", "pull_request")
SKIP_CARVEOUT_AGGREGATE = "test-go127"
SKIP_CARVEOUT_PRODUCERS = {"test-oss-go127", "test-enterprise-go127"}
# The COMPLETE approved predicate, not a fragment of it. A substring test here
# is the weak form and was reproduced as a bypass: appending
# `&& github.event.action != 'opened'` keeps the fragment, still skips an opened
# pull request whose CI policy DID change, and the aggregate gate accepts any
# skipped producer on a pull request. Compare the whole normalized string so a
# broadened predicate cannot keep the approved words while changing when the
# producer actually skips.
SKIP_CARVEOUT_CONDITION = (
    "${{ !cancelled() && needs.security-scan.result == 'success' "
    "&& github.event_name == 'pull_request' "
    "&& needs.changed-files.outputs.ci_policy == 'true' }}"
)
# Go 1.26 race lane: main pushes and other non-pull-request events only.
RACE_PRODUCERS = {"test-oss-go126", "test-enterprise-go126"}
RACE_AGGREGATE = "race-go126"
RACE_LANE_CONDITION = "${{ github.event_name != 'pull_request' }}"
RACE_AGGREGATE_CONDITION = "${{ always() && github.event_name != 'pull_request' }}"
# Concurrent-job cap per race matrix. The main race lane gets six per build
# variant; the Go 1.27 matrix, which runs beside a pull request's own no-race
# lane, gets four.
RACE_MAX_PARALLEL = {
    "test-oss-go126": 6,
    "test-enterprise-go126": 6,
    "test-oss-go127": 4,
    "test-enterprise-go127": 4,
}
# The no-race lane every pull request waits on. Heavy trees run whole; the rest
# shards are the planner's rest buckets.
UNIT_PRODUCER = "test-unit-go126"
# A documentation-only pull request skips these Go producers; test (1.26)
# accepts the skip only with a successful classifier that said docs_only.
DOCS_CARVEOUT_AGGREGATE = "test-go126"
DOCS_CARVEOUT_PRODUCERS = {UNIT_PRODUCER, "test-subprocess-coverage", "guard-conformance"}
DOCS_SKIP_CONDITION = (
    "${{ !cancelled() && needs.security-scan.result == 'success' "
    "&& needs.changed-files.outputs.docs_only != 'true' }}"
)
# The planner owns the shard list; the workflow matrix must match it exactly.
UNIT_SHARDS = set(json.loads(subprocess.run(
    ["python3", str(ROOT / "scripts" / "ci_test_packages.py"), "--list-unit-shards"],
    check=True, capture_output=True, text=True,
).stdout))
REQUIRED_PRODUCERS = {
    "security-scan",
    "test-go126",
    "test-go127",
    "test-macos",
    "lint",
    "build",
    "govulncheck",
}


def substitute_needs_results(run: str, results: dict[str, str]) -> str:
    """Replace GitHub-only needs expressions with fixed synthetic result values.

    GitHub expands these expressions before handing the script to bash.  The
    topology test performs that expansion itself, but only from its fixed
    result table: workflow text cannot select a shell value or inject syntax.
    """

    def replacement(match: re.Match[str]) -> str:
        dependency = match.group(1)
        if dependency not in results:
            raise ValueError(f"gate references undeclared dependency {dependency}")
        return results[dependency]

    return NEEDS_RESULT_RE.sub(replacement, run)


def gate_script_is_safe(run: str) -> bool:
    """Allow only the tiny shell subset used by aggregate compatibility gates.

    The execution harness has an empty PATH and a temporary working directory.
    This additional grammar fence rejects command substitution, redirection,
    absolute paths, and commands other than shell builtins before bash sees a
    workflow change.  A gate that needs a broader shell program must gain a
    purpose-built harness instead of silently acquiring CI-environment access.
    """
    allowed_line = re.compile(
        r'''^(?:
            set\ -u|
            echo\ "[^"]*"|
            test\ "[^"]*"\ =\ "(?:success|true|false)"(?:\ \|\|\ \{)?|
            if\ \[\ "\$EVENT_NAME"\ =\ "pull_request"\ \];\ then|
            if\ \[\ "[^"]*"\ !=\ "false"\ \];\ then|
            if\ !\ test\ "[^"]*"\ =\ "success";\ then|
            if\ \[\ "\$EVENT_NAME"\ !=\ "pull_request"\ \]\ \|\|\ \[\ "[^"]*"\ !=\ "skipped"\ \];\ then|
            if\ \[\ "[^"]*"\ !=\ "skipped"\ \];\ then|
            \[\ "\$EVENT_NAME"\ (?:=|!=)\ "pull_request"\ \]\ \&\&|
            \[\ "[^"]*"\ (?:=|!=)\ "skipped"\ \]|
            exit\ 1|fi|\}
        )$''',
        re.VERBOSE,
    )
    if not isinstance(run, str):
        return False
    # Neutralize the GitHub-only needs expressions FIRST, then refuse any other
    # dollar expansion or backtick. Without this the line grammar below is much
    # weaker than it reads: `$(...)` contains no double quote, so it matches the
    # `[^"]*` inside an otherwise-legitimate `test "..." = "success"` line and
    # sails through. Proven by reproduction before this guard existed --
    # `test "$(/usr/bin/touch FILE)" = "success"` was reported safe AND created
    # the file, because an absolute path needs no PATH lookup. The empty PATH in
    # execute_gate is therefore not the backstop it appears to be, and the
    # docstring above was claiming a property the grammar did not hold.
    neutralized = NEEDS_RESULT_RE.sub(
        "success", run.replace(POLICY_OUTPUT, "false").replace(DOCS_OUTPUT, "false")
    )
    # Then refuse the backslash. `echo "x\"` satisfies the `echo\ "[^"]*"`
    # alternative below -- the escaped quote is just another `[^"]` byte -- while
    # bash reads it as an OPEN string, so the next line is string content rather
    # than the comment this validator skips it as. Proven by reproduction:
    # `echo "x\"` followed by `# "; /usr/bin/touch FILE` was reported safe AND
    # created the file. This is the same shape as the `$(...)` bypass guarded
    # above, and it is the second form of it found, so the rule is the list:
    # every quoting form bash treats specially must be named here, because the
    # grammar's coverage is exactly the set someone thought to enumerate --
    # command substitution `$(...)`, backtick, and now backslash continuation.
    if "\\" in neutralized:
        return False
    for line in neutralized.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        without_event = stripped.replace('"$EVENT_NAME"', '"pull_request"')
        if "$" in without_event or "`" in without_event:
            return False
    return all(
        allowed_line.fullmatch(line.strip())
        for line in neutralized.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def execute_gate(
    run: str, results: dict[str, str], event_name: str, ci_policy: str = "false", docs_only: str = "false"
) -> int:
    """Run a safe aggregate gate as GitHub's bash shell would run it."""
    if not gate_script_is_safe(run):
        raise ValueError("aggregate gate contains shell outside the safe execution subset")
    with tempfile.TemporaryDirectory(prefix="pipelock-ci-gate-") as temp_dir:
        completed = subprocess.run(
            [
                "/usr/bin/bash", "-eo", "pipefail", "-c",
                substitute_needs_results(run.replace(POLICY_OUTPUT, ci_policy).replace(DOCS_OUTPUT, docs_only), results),
            ],
            cwd=temp_dir,
            env={
                "EVENT_NAME": event_name,
                "HOME": temp_dir,
                "PATH": "",
                "TMPDIR": temp_dir,
            },
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    return completed.returncode


def gate_execution_errors(aggregate: str, run: str, dependencies: set[str]) -> list[str]:
    """Return failures from executing every aggregate result state.

    Go 1.27 may accept a skipped shard producer, which runs only on a pull
    request that changes CI policy.  Every other omitted, unknown, cancelled,
    or failed producer result must red the aggregate required check.
    """
    errors = []
    successful = {dependency: "success" for dependency in dependencies}
    cases = [
        ("all producers succeed", successful, event_name, "false", 0)
        for event_name in EVENT_NAMES
    ]
    for dependency in sorted(dependencies):
        for result in ("failure", "cancelled", "", "unknown", "skipped"):
            values = successful | {dependency: result}
            for event_name in EVENT_NAMES:
                legitimate_skip = (
                    aggregate == SKIP_CARVEOUT_AGGREGATE
                    and dependency in SKIP_CARVEOUT_PRODUCERS
                    and result == "skipped"
                )
                # Policy detection intentionally does not run on pushes.
                ignored_policy = dependency == "changed-files" and event_name == "push"
                cases.append((
                    f"{dependency}={result or 'empty'}", values, event_name, "false",
                    0 if legitimate_skip or ignored_policy else 1,
                ))
    if aggregate == SKIP_CARVEOUT_AGGREGATE:
        skipped = successful | dict.fromkeys(SKIP_CARVEOUT_PRODUCERS, "skipped")
        for policy in ("true", "", "unknown", "TRUE"):
            cases.append((f"skipped race producers, ci_policy={policy!r}",
                          skipped, "pull_request", policy, 1))
        for producer in sorted(SKIP_CARVEOUT_PRODUCERS):
            cases.append((f"{producer}=skipped with ci_policy=true",
                          successful | {producer: "skipped"}, "pull_request", "true", 1))
        cases.append(("CI-policy change proved", successful, "pull_request", "true", 0))
        for policy in ("", "unknown", "TRUE"):
            cases.append((f"invalid ci_policy={policy!r}", successful, "pull_request", policy, 1))
        for result in ("failure", "cancelled", "", "unknown", "skipped"):
            cases.append((f"skipped race producers, changed-files={result!r}",
                          skipped | {"changed-files": result}, "pull_request", "false", 1))
        cases.append(("intentional push skips", skipped | {"changed-files": "skipped"},
                      "push", "", 0))
    docs_cases = []
    if aggregate == DOCS_CARVEOUT_AGGREGATE:
        skipped = successful | dict.fromkeys(DOCS_CARVEOUT_PRODUCERS, "skipped")
        docs_cases.append(("documentation-only skips", skipped, "pull_request", "true", 0))
        for docs in ("false", "", "TRUE", "unknown"):
            docs_cases.append((f"skipped Go producers, docs_only={docs!r}", skipped, "pull_request", docs, 1))
        docs_cases.append(("documentation-only skips on push", skipped, "push", "true", 1))
        for result in ("failure", "cancelled", "", "unknown", "skipped"):
            docs_cases.append((f"documentation-only skips, changed-files={result!r}",
                               skipped | {"changed-files": result}, "pull_request", "true", 1))
        for producer in sorted(DOCS_CARVEOUT_PRODUCERS):
            for result in ("failure", "cancelled", "", "unknown"):
                docs_cases.append((f"{producer}={result or 'empty'} on a documentation-only change",
                                   skipped | {producer: result}, "pull_request", "true", 1))
        for producer in sorted(dependencies - DOCS_CARVEOUT_PRODUCERS - {"changed-files"}):
            docs_cases.append((f"{producer}=skipped on a documentation-only change",
                               skipped | {producer: "skipped"}, "pull_request", "true", 1))
    # Ordinary cases run with docs_only false; docs cases with CI policy false.
    all_cases = [(d, v, e, p, x, "false") for d, v, e, p, x in cases]
    all_cases += [(d, v, e, "false", x, docs) for d, v, e, docs, x in docs_cases]
    for description, values, event_name, policy, expected, docs in all_cases:
        try:
            actual = execute_gate(run, values, event_name, policy, docs)
        except (subprocess.TimeoutExpired, ValueError) as error:
            errors.append(f"{aggregate} gate cannot safely execute: {error}")
            break
        if (actual == 0) != (expected == 0):
            errors.append(
                f"{aggregate} gate returned {actual} for {description} on {event_name}; "
                f"expected {'zero' if expected == 0 else 'non-zero'}"
            )
    return errors


def skip_carveout_errors(jobs: dict) -> list[str]:
    """Pin the race producers to the approved event and policy predicate.

    The aggregate independently checks detector success and an explicit false
    output on pull requests before accepting a skip. Pinning this predicate
    prevents an additional producer-side condition from skipping a required
    CI-policy run.
    """
    errors = []
    approved = " ".join(SKIP_CARVEOUT_CONDITION.split())
    for producer in sorted(SKIP_CARVEOUT_PRODUCERS):
        condition = jobs.get(producer, {}).get("if")
        normalized = " ".join(condition.split()) if isinstance(condition, str) else None
        if normalized != approved:
            errors.append(
                f"{producer} changed its approved event / CI-policy path predicate, "
                f"so the {SKIP_CARVEOUT_AGGREGATE} gate's skipped "
                f"carve-out is unjustified"
            )
    return errors


def race_lane_errors(jobs: dict) -> list[str]:
    """Pin the Go 1.26 race lane to main-side events and a bounded footprint.

    The race producers are skipped on every pull request by design, so they
    must not feed a required check; they roll up into race (1.26), which itself
    does not run on pull requests and fails closed on any non-success result.
    """
    errors = []
    for producer in sorted(RACE_PRODUCERS):
        if jobs.get(producer, {}).get("if") != RACE_LANE_CONDITION:
            errors.append(f"{producer} must run on every non-pull-request event and only those")
    # Every race matrix, including the Go 1.27 one CI-policy pull requests run,
    # shares the account's runners with pull requests that are waiting.
    for producer in sorted(RACE_PRODUCERS | SKIP_CARVEOUT_PRODUCERS):
        job = jobs.get(producer, {})
        cap = RACE_MAX_PARALLEL[producer]
        max_parallel = job.get("strategy", {}).get("max-parallel")
        if isinstance(max_parallel, bool) or not isinstance(max_parallel, int) or not 1 <= max_parallel <= cap:
            errors.append(
                f"{producer} must cap max-parallel at {cap} so a race matrix cannot "
                f"take the runners pull requests are waiting on"
            )
    for aggregate, job in jobs.items():
        if aggregate != RACE_AGGREGATE and RACE_PRODUCERS & set(job.get("needs", []) or []):
            errors.append(f"{aggregate} consumes race-lane evidence that pull requests never produce")
    race = jobs.get(RACE_AGGREGATE)
    if race is None:
        errors.append(f"missing {RACE_AGGREGATE}")
        return errors
    if race.get("name") != "race (1.26)":
        errors.append(f"{RACE_AGGREGATE} changed its display name")
    if race.get("if") != RACE_AGGREGATE_CONDITION:
        errors.append(f"{RACE_AGGREGATE} must run after failed producers and never on pull requests")
    dependencies = set(race.get("needs", []) or [])
    if dependencies != {"security-scan", *RACE_PRODUCERS}:
        errors.append(f"{RACE_AGGREGATE} needs {sorted(dependencies)}")
    steps = race.get("steps", [])
    if len(steps) != 1 or not step_runs_unconditionally(steps[0]):
        errors.append(f"{RACE_AGGREGATE} gate can skip and green after failed evidence")
        return errors
    successful = dict.fromkeys(dependencies, "success")
    try:
        if execute_gate(steps[0].get("run", ""), successful, "push") != 0:
            errors.append(f"{RACE_AGGREGATE} gate fails when every producer succeeds")
        for dependency in sorted(dependencies):
            for result in ("failure", "cancelled", "", "unknown", "skipped"):
                if execute_gate(steps[0].get("run", ""), successful | {dependency: result}, "push") == 0:
                    errors.append(f"{RACE_AGGREGATE} gate passes with {dependency}={result or 'empty'}")
    except (subprocess.TimeoutExpired, ValueError) as error:
        errors.append(f"{RACE_AGGREGATE} gate cannot safely execute: {error}")
    return errors


def unit_lane_errors(jobs: dict) -> list[str]:
    """The no-race lane is what pull requests wait on: it must run everywhere."""
    errors = []
    unit = jobs.get(UNIT_PRODUCER)
    if unit is None:
        return [f"missing {UNIT_PRODUCER}"]
    condition = unit.get("if")
    if not isinstance(condition, str) or " ".join(condition.split()) != " ".join(DOCS_SKIP_CONDITION.split()):
        errors.append(f"{UNIT_PRODUCER} must run on every event except a documentation-only pull request")
    if set(unit.get("needs", []) or []) != {"security-scan", "changed-files"}:
        errors.append(f"{UNIT_PRODUCER} can execute PR code before a successful security scan")
    matrix = unit.get("strategy", {}).get("matrix", {})
    if matrix.get("variant") != ["oss", "enterprise"]:
        errors.append(f"{UNIT_PRODUCER} must test both build variants")
    if set(matrix.get("shard", [])) != UNIT_SHARDS:
        errors.append(f"{UNIT_PRODUCER} does not cover every package shard")
    run = "\n".join(step.get("run", "") for step in unit.get("steps", []))
    go_tests = [line for line in run.splitlines() if line.strip().startswith("go test ")]
    if not go_tests:
        errors.append(f"{UNIT_PRODUCER} runs no go test command")
    if any(re.search(r"(?:^|\s)-race(?:\s|$)", line) for line in go_tests):
        errors.append(f"{UNIT_PRODUCER} runs the race detector; that belongs to the race lane")
    return errors


def step_runs_unconditionally(step: dict) -> bool:
    """Return True when a step cannot skip after its job has already started.

    A skipped compatibility or summary step turns `if: always()` into success:
    prior steps were skipped, not failed, so GitHub reports the job green.
    """
    return step.get("if") in (None, ALWAYS_CONDITION, "always()")


def workflow_jobs(workflow: Path = WORKFLOW) -> dict:
    """Load CI jobs, refusing malformed or structurally incomplete workflows."""
    try:
        document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError(f"cannot parse CI workflow: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("jobs"), dict):
        raise ValueError("CI workflow has no jobs mapping")
    return document["jobs"]


def topology_errors(jobs: dict) -> list[str]:
    """Return every broken topology invariant for useful negative fixtures."""
    errors = []
    for minor in MINORS:
        oss = f"test-oss-go{minor}"
        enterprise = f"test-enterprise-go{minor}"
        replay = f"test-replay-go{minor}"
        aggregate = f"test-go{minor}"
        for producer in (oss, enterprise, replay, aggregate):
            if producer not in jobs:
                errors.append(f"missing {producer}")
        if any(producer not in jobs for producer in (oss, enterprise, replay, aggregate)):
            continue

        if set(jobs[oss]["strategy"]["matrix"]["shard"]) != SHARDS:
            errors.append(f"{oss} does not preserve the shard set")
        if set(jobs[enterprise]["strategy"]["matrix"]["shard"]) != SHARDS:
            errors.append(f"{enterprise} does not preserve the shard set")

        aggregate_needs = set(jobs[aggregate].get("needs", []))
        if minor == "126":
            # Pull requests wait on the no-race lane; the race producers prove
            # the same tests on main and roll up into race (1.26) instead.
            expected = {
                "security-scan", "changed-files", UNIT_PRODUCER,
                "test-subprocess-coverage", "guard-conformance", replay,
            }
        else:
            expected = {"security-scan", oss, enterprise, replay, "changed-files"}
        if aggregate_needs != expected:
            errors.append(f"{aggregate} needs {sorted(aggregate_needs)}, expected {sorted(expected)}")
        opposite = "127" if minor == "126" else "126"
        if any(f"go{opposite}" in dependency for dependency in aggregate_needs):
            errors.append(f"{aggregate} consumes Go {opposite} evidence")
        if jobs[aggregate].get("name") != f"test (1.{minor[1:]})":
            errors.append(f"{aggregate} changed its required display name")
        if jobs[aggregate].get("if") != ALWAYS_CONDITION:
            errors.append(f"{aggregate} is skipped instead of failing when a dependency fails")

        replay_needs = set(jobs[replay].get("needs", []))
        if replay_needs != {"security-scan"}:
            errors.append(f"{replay} can execute PR code before a successful security scan")
        replay_steps = jobs[replay].get("steps", [])
        if sum(step.get("run") == "make test-replay-harness" for step in replay_steps) != 1:
            errors.append(f"{replay} is not a singleton replay producer")
        setup_steps = [step for step in replay_steps if step.get("name") == "Set up Go"]
        if len(setup_steps) != 1 or setup_steps[0].get("with", {}).get("go-version") != f"1.{minor[1:]}":
            errors.append(f"{replay} does not run replay under Go 1.{minor[1:]}")
        aggregate_steps = jobs[aggregate].get("steps", [])
        if any("uses" in step or step.get("run") == "make test-replay-harness" for step in aggregate_steps):
            errors.append(f"{aggregate} still executes replay after matrix completion")
        gate_steps = [
            step for step in aggregate_steps if step.get("name") == "Required check compatibility gate"
        ]
        if len(gate_steps) != 1:
            errors.append(f"{aggregate} does not have exactly one compatibility gate")
        elif not step_runs_unconditionally(gate_steps[0]):
            errors.append(f"{aggregate} compatibility gate can skip and green after failed evidence")
        # `needs` is inert under `if: always()`.  Execute the gate with every
        # producer state instead of treating a matching shell substring as proof
        # that the runner's bash control flow will return failure.
        if minor == "127" and len(gate_steps) == 1:
            if gate_steps[0].get("env", {}).get("EVENT_NAME") != "${{ github.event_name }}":
                errors.append(f"{aggregate} does not bind the actual event name")
        gate_run = gate_steps[0].get("run", "") if len(gate_steps) == 1 else ""
        errors.extend(gate_execution_errors(aggregate, gate_run, expected))
        for producer in (oss, enterprise):
            if any(step.get("run") == "make test-replay-harness" for step in jobs[producer].get("steps", [])):
                errors.append(f"{producer} runs replay inside every shard")

    errors.extend(skip_carveout_errors(jobs))
    errors.extend(race_lane_errors(jobs))
    errors.extend(unit_lane_errors(jobs))

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
            "test (1.26)",
            "test (1.27)",
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

    def test_failed_policy_detection_cannot_green_skipped_race_producers(self):
        gate = self.jobs["test-go127"]["steps"][0]["run"]
        results = dict.fromkeys(self.jobs["test-go127"]["needs"], "success")
        results.update(dict.fromkeys(SKIP_CARVEOUT_PRODUCERS, "skipped"))
        for result in ("failure", "cancelled", "skipped", "", "unknown"):
            with self.subTest(result=result):
                self.assertNotEqual(execute_gate(
                    gate, results | {"changed-files": result}, "pull_request"), 0)
        self.assertEqual(execute_gate(gate, results, "pull_request", "false"), 0)
        for policy in ("true", "", "unknown", "TRUE"):
            with self.subTest(policy=policy):
                self.assertNotEqual(execute_gate(gate, results, "pull_request", policy), 0)
        self.assertEqual(execute_gate(
            gate, results | {"changed-files": "skipped"}, "push", ""), 0)

    def test_missing_event_binding_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        broken["test-go127"]["steps"][0]["env"]["EVENT_NAME"] = "push"
        self.assertIn("test-go127 does not bind the actual event name", topology_errors(broken))

    def test_unparseable_workflow_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="pipelock-invalid-workflow-") as temp_dir:
            workflow = Path(temp_dir) / "ci.yaml"
            workflow.write_text("jobs: [", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "cannot parse CI workflow"):
                workflow_jobs(workflow)

    def test_escaped_quote_continuation_is_rejected(self):
        # Positive control first: the same line without the backslash is real
        # gate syntax and must stay accepted, so a FAIL below means the new
        # backslash rule fired and not that the grammar broke outright.
        self.assertTrue(gate_script_is_safe('echo "x"'))
        unsafe = 'echo "x\\"\n# "; /usr/bin/touch /tmp/pipelock-fence-probe'
        self.assertFalse(
            gate_script_is_safe(unsafe),
            "an escaped quote leaves bash inside a string, so the following line "
            "is content rather than the comment this validator skips",
        )
        with self.assertRaisesRegex(ValueError, "outside the safe execution subset"):
            execute_gate(unsafe, {}, "push")

    def test_unjustified_producer_skip_fails_the_contract(self):
        # Positive control: the real workflow justifies the carve-out today.
        self.assertEqual(skip_carveout_errors(self.jobs), [])
        broken = copy.deepcopy(self.jobs)
        original = broken["test-oss-go127"]["if"]
        broken["test-oss-go127"]["if"] = "${{ always() }}"
        self.assertNotEqual(original, broken["test-oss-go127"]["if"], "mutation did not change the fixture")
        errors = skip_carveout_errors(broken)
        self.assertEqual(len(errors), 1)
        self.assertIn("test-oss-go127", errors[0])
        self.assertIn("CI-policy path", errors[0])

    def test_pull_request_only_swallow_fails_the_contract(self):
        # A gate that reds every failure on a push and returns zero for the SAME
        # failure on a pull request, using only syntax the fence accepts: the
        # skip test compares two literals, so it is false on every event and the
        # `exit 1` becomes reachable only when the event is not a pull request.
        swallows_on_pull_request = """set -u
test "${{ needs.security-scan.result }}" = "success"
echo "test-oss-go127 result: ${{ needs.test-oss-go127.result }}"
if ! test "${{ needs.test-oss-go127.result }}" = "success"; then
  if [ "$EVENT_NAME" != "pull_request" ] || [ "skipped" != "skipped" ]; then
    exit 1
  fi
fi
echo "test-enterprise-go127 result: ${{ needs.test-enterprise-go127.result }}"
if ! test "${{ needs.test-enterprise-go127.result }}" = "success"; then
  if [ "$EVENT_NAME" != "pull_request" ] || [ "${{ needs.test-enterprise-go127.result }}" != "skipped" ]; then
    exit 1
  fi
fi
echo "test-replay-go127 result: ${{ needs.test-replay-go127.result }}"
test "${{ needs.test-replay-go127.result }}" = "success"
"""
        dependencies = set(self.jobs["test-go127"]["needs"])
        # Positive control: the gate the workflow actually ships passes.
        real_gate = next(
            step["run"]
            for step in self.jobs["test-go127"]["steps"]
            if step.get("name") == "Required check compatibility gate"
        )
        self.assertEqual(gate_execution_errors("test-go127", real_gate, dependencies), [])
        self.assertTrue(
            gate_script_is_safe(swallows_on_pull_request),
            "the fixture must pass the fence, or it proves nothing about event coverage",
        )
        self.assertEqual(
            execute_gate(swallows_on_pull_request, dict.fromkeys(dependencies, "success"), "push"),
            0,
            "the fixture must green a wholly successful run",
        )
        errors = gate_execution_errors("test-go127", swallows_on_pull_request, dependencies)
        self.assertTrue(
            any("test-oss-go127=failure on pull_request" in error for error in errors),
            f"a pull-request-only swallow went unreported: {errors}",
        )

    def test_broadened_skip_predicate_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        original = broken["test-oss-go127"]["if"]
        broadened = original.replace("}}", "&& github.event.action != 'opened' }}")
        self.assertNotEqual(original, broadened, "mutation did not change the fixture")
        self.assertIn(
            "needs.changed-files.outputs.ci_policy == 'true'",
            broadened,
            "the mutation must KEEP the approved words, or it does not test the substring weakness",
        )
        broken["test-oss-go127"]["if"] = broadened
        errors = skip_carveout_errors(broken)
        self.assertEqual(len(errors), 1)
        self.assertIn("test-oss-go127", errors[0])

    def test_race_lane_on_pull_requests_fails_the_contract(self):
        self.assertEqual(race_lane_errors(self.jobs), [])
        broken = copy.deepcopy(self.jobs)
        broken["test-oss-go126"].pop("if")
        errors = race_lane_errors(broken)
        self.assertEqual(len(errors), 1)
        self.assertIn("test-oss-go126 must run on every non-pull-request event", errors[0])

    def test_uncapped_race_lane_fails_the_contract(self):
        for producer, value in (
            ("test-enterprise-go126", None),
            ("test-enterprise-go126", 7),
            ("test-oss-go127", None),
            ("test-oss-go127", 5),
            ("test-oss-go126", 0),
            ("test-oss-go126", True),
        ):
            with self.subTest(producer=producer, value=value):
                broken = copy.deepcopy(self.jobs)
                if value is None:
                    broken[producer]["strategy"].pop("max-parallel")
                else:
                    broken[producer]["strategy"]["max-parallel"] = value
                errors = race_lane_errors(broken)
                self.assertEqual(len(errors), 1)
                self.assertIn(f"{producer} must cap max-parallel at {RACE_MAX_PARALLEL[producer]}", errors[0])

    def test_required_check_consuming_race_evidence_fails_the_contract(self):
        # A pull request never produces race evidence, so a required aggregate
        # that needs it would either stall or learn to accept skips.
        broken = copy.deepcopy(self.jobs)
        broken["test-go126"]["needs"].append("test-oss-go126")
        self.assertIn(
            "test-go126 consumes race-lane evidence that pull requests never produce",
            race_lane_errors(broken),
        )

    def test_race_rollup_that_accepts_skips_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        broken["race-go126"]["steps"][0]["run"] = 'set -u\ntest "${{ needs.security-scan.result }}" = "success"\n'
        errors = race_lane_errors(broken)
        self.assertIn("race-go126 gate passes with test-oss-go126=failure", errors)

    def test_unit_lane_shape_drift_fails_the_contract(self):
        self.assertEqual(unit_lane_errors(self.jobs), [])
        broken = copy.deepcopy(self.jobs)
        broken["test-unit-go126"]["strategy"]["matrix"]["variant"] = ["oss"]
        broken["test-unit-go126"]["strategy"]["matrix"]["shard"].remove("rest-3")
        broken["test-unit-go126"]["if"] = "${{ github.event_name == 'push' }}"
        errors = unit_lane_errors(broken)
        self.assertIn("test-unit-go126 must test both build variants", errors)
        self.assertIn("test-unit-go126 does not cover every package shard", errors)
        self.assertIn("test-unit-go126 must run on every event except a documentation-only pull request", errors)

    def test_docs_only_skip_requires_classifier_proof(self):
        gate = next(
            step["run"] for step in self.jobs["test-go126"]["steps"]
            if step.get("name") == "Required check compatibility gate"
        )
        dependencies = set(self.jobs["test-go126"]["needs"])
        self.assertEqual(gate_execution_errors("test-go126", gate, dependencies), [])
        # A gate that accepts a skipped fast lane without checking docs_only
        # would green a pull request whose Go tests never ran.
        lax = gate.replace('test "${{ needs.changed-files.outputs.docs_only }}" = "true"', 'echo "docs"')
        self.assertNotEqual(lax, gate, "mutation did not change the fixture")
        errors = gate_execution_errors("test-go126", lax, dependencies)
        self.assertTrue(
            any("docs_only='false'" in error for error in errors),
            f"a skip without the docs-only proof went unreported: {errors}",
        )

    def test_go127_failure_cannot_red_go126_aggregate(self):
        aggregate_needs = set(self.jobs["test-go126"]["needs"])
        self.assertFalse(
            any("go127" in dependency for dependency in aggregate_needs),
            "a Go 1.27-only failure must not reach test (1.26)",
        )

    def test_cross_minor_wiring_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        broken["test-go126"]["needs"].append("test-oss-go127")
        self.assertIn("test-go126 consumes Go 127 evidence", topology_errors(broken))

    def test_missing_replay_step_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        broken["test-replay-go127"]["steps"] = [
            step
            for step in broken["test-replay-go127"]["steps"]
            if step.get("run") != "make test-replay-harness"
        ]
        errors = topology_errors(broken)
        self.assertIn("test-replay-go127 is not a singleton replay producer", errors)

    def test_replay_inside_a_shard_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        broken["test-oss-go126"]["steps"].append(
            {"name": "Replay harness", "run": "make test-replay-harness"}
        )
        self.assertIn("test-oss-go126 runs replay inside every shard", topology_errors(broken))

    def test_unguarded_replay_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        del broken["test-replay-go127"]["needs"]
        self.assertIn(
            "test-replay-go127 can execute PR code before a successful security scan",
            topology_errors(broken),
        )

    def test_aggregate_without_always_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        del broken["test-go126"]["if"]
        self.assertIn(
            "test-go126 is skipped instead of failing when a dependency fails",
            topology_errors(broken),
        )

    def test_skip_gated_compatibility_gate_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        for step in broken["test-go127"]["steps"]:
            if step.get("name") == "Required check compatibility gate":
                step["if"] = SCAN_SUCCESS_CONDITION
        self.assertIn(
            "test-go127 compatibility gate can skip and green after failed evidence",
            topology_errors(broken),
        )

    def test_aggregate_gate_dropping_replay_result_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        gate = next(
            step
            for step in broken["test-go127"]["steps"]
            if step.get("name") == "Required check compatibility gate"
        )
        gate["run"] = "\n".join(
            line
            for line in gate["run"].splitlines()
            if "needs.test-replay-go127.result" not in line
        )
        self.assertTrue(
            any(
                "test-replay-go127=failure" in error
                for error in topology_errors(broken)
            )
        )

    def test_reintroduced_and_or_defect_is_detected_by_execution(self):
        """A #1592-shaped compound preserves literals but swallows a failure."""
        broken = copy.deepcopy(self.jobs)
        gate = next(
            step
            for step in broken["test-go127"]["steps"]
            if step.get("name") == "Required check compatibility gate"
        )
        gate["run"] = """\
test "${{ needs.security-scan.result }}" = "success"
test "${{ needs.test-oss-go127.result }}" = "success" || {
  [ "$EVENT_NAME" != "pull_request" ] &&
  [ "${{ needs.test-oss-go127.result }}" != "skipped" ]
}
test "${{ needs.test-enterprise-go127.result }}" = "success"
test "${{ needs.test-replay-go127.result }}" = "success"
"""
        gate_run = gate["run"]
        self.assertIn('test "${{ needs.test-oss-go127.result }}" = "success"', gate_run)
        self.assertEqual(
            execute_gate(
                gate_run,
                {
                    "security-scan": "success",
                    "test-oss-go127": "failure",
                    "test-enterprise-go127": "success",
                    "test-replay-go127": "success",
                },
                "push",
            ),
            0,
        )
        self.assertTrue(
            any("test-oss-go127=failure" in error for error in topology_errors(broken))
        )

    def test_execution_fence_refuses_shell_expansion(self):
        """The fence must reject expansion, not merely look like it does.

        Before this regression existed the grammar accepted
        `test "$(/usr/bin/touch FILE)" = "success"`: a command substitution
        carries no double quote, so it matched the `[^"]*` span inside an
        otherwise-legitimate gate line. It then EXECUTED and created the file,
        because an absolute path needs no PATH lookup and the harness's empty
        PATH stops nothing. A fence whose docstring claims to reject command
        substitution and absolute paths has to actually reject them.
        """
        for unsafe in (
            'test "$(whoami)" = "success"',
            'test "$(/usr/bin/touch /tmp/pipelock-fence-probe)" = "success"',
            'test "`whoami`" = "success"',
            'test "${HOME}" = "success"',
            'echo "$(id)"',
        ):
            with self.subTest(unsafe=unsafe):
                self.assertFalse(
                    gate_script_is_safe(unsafe),
                    f"fence accepted shell expansion: {unsafe}",
                )
                with self.assertRaises(ValueError):
                    execute_gate(unsafe, {}, "push")

        for safe in (
            'test "success" = "success"',
            '[ "$EVENT_NAME" = "pull_request" ] &&',
            'exit 1',
            'set -u',
        ):
            with self.subTest(safe=safe):
                self.assertTrue(gate_script_is_safe(safe), f"fence rejected a real gate line: {safe}")

    def test_skip_gated_summary_step_fails_the_contract(self):
        broken = copy.deepcopy(self.jobs)
        broken["pipelock-ci-summary"]["steps"][0]["if"] = SCAN_SUCCESS_CONDITION
        self.assertIn(
            "summary reporting step can skip and green after failed evidence",
            topology_errors(broken),
        )


if __name__ == "__main__":
    unittest.main()
