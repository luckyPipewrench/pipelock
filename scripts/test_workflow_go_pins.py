#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Every exact Go toolchain pin agrees with the assertion that guards it.

A workflow job that pins an exact Go version pairs it with a step asserting
`go env GOVERSION` equals that version, so setup-go resolving a different stdlib
fails loudly instead of scanning or shipping the wrong toolchain. Some workflows
are additionally pinned from the outside, by a Python contract test asserting the
workflow's literal text. Every one of those copies only works while they move
together.

They did not, on 2026-09-05, and one bump broke them two different ways. Moving
four `go-version:` pins in release.yaml from 1.25.12 to 1.25.14 left three
`go1.25.12` assertions behind, because the pins are quoted `'1.25.12'` while the
assertions are written `go1.25.12`, so one search-and-replace matched a single
spelling. Every release job would have installed the new toolchain and then failed
its own check, which breaks publishing rather than merely scanning the wrong thing.
The same bump moved the gauntlet workflow's pin and stranded
`scripts/test_gauntlet_candidate_workflow.py` on the old literal.

The first version of this guard compared whole-file SETS, and review caught that
this made it vacuous for the case it was written for: with four pins and four
assertions all reading 1.25.14, deleting three assertions leaves both sets equal
to {"1.25.14"} and the guard passes. Reproduced before rewriting. Scoping is
therefore per job, and comparison is by multiset, so a removed assertion and an
assertion swapped between jobs both fail. Script assertions are scoped to the
workflow each script names, so a version pinned only by some unrelated workflow
cannot satisfy them.

Review then found a third hole in the same shape: the assertion pattern matched
any `= "goX.Y.Z"` text anywhere in a `run` block, including a commented-out line,
so commenting out the live check while leaving its text behind still satisfied the
guard. Reproduced before fixing. Assertions are now collected only from lines that
are not shell comments, and only from a block that actually runs `go env GOVERSION`,
so dead text cannot stand in for a live check.

The bound worth knowing: only whole-line shell comments are stripped. A version
equality hidden in a trailing inline comment after live code would still be
counted, and closing that needs a shell parser rather than a line filter. The
`go env GOVERSION` requirement is the second line of defense there.

Floating pins such as '1.25' are deliberately excluded: they carry no exact
version to reconcile, and a workflow may legitimately mix a float for ordinary
build jobs with one exact pin for a job that needs a known stdlib.
"""

from __future__ import annotations

import collections
import pathlib
import re
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
SCRIPT_DIR = ROOT / "scripts"

EXACT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
# `go-version: '1.25.14'` inside a script's own assertion about workflow text.
SCRIPT_PIN_RE = re.compile(r"""go-version:\s*['"](\d+\.\d+\.\d+)['"]""")
# `test "$got" = "go1.25.14"` and the inline `test "$(go env GOVERSION)" = ...`.
ASSERT_RE = re.compile(r"""=\s*['"]go(\d+\.\d+\.\d+)['"]""")


def _jobs(workflow: pathlib.Path):
    """Yield (job_name, steps) for every job with a step list."""
    try:
        doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    except yaml.YAMLError:  # a malformed workflow is another gate's problem
        return
    if not isinstance(doc, dict):
        return
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return
    for name, job in jobs.items():
        if isinstance(job, dict) and isinstance(job.get("steps"), list):
            yield name, job["steps"]


def _live_asserted_versions(run: str) -> list[str]:
    """Versions checked by a live `go env GOVERSION` comparison in this run block.

    Commented-out lines are dropped, so text left behind after a check is deleted
    cannot stand in for the check. The block must also actually read
    `go env GOVERSION`, so an unrelated equality on a version-shaped string is not
    mistaken for a toolchain assertion.
    """
    live = "\n".join(
        line for line in run.splitlines() if not line.strip().startswith("#")
    )
    if "go env GOVERSION" not in live:
        return []
    return ASSERT_RE.findall(live)


def _job_pins_and_asserts(steps) -> tuple[list[str], list[str]]:
    """Exact Go pins and live version assertions declared by one job's steps."""
    pins: list[str] = []
    asserts: list[str] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        with_block = step.get("with")
        if isinstance(with_block, dict):
            version = str(with_block.get("go-version", "")).strip()
            if EXACT_VERSION_RE.match(version):
                pins.append(version)
        run = step.get("run")
        if isinstance(run, str):
            asserts.extend(_live_asserted_versions(run))
    return pins, asserts


class WorkflowGoPinTest(unittest.TestCase):
    def test_each_job_asserts_the_exact_go_version_it_pins(self) -> None:
        checked = 0
        for path in sorted(WORKFLOW_DIR.glob("*.y*ml")):
            for job_name, steps in _jobs(path):
                pins, asserts = _job_pins_and_asserts(steps)
                if not pins and not asserts:
                    continue
                checked += 1
                self.assertEqual(
                    collections.Counter(asserts),
                    collections.Counter(pins),
                    f"{path.name} job {job_name!r} pins {sorted(pins)} but asserts "
                    f"{sorted(asserts)}; a job that installs one toolchain and checks "
                    "for another fails after setup, and a missing assertion leaves a "
                    "wrong stdlib unnoticed",
                )
        self.assertGreater(
            checked, 0, "no workflow job pinned or asserted a Go version"
        )

    def test_script_pins_match_the_workflow_each_script_names(self) -> None:
        workflow_names = {p.name for p in WORKFLOW_DIR.glob("*.y*ml")}
        checked = 0
        for path in sorted(SCRIPT_DIR.glob("*.py")):
            if path.name == pathlib.Path(__file__).name:
                # This file documents the literal forms it matches; excluding it
                # keeps the guard from asserting against its own prose.
                continue
            body = path.read_text(encoding="utf-8")
            versions = set(SCRIPT_PIN_RE.findall(body))
            if not versions:
                continue
            named = sorted(n for n in workflow_names if n in body)
            self.assertTrue(
                named,
                f"{path.name} asserts a Go version but names no workflow, so the "
                "assertion cannot be scoped to what it is meant to guard",
            )
            owning_pins: set[str] = set()
            for name in named:
                for _job, steps in _jobs(WORKFLOW_DIR / name):
                    owning_pins.update(_job_pins_and_asserts(steps)[0])
            for version in sorted(versions):
                checked += 1
                self.assertIn(
                    version,
                    owning_pins,
                    f"{path.name} asserts Go {version}, which {', '.join(named)} does "
                    "not pin; a contract test left behind by a toolchain bump fails CI "
                    "without naming the bump that stranded it",
                )
        self.assertGreater(
            checked, 0, "no script asserted a workflow Go pin"
        )


    def test_a_commented_out_assertion_does_not_count_as_a_check(self) -> None:
        """Dead text must not satisfy the guard that live text satisfies.

        This is the defect the guard shipped with: the pattern matched any
        `= "goX.Y.Z"` anywhere in a run block, so commenting out the check while
        leaving its text behind still passed.
        """
        live = 'got="$(go env GOVERSION)"\ntest "$got" = "go1.25.14"\n'
        self.assertEqual(_live_asserted_versions(live), ["1.25.14"])

        commented = 'got="$(go env GOVERSION)"\n# test "$got" = "go1.25.14"\n'
        self.assertEqual(
            _live_asserted_versions(commented),
            [],
            "a commented-out assertion was counted as a live check",
        )

        unrelated = 'test "$SOME_OTHER" = "go1.25.14"\n'
        self.assertEqual(
            _live_asserted_versions(unrelated),
            [],
            "an equality unrelated to go env GOVERSION was counted as a toolchain check",
        )


if __name__ == "__main__":
    unittest.main()
