"""Every exact Go toolchain pin agrees with everything that asserts it.

A workflow that pins an exact Go version usually pairs it with a step asserting
`go env GOVERSION` equals that version, so setup-go resolving a different stdlib
fails loudly instead of scanning or shipping the wrong toolchain. Some workflows
are additionally pinned from the outside, by a Python contract test asserting the
workflow's literal text. All of those copies only work while they move together.

They did not, on 2026-09-05, and they failed in two different ways from one bump.
Moving four `go-version:` pins in release.yaml from 1.25.12 to 1.25.14 left three
`go1.25.12` assertions behind, because the pins are quoted as `'1.25.12'` while
the assertions are written `go1.25.12`, so one search-and-replace matched a single
spelling. Every release job would have installed the new toolchain and then failed
its own check, which breaks publishing rather than merely scanning the wrong
thing. The same bump moved the gauntlet workflow's pin and left
`scripts/test_gauntlet_candidate_workflow.py` asserting the old literal, which
was found only by an independent review pass.

Both halves are covered here: assertions inside a workflow, and version literals
asserted from a script. Floating pins such as '1.25' are deliberately excluded,
since they carry no exact version to reconcile and a workflow may legitimately
mix a float for ordinary build jobs with one exact pin for a job that needs a
known stdlib.
"""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
SCRIPT_DIR = ROOT / "scripts"

# `go-version: '1.25.14'` / `go-version: "1.25.14"` — exact pins only, so a bare
# `1.25` float is not treated as a version to reconcile.
PIN_RE = re.compile(r"""go-version:\s*['"](\d+\.\d+\.\d+)['"]""")

# `test "$got" = "go1.25.14"` and the inline `test "$(go env GOVERSION)" = ...`
# form. Anchored on the equality so prose mentioning a version in a comment is
# not mistaken for an assertion.
ASSERT_RE = re.compile(r"""=\s*['"]go(\d+\.\d+\.\d+)['"]""")


def _strip_comments(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


class WorkflowGoPinTest(unittest.TestCase):
    def _workflow_pins(self) -> set[str]:
        pins: set[str] = set()
        for path in sorted(WORKFLOW_DIR.glob("*.y*ml")):
            pins |= set(PIN_RE.findall(_strip_comments(path.read_text(encoding="utf-8"))))
        return pins

    def test_exact_pins_and_version_assertions_agree(self) -> None:
        checked = 0
        for path in sorted(WORKFLOW_DIR.glob("*.y*ml")):
            body = _strip_comments(path.read_text(encoding="utf-8"))
            pins = set(PIN_RE.findall(body))
            asserts = set(ASSERT_RE.findall(body))
            if not asserts:
                continue
            checked += 1
            self.assertTrue(
                pins, "%s asserts a Go version but pins none exactly" % path.name
            )
            self.assertEqual(
                asserts,
                pins,
                "%s pins %s but asserts %s; a half-done bump makes every job "
                "install one toolchain and then fail its own check"
                % (path.name, sorted(pins), sorted(asserts)),
            )
        self.assertGreater(
            checked, 0, "no workflow asserted a Go version, so this guard checked nothing"
        )

    def test_scripts_do_not_pin_a_go_version_no_workflow_uses(self) -> None:
        workflow_pins = self._workflow_pins()
        self.assertTrue(workflow_pins, "no workflow pins an exact Go version")
        checked = 0
        for path in sorted(SCRIPT_DIR.glob("*.py")):
            if path.name == pathlib.Path(__file__).name:
                # This file documents the literal form it matches; excluding it
                # keeps the guard from asserting against its own prose.
                continue
            for version in set(PIN_RE.findall(path.read_text(encoding="utf-8"))):
                checked += 1
                self.assertIn(
                    version,
                    workflow_pins,
                    "%s asserts Go %s, which no workflow pins; a contract test "
                    "left behind by a toolchain bump fails CI without naming the "
                    "bump that stranded it" % (path.name, version),
                )
        self.assertGreater(
            checked,
            0,
            "no script asserted a workflow Go pin, so this guard checked nothing",
        )


if __name__ == "__main__":
    unittest.main()
