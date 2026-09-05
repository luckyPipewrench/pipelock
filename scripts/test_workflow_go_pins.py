"""Every exact Go toolchain pin agrees with the assertion that guards it.

A workflow that pins an exact Go version usually pairs it with a step asserting
`go env GOVERSION` equals that version, so setup-go resolving a different stdlib
fails loudly instead of scanning or shipping the wrong toolchain. The pair only
works while both halves move together.

They did not, on 2026-09-05: a bump moved four `go-version:` pins in
release.yaml from 1.25.12 to 1.25.14 and left three `go1.25.12` assertions
behind, because the pins are quoted as `'1.25.12'` and the assertions are
written as `go1.25.12`, so a single search-and-replace matched one form and not
the other. Every release job would have installed the new toolchain and then
failed its own check, which breaks publishing rather than merely scanning the
wrong thing.

Floating pins such as '1.25' are deliberately excluded: they carry no exact
version to agree with, and a workflow may legitimately mix a float for ordinary
build jobs with one exact pin for a job that needs a known stdlib.
"""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"

# `go-version: '1.25.14'` / `go-version: "1.25.14"` — exact pins only, so a
# bare `1.25` float is not treated as a version to reconcile.
PIN_RE = re.compile(r"""go-version:\s*['"](\d+\.\d+\.\d+)['"]""")

# `test "$got" = "go1.25.14"` and the inline `test "$(go env GOVERSION)" = ...`
# form. Anchored on the equality so prose mentioning a version in a comment is
# not mistaken for an assertion.
ASSERT_RE = re.compile(r"""=\s*['"]go(\d+\.\d+\.\d+)['"]""")


def _strip_comments(text: str) -> str:
    kept = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        kept.append(line)
    return "\n".join(kept)


class WorkflowGoPinTest(unittest.TestCase):
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
                pins,
                "%s asserts a Go version but pins none exactly" % path.name,
            )
            self.assertEqual(
                asserts,
                pins,
                "%s pins %s but asserts %s; a half-done bump makes every job "
                "install one toolchain and then fail its own check"
                % (path.name, sorted(pins), sorted(asserts)),
            )
        self.assertGreater(
            checked,
            0,
            "no workflow asserted a Go version, so this guard checked nothing",
        )


if __name__ == "__main__":
    unittest.main()
