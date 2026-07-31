# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Adversarial tests for release and CI package sharding."""

from __future__ import annotations

import ast
import re
import unittest
from fnmatch import fnmatchcase
from pathlib import Path

from scripts.ci_test_packages import SHARDS, package_in_tree, package_suffix, select_packages


def _defines_unittest_testcase(path: Path) -> bool:
    """Report whether a module defines a unittest.TestCase subclass.

    Parses rather than imports, so surveying the tree cannot execute module-level
    code, and so a module that fails to import is still counted rather than
    silently dropped from the inventory.

    Deliberately errs toward INCLUDING a module. The two mistakes are not
    symmetric: over-including a non-test module fails this guard loudly with a
    message a human resolves in seconds, while under-including a real test module
    silently restores the bug the guard exists to catch. That is why the search
    walks the whole tree rather than only module-level classes: a TestCase
    subclass declared inside a module-level `if` is still collected by unittest
    at import time, but it does not appear in `tree.body`.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError):
        # Unreadable or unparseable: assume it may hold tests rather than
        # quietly shrinking the inventory this guard is built from.
        return True

    # Resolve how this module refers to unittest.TestCase, so an unrelated class
    # that merely happens to be named TestCase is not mistaken for one.
    testcase_names = set()
    unittest_names = {"unittest"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "unittest":
            for alias in node.names:
                if alias.name == "TestCase":
                    testcase_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "unittest":
                    unittest_names.add(alias.asname or alias.name)

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for base in node.bases:
            # `unittest.TestCase`, including an aliased `import unittest as ut`.
            if isinstance(base, ast.Attribute) and base.attr == "TestCase":
                value = base.value
                if isinstance(value, ast.Name) and value.id in unittest_names:
                    return True
            # A bare `TestCase` that this module actually imported from unittest.
            if isinstance(base, ast.Name) and base.id in testcase_names:
                return True
    return False


class TestPackageSharding(unittest.TestCase):
    def test_release_cosign_matches_goreleaser_signature_format(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/release.yaml").read_text(encoding="utf-8")
        goreleaser = (root / ".goreleaser.yaml").read_text(encoding="utf-8")

        version_match = re.search(r"^\s*cosign-release:\s*['\"]v(\d+)\.", workflow, re.MULTILINE)
        self.assertIsNotNone(version_match, "release workflow cosign version not found")

        uses_legacy_outputs = (
            "--output-certificate=" in goreleaser and "--output-signature=" in goreleaser
        )
        if uses_legacy_outputs:
            self.assertLess(
                int(version_match.group(1)),
                3,
                "Cosign v3 requires bundle output; legacy .sig/.pem flags fail during release",
            )

    def test_release_workflow_uses_every_supported_shard(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/release.yaml").read_text(
            encoding="utf-8",
        )

        matrix_match = re.search(r"^\s*shard:\s*\[([^\]]+)\]\s*$", workflow, re.MULTILINE)
        self.assertIsNotNone(matrix_match, "release workflow shard matrix not found")
        matrix_shards = tuple(
            value.strip().strip("'\"") for value in matrix_match.group(1).split(",")
        )

        loop_match = re.search(r"^\s*for shard in ([^;]+); do\s*$", workflow, re.MULTILINE)
        self.assertIsNotNone(loop_match, "release workflow coverage loop not found")
        loop_shards = tuple(loop_match.group(1).split())

        self.assertEqual(matrix_shards, SHARDS)
        self.assertEqual(loop_shards, SHARDS)

    def test_pr_ci_runs_all_script_unittests(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/ci.yaml").read_text(encoding="utf-8")

        command = "python3 -m unittest discover -s scripts -p '*test*.py'"
        self.assertIn(command, workflow)

        # Build the inventory of real test modules INDEPENDENTLY of the naming
        # convention, by asking which files actually define a unittest.TestCase.
        # Deriving the inventory from a name filter makes the assertion vacuous:
        # every name matching `startswith("test")` or `endswith("_test.py")`
        # necessarily contains "test", so it always matches the CI pattern and
        # the check can never fail. A module named `TestHelpers.py` or
        # `helpers_check.py` is the case that actually matters, and a
        # name-derived inventory cannot see it.
        defines_tests = sorted(
            path.name
            for path in (root / "scripts").rglob("*.py")
            if _defines_unittest_testcase(path)
        )
        self.assertTrue(
            defines_tests,
            "found no unittest.TestCase modules under scripts/, so this guard is inert",
        )
        missed = [name for name in defines_tests if not fnmatchcase(name, "*test*.py")]
        self.assertEqual(
            missed,
            [],
            "these modules define tests that CI discovery would never collect: "
            f"{missed}. Either rename them to match '*test*.py' or widen the "
            "discovery pattern in the CI lint job.",
        )

    def test_every_package_is_selected_exactly_once(self) -> None:
        packages = [
            "example.test/pipelock/cmd/pipelock",
            "example.test/pipelock/internal/proxy",
            "example.test/pipelock/internal/proxy/cache",
            "example.test/pipelock/internal/scanner",
            "example.test/pipelock/internal/mcp/http",
            "example.test/pipelock/internal/config",
            "example.test/pipelock/enterprise/dashboard",
        ]

        selected = [
            package
            for shard in ("proxy", "scanner", "mcp", "rest-0", "rest-1", "rest-2")
            for package in select_packages(packages, shard)
        ]

        self.assertCountEqual(selected, packages)
        self.assertEqual(len(selected), len(set(selected)))

    def test_rest_shards_are_deterministic_and_balanced(self) -> None:
        packages = [
            "example.test/pipelock/internal/zeta",
            "example.test/pipelock/internal/proxy",
            "example.test/pipelock/internal/alpha",
            "example.test/pipelock/internal/scanner",
            "example.test/pipelock/internal/mcp",
            "example.test/pipelock/internal/beta",
            "example.test/pipelock/internal/delta",
            "example.test/pipelock/internal/gamma",
        ]

        rest_shards = [
            select_packages(packages, "rest-0"),
            select_packages(packages, "rest-1"),
            select_packages(packages, "rest-2"),
        ]

        self.assertEqual(
            rest_shards,
            [
                [
                    "example.test/pipelock/internal/alpha",
                    "example.test/pipelock/internal/gamma",
                ],
                [
                    "example.test/pipelock/internal/beta",
                    "example.test/pipelock/internal/zeta",
                ],
                ["example.test/pipelock/internal/delta"],
            ],
        )
        self.assertLessEqual(
            max(len(shard) for shard in rest_shards) - min(len(shard) for shard in rest_shards),
            1,
        )

    def test_nested_internal_directory_cannot_impersonate_heavy_shard(self) -> None:
        package = "example.test/pipelock/internal/config/internal/proxy"
        self.assertEqual(package_suffix(package), "internal/config/internal/proxy")
        self.assertFalse(package_in_tree(package, "internal/proxy"))
        selected = [
            selected_package
            for shard in ("rest-0", "rest-1", "rest-2")
            for selected_package in select_packages([package], shard)
        ]
        self.assertEqual(selected, [package])

    def test_prefix_collision_is_not_a_tree_match(self) -> None:
        package = "example.test/pipelock/internal/proxying"
        self.assertFalse(package_in_tree(package, "internal/proxy"))
        selected = [
            selected_package
            for shard in ("rest-0", "rest-1", "rest-2")
            for selected_package in select_packages([package], shard)
        ]
        self.assertEqual(selected, [package])

    def test_empty_heavy_shard_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "no packages matched shard"):
            select_packages(["example.test/pipelock/internal/config"], "proxy")


if __name__ == "__main__":
    unittest.main()
