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
    except (OSError, SyntaxError, UnicodeError, ValueError):
        # Unreadable, undecodable, or unparseable: assume it may hold tests
        # rather than quietly shrinking the inventory this guard is built from.
        # UnicodeError matters because read_text raises it BEFORE ast.parse ever
        # runs, so a file that is not valid UTF-8 would otherwise abort the whole
        # CI check rather than fall back.
        return True

    # Resolve how this module refers to unittest.TestCase, so a class that merely
    # happens to be named TestCase, or a module that binds the name `unittest` to
    # something unrelated, is not mistaken for the standard library.
    testcase_names: set[str] = set()
    unittest_names: set[str] = set()
    for node in ast.walk(tree):
        # `node.level == 0` means an absolute import. `ImportFrom.module` is
        # "unittest" for both `from unittest import ...` and the relative
        # `from .unittest import ...`, so without the level check a package with
        # its own local unittest module would be read as importing the standard
        # library and could fail this guard for an unrelated reason.
        if isinstance(node, ast.ImportFrom) and node.module == "unittest" and node.level == 0:
            for alias in node.names:
                if alias.name == "TestCase":
                    testcase_names.add(alias.asname or alias.name)
                elif alias.name == "*":
                    # `from unittest import *` yields a single alias named "*",
                    # so which names it binds cannot be resolved statically. It
                    # may well bind TestCase. Include the module rather than let
                    # an unresolvable import silently drop a real test file,
                    # which is the exact under-inclusion this guard exists to
                    # prevent.
                    return True
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "unittest":
                    unittest_names.add(alias.asname or "unittest")
                elif alias.name.startswith("unittest.") and alias.asname is None:
                    # `import unittest.mock` also binds the name `unittest`.
                    unittest_names.add("unittest")

    def class_defs_in_module_scope(body: list[ast.stmt]):
        """Yield classes reachable in the module namespace at import time.

        Descends through module-level control flow, because a class declared
        inside `if`/`try`/`with` at module level IS bound in the module namespace
        and IS collected by unittest. Does NOT descend into class or function
        bodies, because a class nested there is not a module-level test case and
        counting it would put non-test helpers in the inventory.
        """
        for node in body:
            if isinstance(node, ast.ClassDef):
                yield node
            elif isinstance(node, (ast.If, ast.Try, ast.With, ast.For, ast.While)):
                yield from class_defs_in_module_scope(node.body)
                yield from class_defs_in_module_scope(getattr(node, "orelse", []))
                yield from class_defs_in_module_scope(getattr(node, "finalbody", []))
                for handler in getattr(node, "handlers", []):
                    yield from class_defs_in_module_scope(handler.body)

    for node in class_defs_in_module_scope(tree.body):
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

        version_match = re.search(r"^\s*COSIGN_VERSION:\s*v(\d+)\.", workflow, re.MULTILINE)
        self.assertIsNotNone(version_match, "release workflow COSIGN_VERSION not found")

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
