# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Adversarial tests for release and CI package sharding."""

from __future__ import annotations

import ast
import io
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from fnmatch import fnmatchcase
from pathlib import Path
from unittest.mock import patch

import os
import subprocess
import sys

from scripts import ci_test_packages
from scripts.ci_test_packages import (
    HEAVY_TREES,
    PACKAGE_SHARDS,
    SEPARATE_COVERAGE_TREES,
    SHARD_BUDGET_SECONDS,
    SHARDS,
    TEST_SPLITS,
    coverage_mode,
    exact_names_regex,
    predicted_loads,
    load_durations,
    load_package_durations,
    name_bucket,
    package_in_tree,
    partition_names,
    package_suffix,
    partition_errors,
    select_packages,
    selector_selects,
    shard_selector,
    tree_test_names,
)


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
        self.assertEqual(loop_shards, PACKAGE_SHARDS)

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
            "example.test/pipelock/internal/cli/runtime",
            "example.test/pipelock/internal/config",
            "example.test/pipelock/enterprise/dashboard",
        ]

        selected = [
            package
            for shard in PACKAGE_SHARDS
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

    def test_weighted_rest_shards_balance_time_and_cover_every_package_once(self) -> None:
        packages = [f"example.test/pipelock/internal/p{index}" for index in range(12)] + [
            "example.test/pipelock/internal/proxy",
            "example.test/pipelock/internal/scanner",
        ]
        weights = {"example.test/pipelock/internal/p0": 300.0, "example.test/pipelock/internal/p1": 290.0}
        weights.update({f"example.test/pipelock/internal/p{index}": 10.0 for index in range(2, 12)})
        shards = [select_packages(packages, shard, weights) for shard in ("rest-0", "rest-1", "rest-2")]
        rest = [pkg for pkg in packages if pkg in weights]
        self.assertCountEqual([pkg for shard in shards for pkg in shard], rest)
        self.assertFalse(any("p0" in pkg for pkg in shards[0]) and any("p1" in pkg for pkg in shards[0]))
        loads = [sum(weights[pkg] for pkg in shard) for shard in shards]
        self.assertLessEqual(max(loads) - min(loads), 300.0)
        self.assertTrue(all(shards), shards)

    def test_coverage_mode_is_separate_only_for_listed_trees(self) -> None:
        self.assertEqual(SEPARATE_COVERAGE_TREES, frozenset({"scanner"}))
        for shard in SHARDS:
            with self.subTest(shard=shard):
                expected = "separate" if shard.startswith("scanner-") else "race"
                self.assertEqual(coverage_mode(shard), expected)
        with self.assertRaisesRegex(ValueError, "unknown shard"):
            coverage_mode("scanner")

    def test_predicted_loads_cover_every_shard_and_fail_over_budget(self) -> None:
        packages = [
            "example.test/pipelock/internal/proxy",
            "example.test/pipelock/internal/scanner",
            "example.test/pipelock/internal/mcp",
            "example.test/pipelock/internal/cli/runtime",
            "example.test/pipelock/internal/a",
            "example.test/pipelock/internal/b",
            "example.test/pipelock/internal/c",
        ]
        trees = {tree: {f"Test{tree}{index}": 10.0 for index in range(20)} for tree in TEST_SPLITS}
        with patch.object(ci_test_packages, "list_packages", return_value=packages), \
             patch.object(ci_test_packages, "load_durations", return_value=trees), \
             patch.object(ci_test_packages, "load_package_durations", return_value={pkg: 100.0 for pkg in packages}), \
             patch.object(ci_test_packages, "tree_test_names", side_effect=lambda root: list(next(
                 tests for tree, tests in trees.items() if str(root).endswith(HEAVY_TREES[tree])))):
            loads = predicted_loads("")
            self.assertEqual(set(loads), set(SHARDS))
            # 20 tests of 10s: every second is charged once and buckets differ by
            # at most one test; a separate-coverage tree also pays its coverage
            # pass. Rest packages run two at a time.
            for tree, count in TEST_SPLITS.items():
                factor = 1.0 + (ci_test_packages.COVERAGE_PASS_FRACTION if tree in SEPARATE_COVERAGE_TREES else 0.0)
                tree_loads = [loads[f"{tree}-{index}"] for index in range(count)]
                self.assertAlmostEqual(sum(tree_loads), 200.0 * factor)
                self.assertLessEqual(max(tree_loads) - min(tree_loads), 10.0 * factor)
            self.assertEqual(sorted(loads[shard] for shard in ("rest-0", "rest-1", "rest-2")), [100.0, 100.0, 100.0])
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
                self.assertEqual(ci_test_packages.check_budget("", SHARD_BUDGET_SECONDS), 0)
                self.assertEqual(ci_test_packages.check_budget("", 40.0), 1)
                # A non-finite or non-positive budget would pass every shard.
                for bad in (float("nan"), float("inf"), 0.0, -1.0):
                    self.assertEqual(ci_test_packages.check_budget("", bad), 2, bad)
            self.assertIn("over the 40s budget", err.getvalue())
            self.assertIn("positive finite", err.getvalue())

    def test_unmeasured_tests_are_never_free_even_when_the_median_is_zero(self) -> None:
        trees = {tree: {f"Test{tree}{index}": 0.0 for index in range(20)} for tree in TEST_SPLITS}
        unmeasured = {tree: list(tests) + [f"TestNew{tree}{index}" for index in range(8)] for tree, tests in trees.items()}
        with patch.object(ci_test_packages, "list_packages", return_value=[]), \
             patch.object(ci_test_packages, "load_durations", return_value=trees), \
             patch.object(ci_test_packages, "load_package_durations", return_value={}), \
             patch.object(ci_test_packages, "tree_test_names", side_effect=lambda root: next(
                 names for tree, names in unmeasured.items() if str(root).endswith(HEAVY_TREES[tree]))):
            loads = predicted_loads("")
            for tree, count in TEST_SPLITS.items():
                total = sum(loads[f"{tree}-{index}"] for index in range(count))
                self.assertGreater(total, 0.0, f"{tree}: eight unmeasured tests predicted free")

    def test_rest_budget_cannot_divide_a_single_slow_package(self) -> None:
        with patch.object(ci_test_packages, "list_packages", return_value=["example.test/slow"]), \
             patch.object(ci_test_packages, "load_durations", return_value={}), \
             patch.object(ci_test_packages, "load_package_durations", return_value={"example.test/slow": 700.0}), \
             patch.object(ci_test_packages, "tree_test_names", return_value=["TestA"]):
            self.assertEqual(predicted_loads("")["rest-0"], 700.0)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(ci_test_packages.check_budget("", SHARD_BUDGET_SECONDS), 1)

    def test_rest_budget_counts_every_wave_of_whole_packages(self) -> None:
        self.assertEqual(ci_test_packages.package_makespan([350.0, 350.0, 350.0], 2), 700.0)
        self.assertEqual(ci_test_packages.package_makespan([100.0, 100.0, 100.0], 2), 200.0)
        self.assertEqual(ci_test_packages.package_makespan([700.0], 2), 700.0)
        self.assertEqual(ci_test_packages.package_makespan([], 2), 0.0)
        packages = [f"example.test/p{index}" for index in range(3)]
        with patch.object(ci_test_packages, "list_packages", return_value=packages), \
             patch.object(ci_test_packages, "load_durations", return_value={}), \
             patch.object(ci_test_packages, "load_package_durations", return_value=dict.fromkeys(packages, 350.0)), \
             patch.object(ci_test_packages, "select_packages", return_value=packages), \
             patch.object(ci_test_packages, "tree_test_names", return_value=["TestA"]):
            # Three 350s packages fit the budget by total/2 (525s) but not in two waves.
            self.assertEqual(predicted_loads("")["rest-0"], 700.0)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(ci_test_packages.check_budget("", SHARD_BUDGET_SECONDS), 1)

    def test_unmeasured_rest_packages_are_never_free(self) -> None:
        measured = {"example.test/a": 0.0, "example.test/b": 0.0}
        packages = [*measured, "example.test/new"]
        with patch.object(ci_test_packages, "list_packages", return_value=packages), \
             patch.object(ci_test_packages, "load_durations", return_value={}), \
             patch.object(ci_test_packages, "load_package_durations", return_value=measured), \
             patch.object(ci_test_packages, "select_packages", return_value=packages), \
             patch.object(ci_test_packages, "tree_test_names", return_value=["TestA"]):
            self.assertGreater(predicted_loads("")["rest-0"], 0.0)

    def test_checked_in_measurements_cover_every_split_tree(self) -> None:
        durations = load_durations()
        for tree in TEST_SPLITS:
            with self.subTest(tree=tree):
                names = set(tree_test_names(ci_test_packages.ROOT / HEAVY_TREES[tree]))
                measured = names & set(durations.get(tree, {}))
                # An unmeasured name is charged the median, so a stale file
                # still balances; most names must be measured for the budget
                # prediction to mean anything.
                self.assertGreater(len(measured), 0.9 * len(names), f"{tree} measurements are stale")

    def test_real_package_weights_load_and_are_valid(self) -> None:
        weights = load_package_durations()
        self.assertTrue(weights, "scripts/ci_test_durations.json has no rest package weights")
        self.assertTrue(all(value >= 0 for value in weights.values()))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "durations.json"
            path.write_text('{"trees": {}}', encoding="utf-8")
            self.assertEqual(load_package_durations(path), {})
            path.write_text('{"trees": {}, "packages": {"x": -1}}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_package_durations(path)

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
            select_packages(["example.test/pipelock/internal/config"], "proxy-0")


def _selected_by(selectors: dict[str, str], name: str) -> list[str]:
    return [shard for shard, selector in selectors.items() if selector_selects(selector, name)]


def _go_split_regexp(pattern: str) -> list[list[str]]:
    """Mirror testing.splitRegexp: alternatives of '/'-separated elements."""
    alternatives: list[list[str]] = []
    elements: list[str] = []
    start = paren = bracket = 0
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if bracket > 0:
            if char == "]":
                bracket -= 1
        elif char == "[":
            bracket += 1
        elif char == "(":
            paren += 1
        elif char == ")":
            paren -= 1
        elif paren == 0 and char in "/|":
            elements.append(pattern[start:index])
            start = index + 1
            if char == "|":
                alternatives.append(elements)
                elements = []
        index += 1
    elements.append(pattern[start:])
    alternatives.append(elements)
    return alternatives


class TestTestNameSplit(unittest.TestCase):
    NAMES = [f"Test{word}{index}" for word in ("Scan", "Proxy", "Fetch") for index in range(40)] + [
        "TestScan",
        "TestScanTextForDLP",
        "FuzzScanResponseContent",
        "ExampleScanner",
        "Test",
    ]

    def selectors(self, tree: str, names: list[str]) -> dict[str, str]:
        return {
            f"{tree}-{index}": shard_selector(f"{tree}-{index}", names)
            for index in range(TEST_SPLITS[tree])
        }

    def test_split_trees_cover_every_package_exactly_once_per_sub_shard(self) -> None:
        packages = [
            "example.test/pipelock/internal/proxy",
            "example.test/pipelock/internal/proxy/baseline",
            "example.test/pipelock/internal/scanner",
            "example.test/pipelock/internal/mcp",
            "example.test/pipelock/internal/mcp/jsonrpc",
            "example.test/pipelock/internal/cli/runtime",
        ]
        for tree in TEST_SPLITS:
            expected = [pkg for pkg in packages if package_in_tree(pkg, HEAVY_TREES[tree])]
            for index in range(TEST_SPLITS[tree]):
                with self.subTest(shard=f"{tree}-{index}"):
                    self.assertEqual(select_packages(packages, f"{tree}-{index}"), expected)

    def test_partition_is_disjoint_and_complete(self) -> None:
        for tree in TEST_SPLITS:
            with self.subTest(tree=tree):
                selectors = self.selectors(tree, self.NAMES)
                self.assertEqual(partition_errors(self.NAMES, selectors), [])
                counts = [
                    sum(1 for name in self.NAMES if selector_selects(sel, name))
                    for sel in selectors.values()
                ]
                self.assertEqual(sum(counts), len(self.NAMES))
                self.assertTrue(all(counts), counts)

    def test_new_name_lands_in_exactly_one_sub_shard(self) -> None:
        # A test added after the inventory was taken, or one the inventory
        # cannot see, must still run exactly once.
        selectors = self.selectors("scanner", self.NAMES)
        for unseen in ("TestAddedLater", "TestScan2Extra", "FuzzNew", "ExampleLater"):
            with self.subTest(name=unseen):
                self.assertNotIn(unseen, self.NAMES)
                self.assertEqual(len(_selected_by(selectors, unseen)), 1)
                self.assertEqual(_selected_by(selectors, unseen), [f"scanner-{TEST_SPLITS['scanner'] - 1}"])

    def test_partition_is_stable_across_order_and_process(self) -> None:
        first = self.selectors("proxy", self.NAMES)
        self.assertEqual(first, self.selectors("proxy", list(reversed(self.NAMES))))
        self.assertEqual(first, self.selectors("proxy", self.NAMES + self.NAMES[:5]))
        # Python's str hash is randomized per process; the bucket must not be.
        code = (
            "from scripts.ci_test_packages import name_bucket;"
            "print([name_bucket(n, 2) for n in ('TestScan', 'TestProxy7', 'FuzzX')])"
        )
        outputs = {
            subprocess.run(
                [sys.executable, "-c", code],
                cwd=ci_test_packages.ROOT,
                env={**os.environ, "PYTHONHASHSEED": seed},
                check=True,
                text=True,
                capture_output=True,
            ).stdout
            for seed in ("0", "1", "12345")
        }
        self.assertEqual(len(outputs), 1, outputs)
        self.assertEqual(
            outputs.pop().strip(),
            str([name_bucket(n, 2) for n in ("TestScan", "TestProxy7", "FuzzX")]),
        )

    def test_regex_anchoring_rejects_prefix_and_suffix_collisions(self) -> None:
        pattern = exact_names_regex(["TestScan", "FuzzScan"])
        for name in ("TestScan", "FuzzScan"):
            self.assertIsNotNone(re.search(pattern, name), name)
        for name in ("TestScanTextForDLP", "XTestScan", "TestSca", "TestScanX", "FuzzScanner", "Test"):
            with self.subTest(name=name):
                self.assertIsNone(re.search(pattern, name))
        self.assertNotIn("/", pattern)

    def test_real_selectors_are_one_top_level_alternative(self) -> None:
        # go test splits -run/-skip on '|' and '/' outside parentheses and
        # brackets (splitRegexp in testing/match.go). A top-level '|' drops the
        # anchors from each piece, so `^(?:TestA)|^(?:TestB)$` also runs
        # TestAExtra. Every generated selector must stay one piece.
        for shard in (f"{tree}-{index}" for tree in TEST_SPLITS for index in range(TEST_SPLITS[tree])):
            with self.subTest(shard=shard):
                pattern = shard_selector(shard).partition("=")[2]
                self.assertEqual(_go_split_regexp(pattern), [[pattern]])
        self.assertEqual(len(_go_split_regexp("^(?:TestA)|^(?:TestB)$")), 2)
        self.assertEqual(_go_split_regexp("^(?:TestA)$/sub"), [["^(?:TestA)$", "sub"]])

    def test_prefix_collision_across_sub_shards_selects_each_once(self) -> None:
        names = ["TestScan", "TestScanTextForDLP"]
        count = TEST_SPLITS["scanner"]
        last = count - 1
        # Find a pairing where the shorter name sits in a -run bucket, so an
        # unanchored -run would also claim the longer name from the -skip side.
        for suffix in range(2000):
            short, long_ = f"TestScan{suffix}", f"TestScan{suffix}TextForDLP"
            if name_bucket(short, count) == 0 and name_bucket(long_, count) == last:
                names = [short, long_, *(f"TestOther{index}" for index in range(40))]
                break
        else:
            self.fail("no colliding pair found")
        selectors = self.selectors("scanner", names)
        if not all(selectors.values()):
            self.skipTest("fixture produced an empty bucket")
        self.assertEqual(partition_errors(names, selectors), [])
        self.assertEqual(_selected_by(selectors, long_), [f"scanner-{last}"])

    def test_empty_bucket_and_oversize_selector_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "would select no tests"):
            shard_selector("proxy-0", ["TestOnlyOne"])
        with self.assertRaisesRegex(ValueError, "empty name set"):
            exact_names_regex([])
        # Enough oversize names that even one bucket of the split overflows.
        huge = [f"Test{'x' * 200}{index}" for index in range(1000 * TEST_SPLITS["proxy"])]
        with self.assertRaisesRegex(ValueError, "raise TEST_SPLITS"):
            shard_selector("proxy-0", huge)

    def test_weighted_partition_balances_time_not_count(self) -> None:
        # Two slow tests that a name hash could put together must land apart,
        # and the fast tests fill around them.
        weights = {"TestSlowA": 300.0, "TestSlowB": 290.0, **{f"TestFast{i}": 1.0 for i in range(40)}}
        buckets = partition_names(list(weights), 2, weights)
        loads = [sum(weights[name] for name in bucket) for bucket in buckets]
        self.assertNotEqual(
            "TestSlowA" in buckets[0], "TestSlowB" in buckets[0], "slow tests share a bucket"
        )
        self.assertLessEqual(max(loads) - min(loads), max(weights.values()))
        self.assertCountEqual([n for b in buckets for n in b], list(weights))

    def test_weighted_partition_is_deterministic_and_charges_unmeasured_the_median(self) -> None:
        weights = {"TestA": 10.0, "TestB": 20.0, "TestC": 30.0}
        names = ["TestA", "TestB", "TestC", "TestNew1", "TestNew2"]
        first = partition_names(names, 2, weights)
        self.assertEqual(first, partition_names(list(reversed(names)) + names[:2], 2, weights))
        # Median of measured names is 20s, so each unmeasured name weighs 20s.
        # Longest first: C(30)|B(20), New1->1, New2->0, A->1 gives 50 | 50.
        self.assertEqual(first, [["TestC", "TestNew2"], ["TestA", "TestB", "TestNew1"]])

    def test_weighted_selectors_stay_disjoint_and_complete(self) -> None:
        weights = {name: float(len(name) % 7 + 1) for name in self.NAMES}
        for tree in TEST_SPLITS:
            with self.subTest(tree=tree):
                selectors = {
                    f"{tree}-{index}": shard_selector(f"{tree}-{index}", self.NAMES, weights)
                    for index in range(TEST_SPLITS[tree])
                }
                self.assertEqual(partition_errors(self.NAMES, selectors), [])
                for unseen in ("TestAddedLater", "FuzzNew"):
                    self.assertEqual(_selected_by(selectors, unseen), [f"{tree}-{TEST_SPLITS[tree] - 1}"])

    def test_durations_file_is_valid_and_names_only_split_trees(self) -> None:
        durations = load_durations()
        self.assertTrue(durations, "scripts/ci_test_durations.json is missing or empty")
        self.assertLessEqual(set(durations), set(TEST_SPLITS))
        for tree in TEST_SPLITS:
            with self.subTest(tree=tree):
                self.assertIn(tree, durations, f"no measured durations for split tree {tree}")

    def test_zero_weights_still_fill_every_bucket(self) -> None:
        names = [f"TestZero{index}" for index in range(12)]
        buckets = partition_names(names, 4, dict.fromkeys(names, 0.0))
        self.assertTrue(all(buckets), buckets)
        self.assertEqual(sorted(len(bucket) for bucket in buckets), [3, 3, 3, 3])

    def test_final_shard_oversize_names_a_remedy_that_shrinks_it(self) -> None:
        huge = [f"Test{'x' * 200}{index}" for index in range(2000)]
        last = f"proxy-{TEST_SPLITS['proxy'] - 1}"
        with self.assertRaises(ValueError) as caught:
            shard_selector(last, huge)
        self.assertIn("lower TEST_SPLITS", str(caught.exception))
        self.assertNotIn("raise TEST_SPLITS", str(caught.exception))

    def test_duration_refresh_merges_per_name_and_drops_removed_tests(self) -> None:
        from scripts.ci_test_durations import merge

        previous = {"proxy": {"TestA": 10.0, "TestB": 20.0, "TestGone": 5.0}}
        measured = {"proxy": {"TestA": 3.0}}
        inventory = {"proxy": {"TestA", "TestB"}}
        merged = merge(previous, measured, inventory)["trees"]
        # TestA re-measured faster, TestB kept, TestGone no longer in the tree.
        self.assertEqual(merged["proxy"], {"TestA": 3.0, "TestB": 20.0})
        # A refresh that measured nothing in a tree keeps that tree intact.
        self.assertEqual(merge(previous, {}, None)["trees"]["proxy"], previous["proxy"])

    def test_malformed_durations_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "durations.json"
            self.assertEqual(load_durations(path), {})
            for bad in ('{"proxy": {}}', '{"trees": {"proxy": []}}', '{"trees": {"proxy": {"TestA": -1}}}',
                        '{"trees": {"proxy": {"TestA": "5"}}}', '{"trees": {"proxy": {"TestA": true}}}'):
                with self.subTest(bad=bad):
                    path.write_text(bad, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_durations(path)

    def test_nonfinite_tree_and_package_weights_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "durations.json"
            for value in ("NaN", "Infinity", "-Infinity", "1e999"):
                with self.subTest(value=value):
                    path.write_text('{"trees": {"scanner": {"TestA": ' + value + '}}}', encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_durations(path)
                    path.write_text('{"packages": {"example.test/slow": ' + value + '}}', encoding="utf-8")
                    with self.assertRaises(ValueError):
                        ci_test_packages.load_package_durations(path)

    def test_unsplit_shards_have_no_selector(self) -> None:
        for shard in ("rest-0", "rest-1", "rest-2"):
            self.assertEqual(shard_selector(shard, self.NAMES), "")
        with self.assertRaisesRegex(ValueError, "unknown shard"):
            shard_selector("proxy", self.NAMES)

    def test_partition_errors_report_missing_and_duplicate(self) -> None:
        selectors = self.selectors("scanner", self.NAMES)
        dropped = dict(selectors)
        dropped["scanner-1"] = "-run=^(?:TestNothing)$"
        errors = partition_errors(self.NAMES, dropped)
        self.assertTrue(any("no sub-shard" in error for error in errors), errors)
        doubled = dict(selectors)
        doubled["scanner-1"] = ""
        errors = partition_errors(self.NAMES, doubled)
        self.assertTrue(any("scanner-0" in e and "scanner-1" in e for e in errors), errors)

    def test_inventory_reads_real_trees_and_ignores_methods(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sub").mkdir()
            (root / "testdata").mkdir()
            (root / "a_test.go").write_text(
                "package a\n"
                "func TestTop(t *testing.T) {}\n"
                "func (s suite) TestMethod(t *testing.T) {}\n"
                "func FuzzTop(f *testing.F) {}\n"
                "func ExampleTop() {}\n"
                "func BenchmarkTop(b *testing.B) {}\n"
                "func helper() {}\n"
            )
            (root / "sub" / "b_test.go").write_text("package sub\nfunc TestSub(t *testing.T) {}\n")
            (root / "testdata" / "c_test.go").write_text("func TestFixture(t *testing.T) {}\n")
            (root / "d.go").write_text("func TestNotATestFile(t *testing.T) {}\n")
            self.assertEqual(
                tree_test_names(root), ["ExampleTop", "FuzzTop", "TestSub", "TestTop"]
            )
        for tree in TEST_SPLITS:
            with self.subTest(tree=tree):
                names = tree_test_names(ci_test_packages.ROOT / HEAVY_TREES[tree])
                self.assertGreater(len(names), 100)
                selectors = self.selectors(tree, names)
                self.assertEqual(partition_errors(names, selectors), [])


if __name__ == "__main__":
    unittest.main()
