# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Adversarial tests for release and CI package sharding."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from scripts.ci_test_packages import SHARDS, package_in_tree, package_suffix, select_packages


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
