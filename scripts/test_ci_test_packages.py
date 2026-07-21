# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Adversarial tests for release and CI package sharding."""

from __future__ import annotations

import unittest

from scripts.ci_test_packages import package_in_tree, package_suffix, select_packages


class TestPackageSharding(unittest.TestCase):
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
