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
            for shard in ("proxy", "scanner", "mcp", "rest")
            for package in select_packages(packages, shard)
        ]

        self.assertCountEqual(selected, packages)
        self.assertEqual(len(selected), len(set(selected)))

    def test_nested_internal_directory_cannot_impersonate_heavy_shard(self) -> None:
        package = "example.test/pipelock/internal/config/internal/proxy"
        self.assertEqual(package_suffix(package), "internal/config/internal/proxy")
        self.assertFalse(package_in_tree(package, "internal/proxy"))
        self.assertEqual(select_packages([package], "rest"), [package])

    def test_prefix_collision_is_not_a_tree_match(self) -> None:
        package = "example.test/pipelock/internal/proxying"
        self.assertFalse(package_in_tree(package, "internal/proxy"))
        self.assertEqual(select_packages([package], "rest"), [package])

    def test_empty_heavy_shard_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "no packages matched shard"):
            select_packages(["example.test/pipelock/internal/config"], "proxy")


if __name__ == "__main__":
    unittest.main()
