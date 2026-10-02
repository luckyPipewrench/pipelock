#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Exercise discovery and search failures through the real stability gate."""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("check-test-stability.sh")


class StabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts/check-test-stability.sh")
        self.git("init", "-q")

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.root, env=self.env, check=True, capture_output=True, timeout=10
        )

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def run_gate(self):
        return subprocess.run(
            ["bash", "scripts/check-test-stability.sh"],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=10,
        )

    def test_clean_new_root_and_root_level_file(self):
        self.write("new component/clean_test.go", "package example\n")
        self.write("root_test.go", "package example\n")
        self.assertEqual(self.run_gate().returncode, 0)

    def test_sleep_in_each_previously_omitted_root(self):
        for root in ("scripts", "configs", "future component"):
            with self.subTest(root=root):
                name = f"{root}/sample_test.go"
                self.write(name, "package example\nfunc test() { time.Sleep(1) }\n")
                result = self.run_gate()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"{name}:2:", result.stderr)
                (self.root / name).unlink()

    def test_fixed_port_in_new_root(self):
        self.write("future/port_test.go", 'net.Listen("tcp", "127.0.0.1:9999")\n')
        result = self.run_gate()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("fixed local ports", result.stderr)

    def test_ignored_files_are_excluded_but_tracked_files_are_not(self):
        self.write(".gitignore", "ignored/\n")
        self.write("ignored/bad_test.go", "time.Sleep(1)\n")
        self.write("internal/clean_test.go", "package example\n")
        self.assertEqual(self.run_gate().returncode, 0)
        self.git("add", "-f", "ignored/bad_test.go")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_allowlist_keeps_filename_for_single_file(self):
        self.write("internal/allowed_test.go", "time.Sleep(1)\n")
        self.write("scripts/test-stability-allowlist.txt", "internal/allowed_test.go:1:time.Sleep(1)\n")
        self.assertEqual(self.run_gate().returncode, 0)

    def test_missing_tracked_file_is_search_error(self):
        self.write("internal/missing_test.go", "package example\n")
        self.git("add", "internal/missing_test.go")
        (self.root / "internal/missing_test.go").unlink()
        result = self.run_gate()
        self.assertGreater(result.returncode, 1)
        self.assertIn("search exited", result.stderr)

    def test_empty_inventory_is_error(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 2)
        self.assertIn("no Go tests found", result.stderr)

    def test_grep_fallback(self):
        tools = self.root / "bin"
        tools.mkdir()
        for tool in ("bash", "git", "dirname", "mktemp", "rm", "cat", "grep"):
            (tools / tool).symlink_to(shutil.which(tool))
        self.env["PATH"] = str(tools)
        self.write("new component/clean_test.go", "package example\n")
        self.assertEqual(self.run_gate().returncode, 0)
        self.write("new component/clean_test.go", "time.Sleep(1)\n")
        result = self.run_gate()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("new component/clean_test.go:1:", result.stderr)

    def test_discovery_failure_is_error(self):
        shutil.rmtree(self.root / ".git")
        result = self.run_gate()
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot discover", result.stderr)


if __name__ == "__main__":
    unittest.main()
