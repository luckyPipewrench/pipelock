#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Exercise guide navigation and its enforcement by the example runner."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import check_guide_links


ROOT = Path(__file__).resolve().parents[1]
BACKLINK = "[Guide](../../docs/guides/demo.md)\n"


class GuideLinksTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.guide = self.root / "docs/guides/demo.md"
        self.guide.parent.mkdir(parents=True)
        self.guide.write_text("[Example](../../examples/demo/)\n", encoding="utf-8")
        self.readme = self.root / "examples/demo/README.md"
        self.readme.parent.mkdir(parents=True)
        self.readme.write_text(BACKLINK, encoding="utf-8")

    def test_valid_link_forms(self):
        for link in [
            BACKLINK,
            "[Guide](/docs/guides/demo.md#section)",
            '[Guide](<../../docs/guides/demo.md> "Guide title")',
            "[Guide][ref]\n\n[ref]: ../../docs/guides/demo.md",
            "[Guide][]\n\n[guide]: ../../docs/guides/demo.md",
            "[Guide]\n\n[guide]: ../../docs/guides/demo.md",
        ]:
            with self.subTest(link=link):
                self.readme.write_text(link, encoding="utf-8")
                self.assertEqual(check_guide_links.check(self.root), (1, []))

    def test_missing_or_non_link_text_fails(self):
        for text in [
            "", "../../docs/guides/demo.md", "`" + BACKLINK.strip() + "`",
            "<!-- " + BACKLINK + " -->", "```md\n" + BACKLINK + "```\n",
            "~~~\n" + BACKLINK + "~~~\n", "    " + BACKLINK,
            "![Guide](../../docs/guides/demo.md)",
            "[Guide](../../docs/guides/other.md)",
            "[ref]: ../../docs/guides/demo.md\n",
        ]:
            with self.subTest(text=text):
                self.readme.write_text(text, encoding="utf-8")
                count, errors = check_guide_links.check(self.root)
                self.assertEqual(count, 1)
                self.assertEqual(len(errors), 1)
                self.assertIn("missing Markdown link", errors[0])

    def test_each_referencing_guide_needs_a_backlink(self):
        other = self.guide.with_name("other.md")
        other.write_text("`examples/demo/README.md`\n", encoding="utf-8")
        count, errors = check_guide_links.check(self.root)
        self.assertEqual(count, 2)
        self.assertEqual(len(errors), 1)
        self.assertIn("other.md", errors[0])
        self.readme.write_text(BACKLINK + "[Other](/docs/guides/other.md)", encoding="utf-8")
        self.assertEqual(check_guide_links.check(self.root), (2, []))

    def test_reference_discovery_excludes_other_example_trees(self):
        self.guide.write_text(
            "[Example](/examples/demo/README.md)\n"
            "cd examples/demo\n"
            "[Chart](../../charts/pipelock/examples/values.yaml)\n"
            "[External](https://vendor.example/examples/unrelated/)\n"
            "<!-- examples/hidden/ -->\n",
            encoding="utf-8",
        )
        self.assertEqual(check_guide_links.check(self.root), (1, []))

    def test_missing_readme_and_missing_example_fail(self):
        self.readme.unlink()
        self.assertIn("missing README", check_guide_links.check(self.root)[1][0])
        self.readme.parent.rmdir()
        self.assertIn("does not exist", check_guide_links.check(self.root)[1][0])

    def test_missing_guides_fail(self):
        self.guide.unlink()
        self.assertEqual(check_guide_links.check(self.root), (0, ["no Markdown guides found under docs/guides"]))

    def test_runner_propagates_missing_backlink_failure(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        shutil.copy2(ROOT / "scripts/verify-examples.sh", scripts / "verify-examples.sh")
        shutil.copy2(ROOT / "examples/check_guide_links.py", self.root / "examples/check_guide_links.py")
        self.readme.write_text("No guide link.\n", encoding="utf-8")
        env = os.environ.copy()
        # The link check must run before the binary preflight or any examples.
        env["PIPELOCK_BIN"] = str(self.root / "missing-binary")
        result = subprocess.run(["bash", str(scripts / "verify-examples.sh")], capture_output=True, text=True, env=env, timeout=15)
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing Markdown link", result.stderr)
        self.assertIn("example-guide-links: FAILED", result.stdout)
        self.assertNotIn("binary is not executable", result.stderr)
        self.readme.write_text(BACKLINK, encoding="utf-8")
        result = subprocess.run(["bash", str(scripts / "verify-examples.sh")], capture_output=True, text=True, env=env, timeout=15)
        self.assertIn("example-guide-links: OK", result.stdout)
        self.assertIn("binary is not executable", result.stderr)

    def test_repository_examples_link_to_their_guides(self):
        checked, errors = check_guide_links.check(ROOT)
        self.assertGreater(checked, 0)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
