# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/git-version.sh product-version discovery.

The regression this guards: the repository carries independently-versioned
verifier tags (`verifier-v0.2.0`) alongside product tags (`v3.3.0`). An
unfiltered `git describe --tags` selects whichever tag is nearest in history, so
once a verifier tag landed after the last release, local and CI builds stamped a
version from the wrong release series -- and because callers strip one leading
"v", the result was the malformed `erifier-v0.2.0-1-gabc1234`.

Each test builds a real throwaway repository rather than mocking git, because
the bug lived in git's tag-selection behaviour and a mock would have reproduced
the assumption instead of the behaviour.
"""

import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "git-version.sh"


class GitVersionScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="pipelock-gitversion-")
        self.repo = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self._git("init", "-q", ".")
        # Pin identity and disable signing so the test never depends on the
        # developer's global git configuration.
        self._git("config", "user.email", "test@example.com")
        self._git("config", "user.name", "test")
        self._git("config", "commit.gpgSign", "false")
        self._git("config", "tag.gpgSign", "false")

    def _git(self, *args: str) -> str:
        return subprocess.run(
            ("git", "-C", str(self.repo)) + args,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def _commit(self, message: str) -> None:
        target = self.repo / "file.txt"
        with target.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")
        self._git("add", "file.txt")
        self._git("commit", "-qm", message)

    def _tag(self, name: str, *, tagger_date: str | None = None) -> None:
        env = None
        if tagger_date is not None:
            env = {**os.environ, "GIT_COMMITTER_DATE": tagger_date}
        subprocess.run(
            ("git", "-C", str(self.repo), "tag", "-a", name, "-m", name),
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

    def _version(self) -> str:
        """Run the script with the throwaway repo as the working directory."""
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            cwd=self.repo,
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null"},
        )
        return result.stdout.strip()

    def test_product_tag_at_head_reports_that_version(self) -> None:
        self._commit("one")
        self._tag("v3.3.0")
        self.assertEqual(self._version(), "3.3.0")

    def test_nearer_verifier_tag_does_not_shadow_the_product_version(self) -> None:
        """The exact regression: a verifier tag newer than the last release."""
        self._commit("one")
        self._tag("v3.3.0")
        self._commit("two")
        self._tag("verifier-v0.2.0")
        self._commit("three")

        version = self._version()

        # Must describe from the product tag, counting all commits since it.
        self.assertTrue(
            version.startswith("3.3.0-2-g"),
            f"expected a 3.3.0 development version, got {version!r}",
        )
        # The historical malformation, asserted directly so a regression is
        # unmistakable in the failure output rather than merely "wrong prefix".
        self.assertNotIn("erifier", version)

    def test_prerelease_product_tag_is_preserved(self) -> None:
        """The dotted product glob must not exclude a legitimate prerelease tag.

        The suffix text is irrelevant to tag selection; what matters is that a
        hyphenated suffix after the patch digit survives intact.
        """
        self._commit("one")
        self._tag("v1.2.3-beta.1")
        self.assertEqual(self._version(), "1.2.3-beta.1")

    def test_floating_action_tag_does_not_shadow_product_version(self) -> None:
        """The repo carries floating v1/v2 tags for the GitHub Action."""
        self._commit("one")
        self._tag("v3.3.0", tagger_date="2026-07-01T00:00:00Z")
        self._tag("v2", tagger_date="2026-07-02T00:00:00Z")
        self._commit("two")

        version = self._version()

        self.assertTrue(
            version.startswith("3.3.0-1-g"),
            f"expected a 3.3.0 development version, got {version!r}",
        )
        self.assertNotEqual(version, "2")
        self.assertFalse(version.startswith("2-"), f"floating action tag shadowed product tag: {version!r}")

    def test_no_product_tag_falls_back_to_a_commit_id(self) -> None:
        """A verifier-only repo must not borrow that unrelated version."""
        self._commit("one")
        self._tag("verifier-v0.2.0")

        version = self._version()

        self.assertNotIn("erifier", version)
        self.assertNotIn("0.2.0", version)
        # An abbreviated commit id: hexadecimal, and never version-shaped.
        self.assertRegex(version, r"^[0-9a-f]{7,}$")

    def test_untagged_repo_falls_back_to_a_commit_id(self) -> None:
        self._commit("one")
        self.assertRegex(self._version(), r"^[0-9a-f]{7,}$")

    def test_dirty_worktree_is_marked(self) -> None:
        """Release tooling relies on the -dirty marker to spot unclean builds."""
        self._commit("one")
        self._tag("v3.3.0")
        (self.repo / "file.txt").write_text("uncommitted\n", encoding="utf-8")
        self.assertEqual(self._version(), "3.3.0-dirty")


if __name__ == "__main__":
    unittest.main()
