# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.release_doc_versions import check


CURRENT = """\
git clone --branch v3.6.0 --depth 1 https://github.com/luckyPipewrench/pipelock.git
docker pull ghcr.io/luckypipewrench/pipelock:3.6.0
helm install pipelock oci://ghcr.io/luckypipewrench/charts/pipelock --version 3.6.0
RUN curl -fsSL https://github.com/luckyPipewrench/pipelock/releases/download/v3.6.0/pipelock_3.6.0_linux_amd64.tar.gz
- uses: luckyPipewrench/pipelock@0123456789abcdef0123456789abcdef01234567 # v3.6.0
"""


def write_tree(root: Path, *, current: str = CURRENT, health: str = '  "version": "v3.6.0",\n') -> None:
    (root / "README.md").write_text(current, encoding="utf-8")
    health_path = root / "docs" / "guides" / "health.md"
    health_path.parent.mkdir(parents=True, exist_ok=True)
    health_path.write_text(health, encoding="utf-8")


class ReleaseDocVersionTests(unittest.TestCase):
    def test_known_current_pins_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(root)
            self.assertEqual(check(root, "v3.6.0"), [])

    def test_each_supported_stale_pin_fails(self) -> None:
        stale_cases = (
            ("git clone branch", "git clone --branch v3.5.0 --depth 1 https://github.com/luckyPipewrench/pipelock.git"),
            ("Docker tag", "docker pull ghcr.io/luckypipewrench/pipelock:3.5.0"),
            ("Helm version", "helm install pipelock oci://ghcr.io/luckypipewrench/charts/pipelock --version 3.5.0"),
            (
                "archive tag and filename",
                "RUN curl https://github.com/luckyPipewrench/pipelock/releases/download/v3.5.0/pipelock_3.5.0_linux_amd64.tar.gz",
            ),
            (
                "Action version comment",
                "- uses: luckyPipewrench/pipelock@0123456789abcdef0123456789abcdef01234567 # v3.5.0",
            ),
        )
        for label, line in stale_cases:
            with self.subTest(surface=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_tree(root, current=CURRENT.replace(
                    "git clone --branch v3.6.0 --depth 1 https://github.com/luckyPipewrench/pipelock.git",
                    line,
                    1,
                ))
                findings = check(root, "v3.6.0")
                self.assertTrue(any("expected" in finding and "README.md" in finding for finding in findings), findings)

    def test_quoted_stale_pins_cannot_hide_behind_current_pins(self) -> None:
        for quote in ("'", '"', "`"):
            for line in (
                f"git clone --branch {quote}v3.5.0{quote} https://github.com/luckyPipewrench/pipelock.git",
                f"- uses: luckyPipewrench/pipelock@0123456789abcdef0123456789abcdef01234567 # {quote}v3.5.0{quote}",
            ):
                with self.subTest(line=line), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    write_tree(root, current=CURRENT + line + "\n")
                    self.assertTrue(any("3.5.0" in finding for finding in check(root, "v3.6.0")))

    def test_unprefixed_action_tag_cannot_hide_behind_current_comment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(root, current=CURRENT + "- uses: luckyPipewrench/pipelock@3.5.0\n")
            self.assertTrue(any("incorrect v prefix" in finding for finding in check(root, "v3.6.0")))

    def test_stale_health_output_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(root, health='  "version": "v3.5.0",\n')
            self.assertTrue(any("health response version" in finding for finding in check(root, "v3.6.0")))

    def test_malformed_candidate_and_supported_reference_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(root)
            findings = check(root, "v3.6")
            self.assertTrue(any("malformed release tag" in finding for finding in findings), findings)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            malformed = CURRENT.replace(
                "ghcr.io/luckypipewrench/pipelock:3.6.0",
                "ghcr.io/luckypipewrench/pipelock:3.6",
            )
            write_tree(root, current=malformed)
            findings = check(root, "v3.6.0")
            self.assertTrue(any("malformed version '3.6'" in finding for finding in findings), findings)

    def test_historical_and_frozen_comparisons_are_positive_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(root)
            (root / "docs" / "cli").mkdir(parents=True)
            (root / "docs" / "cli" / "update.md").write_text(
                "pipelock update --version v3.1.0   # install a specific release tag\n",
                encoding="utf-8",
            )
            (root / "docs" / "contain-cli.md").write_text(
                "sudo pipelock contain upgrade --version v3.2.0  # pin to a specific tag\n",
                encoding="utf-8",
            )
            (root / "docs" / "benchmarks").mkdir(parents=True)
            (root / "docs" / "benchmarks" / "history.md").write_text(
                "docker pull ghcr.io/luckypipewrench/pipelock:3.2.0\n",
                encoding="utf-8",
            )
            (root / "CHANGELOG.md").write_text(
                "git clone --branch v3.4.0 https://github.com/luckyPipewrench/pipelock.git\n",
                encoding="utf-8",
            )
            self.assertEqual(check(root, "v3.6.0"), [])

    def test_prefixes_follow_published_artifact_names(self) -> None:
        for before, after in (
            ("--branch v3.6.0", "--branch 3.6.0"),
            ("pipelock:3.6.0", "pipelock:v3.6.0"),
            ("--version 3.6.0", "--version v3.6.0"),
        ):
            with self.subTest(reference=after), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_tree(root, current=CURRENT.replace(before, after))
                self.assertTrue(any("incorrect v prefix" in item for item in check(root, "v3.6.0")))

    def test_continuations_punctuation_and_tag_refs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(root, current=CURRENT + "\nSee (ghcr.io/luckypipewrench/pipelock:3.6.0).\n")
            self.assertEqual(check(root, "v3.6.0"), [])
            with (root / "README.md").open("a") as target:
                target.write("\nhelm pull oci://ghcr.io/luckypipewrench/charts/pipelock \\\n --version 3.5.0\n- uses: luckyPipewrench/pipelock@v3.5.0\ngh release download v3.5.0 --repo luckyPipewrench/pipelock\n")
            findings = check(root, "v3.6.0")
            for surface in ("Helm chart version", "GitHub Action tag", "release download command"):
                self.assertTrue(any(surface in item for item in findings), findings)

    def test_cli_and_shell_consumer_deny_stale_and_allow_current(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        script = source_root / "scripts/release_doc_versions.py"
        consumer = (source_root / "scripts/check-release-ready.sh").read_text()
        start = consumer.index('if ! python3 "$REPO_ROOT/scripts/release_doc_versions.py"')
        block = consumer[start:consumer.index("\nfi", start) + 3]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "scripts/release_doc_versions.py").write_text(script.read_text())
            for version, expected in (("3.6.0", 0), ("3.5.0", 1)):
                write_tree(root, current=CURRENT.replace("3.6.0", version))
                result = subprocess.run([sys.executable, str(script), str(root), "v3.6.0"], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)
                result = subprocess.run(["bash", "-c", 'REPO_ROOT="$1"; VERSION=v3.6.0; fail=0; ' + block + '; exit "$fail"', "consumer", str(root)], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_archive_tag_and_filename_fail_independently(self) -> None:
        for before, after in (("/v3.6.0/", "/v3.5.0/"), ("pipelock_3.6.0_", "pipelock_3.5.0_")):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_tree(root, current=CURRENT.replace(before, after))
                self.assertTrue(any("release archive URL" in item for item in check(root, "v3.6.0")))

    def test_missing_required_surface_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_tree(
                root,
                current="\n".join(
                    line for line in CURRENT.splitlines() if "helm install" not in line
                )
                + "\n",
            )
            findings = check(root, "v3.6.0")
            self.assertTrue(any("missing required current-release surface: Helm" in finding for finding in findings), findings)



if __name__ == "__main__":
    unittest.main()
