import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "check-verifier-publish-tag.sh"


class VerifierPublishTagTests(unittest.TestCase):
    def fixture(self, ts_version: str = "0.3.1", rust_version: str = "0.3.1") -> Path:
        temp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        ts = temp / "sdk" / "verifiers" / "ts"
        rust = temp / "sdk" / "verifiers" / "rust"
        ts.mkdir(parents=True)
        rust.mkdir(parents=True)
        (ts / "package.json").write_text(json.dumps({"version": ts_version}), encoding="utf-8")
        (rust / "Cargo.toml").write_text(
            f'[package]\nname = "pipelock-verifier-rs"\nversion = "{rust_version}"\n',
            encoding="utf-8",
        )
        return temp

    def run_check(self, root: Path, tag: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(CHECK), "--root", str(root), tag],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_matching_tag_and_manifests_pass(self) -> None:
        result = self.run_check(self.fixture(), "verifier-v0.3.1")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_tag_fails_before_publish(self) -> None:
        result = self.run_check(self.fixture(), "verifier-v0.3.2")
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not match package version", result.stderr)

    def test_manifest_version_drift_fails_before_publish(self) -> None:
        result = self.run_check(self.fixture(rust_version="0.3.2"), "verifier-v0.3.1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("TypeScript 0.3.1 does not match Rust 0.3.2", result.stderr)


if __name__ == "__main__":
    unittest.main()
