# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-config-examples.sh"


class ConfigExampleFixtureContractTests(unittest.TestCase):
    def run_fixture_gate(self, keygen_mode: str) -> subprocess.CompletedProcess[str]:
        temp = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        fake = temp / "pipelock"
        fake.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = tls ] && [ "${2:-}" = init ]; then
    mkdir -p "$4"
    exit 0
fi
if [ "${1:-}" = signing ] && [ "${2:-}" = key ] && [ "${3:-}" = generate ]; then
    [ "$FAKE_KEYGEN_MODE" != fail ] || exit 9
    exit 0
fi
exit 97
""",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        env = os.environ.copy()
        env["HOME"] = str(temp / "home")
        env["FAKE_KEYGEN_MODE"] = keygen_mode
        return subprocess.run(
            ["bash", str(SCRIPT), str(fake)],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_recorder_key_uses_dedicated_lifecycle_command(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("signing key generate", source)
        self.assertIn("--purpose receipt-signing", source)
        self.assertNotIn('"$BIN" init --output "$WORK/keygen/', source)

    def test_missing_recorder_key_fails_the_gate(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        failure = 'echo "config-examples: could not fixture a recorder signing key" >&2'
        start = source.index(failure)
        self.assertIn("exit 1", source[start : start + 160])

    def test_key_generation_failure_fails_the_gate(self) -> None:
        result = self.run_fixture_gate("fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not fixture a recorder signing key", result.stderr)

    def test_empty_generated_key_fails_the_gate(self) -> None:
        result = self.run_fixture_gate("empty")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not fixture a recorder signing key", result.stderr)


if __name__ == "__main__":
    unittest.main()
