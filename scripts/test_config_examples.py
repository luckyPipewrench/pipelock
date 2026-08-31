# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-config-examples.sh"


class ConfigExampleFixtureContractTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
