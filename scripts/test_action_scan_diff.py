# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
ACTION = (ROOT / "action.yml").read_text(encoding="utf-8")


class ActionScanDiffTest(unittest.TestCase):
    def test_instrument_error_cannot_present_as_clean(self) -> None:
        self.assertIn('if [ "$SCAN_RC" -ne 0 ] && [ "$SCAN_RC" -ne 1 ]; then', ACTION)
        error_branch = ACTION.index('if [ "$SCAN_RC" -ne 0 ] && [ "$SCAN_RC" -ne 1 ]; then')
        branch_end = ACTION.index("\n        fi", error_branch)
        self.assertIn("exit 1", ACTION[error_branch:branch_end])
        self.assertIn('> "$SCAN_OUT" 2> "$SCAN_ERR"', ACTION)
        self.assertNotIn('> "$SCAN_OUT" 2>&1', ACTION)

    def test_exit_status_and_json_result_must_agree(self) -> None:
        self.assertIn('[ "$FINDINGS" -eq 0 ] && [ "$SCAN_RC" -ne 0 ]', ACTION)
        self.assertIn('[ "$FINDINGS" -gt 0 ] && [ "$SCAN_RC" -ne 1 ]', ACTION)
        self.assertIn("scan result disagrees with its exit status", ACTION)
        mismatch_start = ACTION.index(
            'if { [ "$FINDINGS" -eq 0 ] && [ "$SCAN_RC" -ne 0 ]; }'
        )
        mismatch_end = ACTION.index("\n        fi", mismatch_start)
        self.assertIn("exit 1", ACTION[mismatch_start:mismatch_end])


if __name__ == "__main__":
    unittest.main()
