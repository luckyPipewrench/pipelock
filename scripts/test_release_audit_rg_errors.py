#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Regression test for fail-closed release-audit searches."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_AUDIT = ROOT / "scripts" / "release-audit.sh"


class ReleaseAuditRipgrepErrorTest(unittest.TestCase):
    def test_issue_comment_search_error_cannot_report_ok(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fake_rg = Path(temp_dir) / "rg"
            fake_rg.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"$*\" == *issue_comment:* ]]; then\n"
                "  exit 2\n"
                "fi\n"
                "exit 1\n",
                encoding="utf-8",
            )
            fake_rg.chmod(fake_rg.stat().st_mode | stat.S_IXUSR)
            result = subprocess.run(
                ["/usr/bin/bash", str(RELEASE_AUDIT)],
                cwd=ROOT,
                env=os.environ | {"PATH": f"{temp_dir}:/usr/bin:/bin"},
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ripgrep exited with 2", result.stderr)
        self.assertNotIn("release audit: OK", result.stderr)


if __name__ == "__main__":
    unittest.main()
