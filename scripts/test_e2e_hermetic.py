#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Behavioral tests for the shared verification environment isolation."""

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SHELL_HELPER = ROOT / "scripts" / "e2e" / "hermetic-env.sh"
PYTHON_HELPER = ROOT / "scripts" / "e2e" / "hermetic.py"
SPEC = importlib.util.spec_from_file_location("pipelock_e2e_hermetic", PYTHON_HELPER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {PYTHON_HELPER}")
HERMETIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HERMETIC)
pipelock_environment = HERMETIC.pipelock_environment


class HermeticEnvironmentTest(unittest.TestCase):
    def test_python_helper_overrides_installed_state_locations(self):
        poisoned = {
            "HOME": "/host/home",
            "XDG_CONFIG_HOME": "/host/config",
            "XDG_DATA_HOME": "/host/data",
            "XDG_STATE_HOME": "/host/state",
            "XDG_CACHE_HOME": "/host/cache",
            "PIPELOCK_CONFIG": "/etc/pipelock/pipelock.yaml",
            "PIPELOCK_POSTURE_PROOF": "/var/lib/pipelock/contain/posture/proof.json",
        }
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, poisoned):
            workdir = Path(tmp)
            config = workdir / "pipelock.yaml"
            config.write_text("mode: balanced\n", encoding="utf-8")
            env = pipelock_environment(workdir, config)

            hermetic_root = workdir / "hermetic"
            for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"):
                self.assertTrue(Path(env[name]).is_relative_to(hermetic_root), name)
            self.assertEqual(env["PIPELOCK_CONFIG"], str(config.resolve()))
            self.assertTrue(Path(env["PIPELOCK_POSTURE_PROOF"]).is_relative_to(hermetic_root))
            self.assertFalse(Path(env["PIPELOCK_POSTURE_PROOF"]).exists())

    def test_shell_helper_overrides_installed_state_and_preserves_host_tool_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            isolation_root = Path(tmp) / "isolation"
            script = r'''
source "$SHELL_HELPER"
pipelock_hermetic_env "$ISOLATION_ROOT"
printf 'runtime=%s\n' "$HOME|$XDG_CONFIG_HOME|$XDG_DATA_HOME|$XDG_STATE_HOME|$XDG_CACHE_HOME|$PIPELOCK_CONFIG|$PIPELOCK_POSTURE_PROOF"
pipelock_host_tool bash -c 'printf "host=%s\\n" "$HOME"'
printf 'after=%s\n' "$HOME"
'''
            env = os.environ.copy()
            env.update(
                {
                    "HOME": "/host/home",
                    "XDG_CONFIG_HOME": "/host/config",
                    "XDG_DATA_HOME": "/host/data",
                    "XDG_STATE_HOME": "/host/state",
                    "XDG_CACHE_HOME": "/host/cache",
                    "PIPELOCK_CONFIG": "/etc/pipelock/pipelock.yaml",
                    "PIPELOCK_POSTURE_PROOF": "/var/lib/pipelock/contain/posture/proof.json",
                    "SHELL_HELPER": str(SHELL_HELPER),
                    "ISOLATION_ROOT": str(isolation_root),
                }
            )
            result = subprocess.run(
                ["bash", "-ceu", script],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )

            lines = result.stdout.splitlines()
            runtime_paths = lines[0].removeprefix("runtime=").split("|")
            self.assertEqual(len(runtime_paths), 7)
            for value in runtime_paths:
                self.assertTrue(Path(value).is_relative_to(isolation_root), value)
            self.assertEqual(lines[1], "host=/host/home")
            self.assertEqual(lines[2], f"after={isolation_root / 'home'}")
            self.assertFalse(Path(runtime_paths[-1]).exists())

    def test_shell_helper_rejects_relative_root(self):
        result = subprocess.run(
            ["bash", "-ceu", 'source "$1"; pipelock_hermetic_env relative/root', "bash", str(SHELL_HELPER)],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root must be absolute", result.stderr)


if __name__ == "__main__":
    unittest.main()
