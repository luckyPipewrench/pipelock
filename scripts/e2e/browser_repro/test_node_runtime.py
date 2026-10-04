# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Real one-shot Node/launcher identity tests, not sandbox acceptance tests."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from run import NODE_IDENTITY, copy_node_runtime, isolated_environment, node_identity


class NodeRuntimeTests(unittest.TestCase):
    def test_launcher_resolution_copies_and_executes_the_actual_native_runtime(self):
        selected = shutil.which("node")
        if not selected:
            self.skipTest("installed Node is required for the real executable identity oracle")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = isolated_environment(root)

            def observe(executable):
                # Bounded, generated one-shot program. This does not exercise or
                # bypass Process's separate supervised-child capability gate.
                return subprocess.run([str(executable), "-p", NODE_IDENTITY], cwd=root,
                                      env=env, check=True, capture_output=True, text=True,
                                      timeout=5).stdout.strip()

            native = node_identity(observe(selected))
            launcher = root / "version-manager-launcher"
            launcher.write_text("#!/bin/sh\nexec " + shlex.quote(native["exec_path"]) + ' "$@"\n')
            launcher.chmod(0o750)
            shim = root / "node"
            shim.symlink_to(launcher)
            observed = node_identity(observe(shim))
            self.assertEqual(observed, native)
            self.assertNotEqual(Path(observed["exec_path"]), shim.resolve())
            destination = root / "node-runtime"
            hashes = copy_node_runtime(observed, destination)
            self.assertEqual(hashes["source_sha256"], hashes["copied_sha256"])
            with destination.open("rb") as stream:
                self.assertEqual(stream.read(4), b"\x7fELF")
            self.assertEqual(destination.stat().st_mode & 0o777, 0o750)
            self.assertEqual(node_identity(observe(destination)),
                             {"exec_path": str(destination), "version": native["version"]})
            # The old Path(selected).resolve() copy chooses this shell launcher.
            # It cannot satisfy the native-byte assertion, despite a valid version.
            self.assertTrue(shim.resolve().read_bytes().startswith(b"#!/bin/sh"))
            old_copy = root / "old-node-runtime"
            shutil.copyfile(shim.resolve(), old_copy)
            old_copy.chmod(0o750)
            self.assertNotEqual(node_identity(observe(old_copy))["exec_path"], str(old_copy))

    def test_identity_rejects_old_non_native_missing_and_ambiguous_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "launcher"
            script.write_text("#!/bin/sh\nexit 0\n")
            script.chmod(0o750)
            valid_shape = {"execPath": str(script), "version": "22.0.0", "release": "node"}
            invalid = ["not-json", "[]", "x" * 4097]
            for override in ({}, {"version": "20.0.0"}, {"version": "22garbage"},
                             {"version": None}, {"release": "other"},
                             {"execPath": "relative/node"}, {"execPath": None},
                             {"execPath": str(script.parent / "absent")}):
                invalid.append(json.dumps({**valid_shape, **override}))
            for output in invalid:
                with self.subTest(output=output[:80]), self.assertRaises(RuntimeError):
                    node_identity(output)
            script.chmod(0o600)
            self.assertFalse(os.access(script, os.X_OK))
            with self.assertRaises(RuntimeError):
                node_identity(json.dumps(valid_shape))


if __name__ == "__main__":
    unittest.main()
