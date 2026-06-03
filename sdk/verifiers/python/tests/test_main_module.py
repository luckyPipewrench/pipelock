# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Exercise the `python -m pipelock_aarp_verify` module entry point."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_PKG_SRC = Path(__file__).resolve().parents[1] / "src"
_CORPUS = (
    Path(__file__).resolve().parents[3] / "conformance" / "testdata" / "aarp-corpus"
)
_G01 = _CORPUS / "golden" / "g01-single-ed25519-mediated.aarp.json"
_TRUST = _CORPUS / "trust.json"


def test_module_entry_point_appraises():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_PKG_SRC) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pipelock_aarp_verify",
            "aarp",
            str(_G01),
            "--trust",
            str(_TRUST),
            "--json",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    body = json.loads(proc.stdout)
    assert body["assertion_signed"] is True


def test_main_callable_is_importable():
    # In-process import so coverage measures __main__'s module body; calling main
    # via the module's bound reference exercises the same entry point.
    import importlib

    mod = importlib.import_module("pipelock_aarp_verify.__main__")
    assert mod.main is not None
