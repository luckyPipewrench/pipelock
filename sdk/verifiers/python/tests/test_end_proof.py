# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

import pytest

from pipelock_aarp_verify.cli import main

ROOT = Path(__file__).resolve().parents[3] / "conformance/testdata/end-proof"
FIXTURE = json.loads((ROOT / "expect.json").read_text())


@pytest.mark.parametrize("cell", FIXTURE["cases"], ids=lambda c: c["name"])
@pytest.mark.parametrize("json_mode", [False, True])
def test_end_proof(cell, json_mode, capsys):
    args = ["receipt", str(ROOT / cell["file"]), "--chain", "--key", FIXTURE["key"]]
    args += cell["flags"]
    if json_mode:
        args.append("--json")
    code = main(args)
    out, err = capsys.readouterr()
    assert code == cell["exit"], out + err
    if json_mode:
        report = json.loads(out)
        assert report["status"] == cell["status"]
        assert report["end_proof"]["proven"] == cell["proven"]
        assert report["scope"] == "receipt_chain"
        assert report["integrity"] == ("invalid" if cell["exit"] == 1 else "valid")
    else:
        assert cell["status"] in out + err
