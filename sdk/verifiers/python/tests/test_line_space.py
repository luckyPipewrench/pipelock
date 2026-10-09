# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

import pytest

from pipelock_aarp_verify.line_space import trim_go_space
from pipelock_aarp_verify.receipt import ReceiptError, load_evidence_chain


def test_shared_go_evidence_line_whitespace_vectors() -> None:
    path = (
        Path(__file__).resolve().parents[3]
        / "conformance/testdata/receipt-line-whitespace.json"
    )
    vectors = json.loads(path.read_text())["vectors"]
    assert len(vectors) == 93
    for vector in vectors:
        trimmed = trim_go_space(vector["line"])
        if not trimmed:
            outcome = "skip"
        else:
            try:
                json.loads(trimmed)
            except json.JSONDecodeError:
                outcome = "reject"
            else:
                outcome = "parse"
        assert outcome == vector["expected"], vector["name"]


def test_single_chain_reader_uses_go_space_not_python_strip(tmp_path: Path) -> None:
    base = (
        Path(__file__).resolve().parents[3]
        / "conformance/testdata/g1-valid-chain.jsonl"
    ).read_bytes()
    path = tmp_path / "evidence.jsonl"
    expected_count = len(
        load_evidence_chain(
            Path(__file__).resolve().parents[3]
            / "conformance/testdata/g1-valid-chain.jsonl"
        )
    )
    path.write_bytes("\u0085".encode() + base)
    assert len(load_evidence_chain(path)) == expected_count
    path.write_bytes("\u0085\n".encode() + base)
    assert len(load_evidence_chain(path)) == expected_count
    path.write_bytes(b"\x1c" + base)
    with pytest.raises(ReceiptError):
        load_evidence_chain(path)
    path.write_bytes(b"\x1c\n" + base)
    with pytest.raises(ReceiptError):
        load_evidence_chain(path)
