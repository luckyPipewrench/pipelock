# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
from pathlib import Path

import pytest

from pipelock_aarp_verify.receipt import (
    ReceiptError,
    load_receipt,
    verify_evidence_chain_file,
)


def test_receipt_rejects_oversized_input_before_parse(tmp_path):
    target = tmp_path / "receipt.json"
    with target.open("wb") as stream:
        stream.truncate((8 << 20) + 1)
    with pytest.raises(ReceiptError, match="exceeds"):
        load_receipt(target)


def test_signed_run_chain_larger_than_8_mib_verifies(tmp_path):
    root = Path(__file__).resolve().parents[3]
    fixture = (
        root
        / "conformance"
        / "testdata"
        / "run-chains"
        / "valid"
        / "evidence-proxy.run.03b13ee13e01e7f770480f62ea42f1fe-0.jsonl"
    )
    key = (
        root / "conformance" / "testdata" / "run-chains" / "signer-key.hex"
    ).read_text().strip()
    target = tmp_path / fixture.name
    target.write_bytes(fixture.read_bytes() + b"\r\n" * ((8 << 20) // 2 + 1))

    result = verify_evidence_chain_file(target, key)
    assert result["valid"] is True, result
    assert result["receipt_count"] == 5


def test_jsonl_reader_rejects_overlong_and_unsafe_files(tmp_path):
    from pipelock_aarp_verify.input_file import iter_verifier_jsonl_lines

    overlong = tmp_path / "overlong.jsonl"
    overlong.write_bytes(b" " * ((1 << 20) + 1) + b"\r\n")
    with pytest.raises(OSError, match="recorder entry limit"):
        list(iter_verifier_jsonl_lines(overlong))

    non_regular = tmp_path / "directory.jsonl"
    non_regular.mkdir()
    with pytest.raises(OSError, match="regular file"):
        list(iter_verifier_jsonl_lines(non_regular))


@pytest.mark.skipif(os.name != "posix", reason="Unix ctime semantics are required")
def test_jsonl_reader_detects_same_inode_rewrite_with_mtime_restored(tmp_path):
    from pipelock_aarp_verify.input_file import iter_verifier_jsonl_lines

    target = tmp_path / "changed.jsonl"
    target.write_bytes(b"first\nsecond\n")
    lines = iter_verifier_jsonl_lines(target)
    assert next(lines) == b"first\n"
    before = target.stat()
    target.write_bytes(b"other\nsecond\n")
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))

    with pytest.raises(OSError, match="changed while reading"):
        list(lines)


def test_jsonl_change_takes_precedence_over_parse_error(tmp_path, monkeypatch):
    from pipelock_aarp_verify import receipt

    target = tmp_path / "malformed.jsonl"
    target.write_text("not-json\nsecond\n")
    original = receipt.parse_json_strict

    def mutate_then_parse(raw):
        target.write_text("bad-json\nsecond\n")
        return original(raw)

    monkeypatch.setattr(receipt, "parse_json_strict", mutate_then_parse)
    with pytest.raises(OSError, match="changed while reading"):
        receipt.load_evidence_chain(target)


def test_jsonl_path_replacement_takes_precedence_over_parse_error(tmp_path, monkeypatch):
    from pipelock_aarp_verify import receipt

    target = tmp_path / "malformed.jsonl"
    replacement = tmp_path / "replacement.jsonl"
    target.write_text("not-json\nsecond\n")
    replacement.write_text("replacement\n")
    original = receipt.parse_json_strict

    def replace_then_parse(raw):
        os.replace(replacement, target)
        return original(raw)

    monkeypatch.setattr(receipt, "parse_json_strict", replace_then_parse)
    with pytest.raises(OSError, match="changed while reading"):
        receipt.load_evidence_chain(target)


def test_jsonl_stream_stops_at_initial_size_when_file_is_appended(tmp_path):
    from pipelock_aarp_verify.input_file import iter_verifier_jsonl_lines

    target = tmp_path / "appended.jsonl"
    target.write_bytes(b"first\nsecond\n")
    lines = iter_verifier_jsonl_lines(target)
    assert next(lines) == b"first\n"
    with target.open("ab") as stream:
        stream.write(b"later\n")
    observed = []
    with pytest.raises(OSError, match="changed while reading"):
        for line in lines:
            observed.append(line)
    assert observed == [b"second\n"], "appended entries must not enter the snapshot"
