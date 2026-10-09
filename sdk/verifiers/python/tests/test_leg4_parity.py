# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for review findings on the receipt-group verifiers."""

from __future__ import annotations

import io
import json
import types
import zipfile
from pathlib import Path
from typing import Any

import pytest

from pipelock_aarp_verify import group as group_module
from pipelock_aarp_verify import recovery
from pipelock_aarp_verify.cli import _run_chain
from pipelock_aarp_verify.group import (
    ACTION_ENTRY_TYPE,
    EVIDENCE_ENTRY_TYPE,
    GroupVerificationError,
    _committed_action_receipts,
    _read_session_evidence,
    _record_hash,
    _require_canonical_utc,
    verify_receipt_group,
)
from pipelock_aarp_verify.line_space import trim_go_space_bytes

FIXTURES = Path(__file__).parent / "fixtures" / "receipt-groups.zip"
V2_CORPUS = Path(__file__).parent / "fixtures" / "receipt-groups-v2.zip"
MIB = 1024 * 1024


class _FakeShard:
    """A shard file that reports a size and refuses to be read past a bound."""

    def __init__(self, name: str, size: int, content: bytes, readable: bool) -> None:
        self.name = name
        self._size = size
        self._content = content
        self._readable = readable
        self.reads = 0

    def stat(self) -> types.SimpleNamespace:
        return types.SimpleNamespace(st_size=self._size)

    def read_bytes(self) -> bytes:
        self.reads += 1
        assert self._readable, f"{self.name} was read into memory past the total bound"
        return self._content


def _recorder_line(session: str, seq: int, prior: str) -> tuple[bytes, str]:
    entry: dict[str, Any] = {
        "v": 1,
        "seq": seq,
        "ts": "2026-01-01T00:00:00Z",
        "session_id": session,
        "trace_id": "t",
        "type": "decision",
        "transport": "",
        "summary": "",
        "detail": {},
        "prev_hash": prior,
    }
    entry["hash"] = _record_hash(entry, b"{}")
    return (json.dumps(entry, separators=(",", ":")) + "\n").encode(), entry["hash"]


def test_session_evidence_total_is_bounded_before_the_next_file_is_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first_line, first_hash = _recorder_line("s", 0, "genesis")
    second_line, _ = _recorder_line("s", 1, first_hash)
    first = _FakeShard("evidence-s-0.jsonl", 100 * MIB, first_line, True)
    second = _FakeShard("evidence-s-1.jsonl", 100 * MIB, second_line, False)
    monkeypatch.setattr(
        group_module, "_session_evidence_paths", lambda *_: [(0, first), (1, second)]
    )
    monkeypatch.setattr(
        group_module,
        "_open_evidence_file",
        lambda shard: io.BytesIO(shard.read_bytes()),
    )
    with pytest.raises(GroupVerificationError, match="oversized"):
        _read_session_evidence(tmp_path, "s", False, True)
    assert first.reads == 1
    assert second.reads == 0


def test_session_evidence_within_the_total_bound_still_reads_every_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first_line, first_hash = _recorder_line("s", 0, "genesis")
    second_line, _ = _recorder_line("s", 1, first_hash)
    first = _FakeShard("evidence-s-0.jsonl", 60 * MIB, first_line, True)
    second = _FakeShard("evidence-s-1.jsonl", 60 * MIB, second_line, True)
    monkeypatch.setattr(
        group_module, "_session_evidence_paths", lambda *_: [(0, first), (1, second)]
    )
    monkeypatch.setattr(
        group_module,
        "_open_evidence_file",
        lambda shard: io.BytesIO(shard.read_bytes()),
    )
    _, parts, entries, _ = _read_session_evidence(tmp_path, "s", False, True)
    assert len(parts) == 2 and len(entries) == 2


def test_committed_tail_is_selected_by_recorder_entry_type_only() -> None:
    # Three action_receipt entries; the middle detail claims the v2 record_type.
    entries = [
        {"type": ACTION_ENTRY_TYPE, "detail": {"record_type": "action_receipt_v1"}},
        {"type": ACTION_ENTRY_TYPE, "detail": {"record_type": "evidence_receipt_v2"}},
        {"type": ACTION_ENTRY_TYPE, "detail": {"record_type": "action_receipt_v1"}},
        {"type": EVIDENCE_ENTRY_TYPE, "detail": {"record_type": "action_receipt_v1"}},
    ]
    action = [{"n": 0}, {"n": 1}, {"n": 2}]
    assert _committed_action_receipts(entries, action) == action
    assert _committed_action_receipts(entries[:2], action) == action[:2]
    assert _committed_action_receipts([], action) == []


def test_predecessor_close_is_read_once_and_the_validated_copy_is_used(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with zipfile.ZipFile(V2_CORPUS) as archive:
        archive.extractall(tmp_path)
    case = next(
        item
        for item in json.loads((tmp_path / "cases.json").read_text())
        if item["name"] == "v2-successor-closed-predecessor"
    )
    directory = tmp_path / "cases" / case["name"]
    predecessor = next(
        path.name.split("-")[2]
        for path in directory.glob("receipt-group-*-close.json")
        if case["group_id"] not in path.name
    )
    real = group_module._strict_artifact
    close_reads: list[str] = []

    def counting(path: Path, kind: str) -> Any:
        if path.name == f"receipt-group-{predecessor}-close.json":
            close_reads.append(path.name)
        return real(path, kind)

    monkeypatch.setattr(group_module, "_strict_artifact", counting)
    result = verify_receipt_group(directory, case["group_id"], case["trusted_keys"])
    assert result["verdict"] == "GROUP_VALID", result
    # Two shards would add two more reads if each loop iteration re-read it.
    assert len(close_reads) <= 2, close_reads


def test_go_space_trim_never_raises_on_invalid_utf8() -> None:
    assert trim_go_space_bytes(b"\xff\xfe  ") == b"\xff\xfe"
    assert trim_go_space_bytes(b"\xe2\x80\x83abc\xff\xe2\x80\x83") == b"abc\xff"
    assert trim_go_space_bytes(b" \t{}\n") == b"{}"
    assert trim_go_space_bytes("　é　".encode()) == "é".encode()


def test_chain_line_with_invalid_utf8_is_a_fatal_verdict_not_a_traceback() -> None:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = _run_chain(stdout, stderr, b'{"a":"\xff"}\n', json_mode=True)
    assert code != 0
    assert json.loads(stdout.getvalue())["envelope_fatal"] is True


def _recovery_seal(tmp_path: Path) -> tuple[dict[str, Any], set[str]]:
    with zipfile.ZipFile(FIXTURES) as archive:
        name = next(
            entry
            for entry in archive.namelist()
            if entry.startswith("group-recovery-successor/chain-link-")
        )
        seal = recovery._strict_seal(archive.read(name))
    return seal, {seal["successor_signer_key"]}


def test_recovery_seal_control_validates(tmp_path: Path) -> None:
    seal, trusted = _recovery_seal(tmp_path)
    recovery._validate(seal, trusted)


def test_recovery_seal_rejects_float_version(tmp_path: Path) -> None:
    seal, trusted = _recovery_seal(tmp_path)
    seal["version"] = 1.0
    with pytest.raises(recovery.RecoverySealError, match="kind or version"):
        recovery._validate(seal, trusted)


@pytest.mark.parametrize(
    "stamp",
    [
        "٢٠٢٦-٠١-٠١T٠٠:٠٠:٠٠Z",
        "2026-01-01T00:00:00.5٠Z",
    ],
)
def test_canonical_utc_accepts_ascii_digits_only(stamp: str, tmp_path: Path) -> None:
    with pytest.raises(GroupVerificationError):
        _require_canonical_utc(stamp, "closed_at")
    seal, trusted = _recovery_seal(tmp_path)
    seal["observed_at"] = stamp
    with pytest.raises(recovery.RecoverySealError):
        recovery._validate(seal, trusted)
    _require_canonical_utc("2026-01-01T00:00:00.5Z", "closed_at")


def test_session_open_null_group_binding_is_an_ungrouped_session() -> None:
    # Go decodes a null pointer field as absent; Rust and TypeScript agree.
    from pipelock_aarp_verify.receipt import ReceiptError, _validate_session_open

    base = {
        "run_nonce": "0" * 32,
        "open_nonce": "n",
        "recorder_session": "proxy",
        "signer_key_epoch": "0",
        "heartbeat_seconds": 30,
        "chain_open_seq": 0,
    }
    _validate_session_open(dict(base))
    _validate_session_open(dict(base, group_binding=None))
    with pytest.raises(ReceiptError):
        _validate_session_open(dict(base, group_binding=[]))


class _GrowingSource(io.BytesIO):
    """A file that grew after its stat: read() returns more than stat said."""

    def __init__(self, content: bytes) -> None:
        super().__init__(content)
        self.requested: list[int] = []

    def read(self, size: int | None = -1) -> bytes:
        self.requested.append(-1 if size is None else size)
        return super().read(size)


@pytest.mark.parametrize("include_bytes", [True, False])
def test_session_evidence_read_is_bounded_when_a_file_grows_after_stat(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, include_bytes: bool
) -> None:
    line, _ = _recorder_line("s", 0, "genesis")
    shard = _FakeShard("evidence-s-0.jsonl", len(line), line, True)
    grown = _GrowingSource(line + b"x" * 4096)
    monkeypatch.setattr(group_module, "_MAX_SHARD_BYTES", 1024)
    monkeypatch.setattr(
        group_module, "_session_evidence_paths", lambda *_: [(0, shard)]
    )
    monkeypatch.setattr(group_module, "_open_evidence_file", lambda _path: grown)
    with pytest.raises(GroupVerificationError, match="oversized"):
        _read_session_evidence(tmp_path, "s", False, include_bytes)
    assert grown.requested and all(0 <= n <= 1025 for n in grown.requested)


def test_writer_probe_refuses_a_lock_swapped_before_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    checked = tmp_path / "writer-s.lock"
    checked.write_bytes(b"")
    swapped = tmp_path / "other.lock"
    swapped.write_bytes(b"")
    real_open = recovery.os.open
    monkeypatch.setattr(
        recovery.os, "open", lambda _path, flags, *a: real_open(swapped, flags, *a)
    )
    with pytest.raises(recovery.RecoverySealError, match="changed during open"):
        recovery.require_writer_gone(tmp_path, "s")


def _two_file_inventory(
    monkeypatch: pytest.MonkeyPatch, budget_slack: int
) -> tuple[bytes, bytes]:
    first_line, first_hash = _recorder_line("s", 0, "genesis")
    second_line, _ = _recorder_line("s", 1, first_hash)
    first = _FakeShard("evidence-s-0.jsonl", len(first_line), first_line, True)
    second = _FakeShard("evidence-s-1.jsonl", len(second_line), second_line, True)
    monkeypatch.setattr(
        group_module, "_session_evidence_paths", lambda *_: [(0, first), (1, second)]
    )
    monkeypatch.setattr(
        group_module,
        "_open_evidence_file",
        lambda shard: io.BytesIO(shard.read_bytes()),
    )
    monkeypatch.setattr(
        group_module,
        "_MAX_INVENTORY_SESSION_BYTES",
        len(first_line) + len(second_line) + budget_slack,
    )
    return first_line, second_line


def test_inventory_session_total_is_bounded_across_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Decoded entries from every file stay in memory, so the inventory session
    # as a whole is capped, not each file on its own.
    _two_file_inventory(monkeypatch, -1)
    with pytest.raises(GroupVerificationError, match="in-memory limit"):
        _read_session_evidence(tmp_path, "s", False, False)


def test_inventory_session_within_the_total_bound_reads_every_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _two_file_inventory(monkeypatch, 0)
    _, _, entries, _ = _read_session_evidence(tmp_path, "s", False, False)
    assert len(entries) == 2
