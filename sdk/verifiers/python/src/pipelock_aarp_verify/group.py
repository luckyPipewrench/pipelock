# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Verifier for signed multi-chain receipt groups."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .ael import AELVerificationError, verify_ael_run
from .canonical import CanonicalizeError
from .line_space import trim_go_space
from .number import (
    BadGrammarError,
    StrictParseError,
    UnsafeNumberError,
    enforce_cross_language_number_range,
    parse_json_strict,
)
from .rawjson import SourcedReceipt, object_member_span, recorder_line_ext_bytes
from .receipt import (
    ACTION_ENTRY_TYPE,
    EVIDENCE_ENTRY_TYPE,
    ReceiptError,
    _reject_duplicate_pairs,
    receipt_hash,
    verify_evidence_chain,
)
from .recovery import RecoverySealError, require_writer_gone, verify_recovery_seal
from .timestamp import validate_timestamp

GROUP_VALID = "GROUP_VALID"
GROUP_INCOMPLETE = "GROUP_INCOMPLETE"
GROUP_INVALID = "GROUP_INVALID"
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_ARTIFACT = 128 * 1024
_MAX_LINE = 1 << 20
_DOMAINS = {
    "open": "pipelock/receipt-group-open/v1",
    "close": "pipelock/receipt-group-close/v1",
    "transition": "pipelock/receipt-group-transition/v1",
}


def _go_blank_line(text: str) -> bool:
    return trim_go_space(text) == ""


class GroupVerificationError(ValueError):
    """A group artifact, membership, or shard failed verification."""


def _exists_nofollow(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _go_json(value: Any) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    raw = raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    raw = raw.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return raw.encode("utf-8")


def _strict_artifact(path: Path, kind: str) -> tuple[dict[str, Any], bytes]:
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size <= 0
            or info.st_size > _MAX_ARTIFACT
        ):
            raise GroupVerificationError("invalid receipt group artifact file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if not os.path.samestat(info, opened):
                raise GroupVerificationError(
                    "receipt group artifact changed during open"
                )
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(_MAX_ARTIFACT + 1)
        finally:
            os.close(fd)
        after = path.stat()
    except OSError as exc:
        raise GroupVerificationError(f"read receipt group {kind}: {exc}") from exc
    if (
        len(raw) > _MAX_ARTIFACT
        or not os.path.samestat(info, after)
        or info.st_mtime_ns != after.st_mtime_ns
    ):
        raise GroupVerificationError(
            "receipt group artifact changed during verification"
        )
    try:
        text = raw.decode("utf-8", errors="strict")
        enforce_cross_language_number_range(parse_json_strict(text))
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ReceiptError,
        StrictParseError,
        UnsafeNumberError,
    ) as exc:
        raise GroupVerificationError(
            f"invalid receipt group {kind} JSON: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise GroupVerificationError(f"receipt group {kind} must be an object")
    if _published_artifact(value, kind) != raw:
        raise GroupVerificationError(
            f"receipt group {kind} is not canonical published JSON"
        )
    return value, raw


def _ordered(value: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise GroupVerificationError("receipt group fields differ from schema")
    return {field: value[field] for field in fields}


_OPEN_FIELDS = (
    "version",
    "kind",
    "group_id",
    "base_session",
    "shard_count",
    "process_shard_index",
    "signer_key",
    "shards",
    "previous_group_id",
    "previous_open_manifest_sha256",
    "created_at",
    "signature",
)
_CLOSE_FIELDS = (
    "version",
    "kind",
    "group_id",
    "open_manifest_sha256",
    "status",
    "shards",
    "closed_at",
    "signer_key",
    "signature",
)
_TRANSITION_FIELDS = (
    "version",
    "kind",
    "new_group_id",
    "new_open_manifest_sha256",
    "previous_group_id",
    "previous_open_manifest_sha256",
    "previous_close_manifest_sha256",
    "predecessors",
    "created_at",
    "signer_key",
    "signature",
)
_OPEN_SHARD_FIELDS = ("shard_index", "session_id")
_CLOSE_SHARD_FIELDS = (
    "shard_index",
    "session_id",
    "final_chain_seq",
    "final_chain_hash",
    "receipt_count",
    "session_close_hash",
    "transcript_root_hash",
    "checkpoint_hash",
    "native_ael_final_seq",
    "native_ael_final_hash",
    "native_ael_record_count",
)
_PRED_FIELDS = (
    "shard_index",
    "session_id",
    "final_chain_seq",
    "final_chain_hash",
    "recovery_seal_sha256",
)


def _published_artifact(value: dict[str, Any], kind: str) -> bytes:
    fields = {
        "open": _OPEN_FIELDS,
        "close": _CLOSE_FIELDS,
        "transition": _TRANSITION_FIELDS,
    }[kind]
    ordered = _ordered(value, fields)
    list_name = "shards" if kind in {"open", "close"} else "predecessors"
    subfields = (
        _OPEN_SHARD_FIELDS
        if kind == "open"
        else (_CLOSE_SHARD_FIELDS if kind == "close" else _PRED_FIELDS)
    )
    if not isinstance(ordered[list_name], list):
        raise GroupVerificationError("receipt group member list is invalid")
    ordered[list_name] = [_ordered(item, subfields) for item in ordered[list_name]]
    return _go_json(ordered)


def _signing_bytes(value: dict[str, Any], kind: str) -> bytes:
    unsigned = dict(value)
    unsigned.pop("signature", None)
    # Keep the group wire struct order after removing the signature field.
    fields = {
        "open": _OPEN_FIELDS,
        "close": _CLOSE_FIELDS,
        "transition": _TRANSITION_FIELDS,
    }[kind]
    unsigned_fields = tuple(field for field in fields if field != "signature")
    ordered = _ordered(unsigned, unsigned_fields)
    list_name = "shards" if kind in {"open", "close"} else "predecessors"
    subfields = (
        _OPEN_SHARD_FIELDS
        if kind == "open"
        else (_CLOSE_SHARD_FIELDS if kind == "close" else _PRED_FIELDS)
    )
    ordered[list_name] = [_ordered(item, subfields) for item in ordered[list_name]]
    return _DOMAINS[kind].encode() + _go_json(ordered)


def _verify_signature(value: dict[str, Any], kind: str, trusted: set[str]) -> None:
    signer = value.get("signer_key")
    signature = value.get("signature")
    if (
        not isinstance(signer, str)
        or not _HEX64.fullmatch(signer)
        or signer not in trusted
    ):
        raise GroupVerificationError("receipt group signer is not a pinned trusted key")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise GroupVerificationError("invalid receipt group signature encoding")
    try:
        sig, pub = bytes.fromhex(signature[8:]), bytes.fromhex(signer)
        if len(sig) != 64 or len(pub) != 32:
            raise ValueError("wrong signature or public key length")
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, _signing_bytes(value, kind))
    except (ValueError, InvalidSignature) as exc:
        raise GroupVerificationError(
            "receipt group signature verification failed"
        ) from exc


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require_canonical_utc(value: Any, field: str) -> None:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", value)
        or re.search(r"\.\d*0Z$", value)
    ):
        raise GroupVerificationError(
            f"receipt group {field} is not canonical UTC RFC3339Nano"
        )


def _validate_open(opening: dict[str, Any], group_id: str) -> None:
    if (
        opening.get("version") != 1
        or opening.get("kind") != "receipt_group_open"
        or opening.get("group_id") != group_id
        or not _HEX32.fullmatch(group_id)
    ):
        raise GroupVerificationError("invalid receipt group opening identity")
    base = opening.get("base_session")
    count, shards = opening.get("shard_count"), opening.get("shards")
    if (
        not isinstance(base, str)
        or not base
        or "/" in base
        or "\\" in base
        or ".run." in base
    ):
        raise GroupVerificationError("invalid receipt group base session")
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or count < 2
        or count > 32
        or not isinstance(shards, list)
        or len(shards) != count
    ):
        raise GroupVerificationError("invalid receipt group shard count")
    process_index = opening.get("process_shard_index")
    if (
        not isinstance(process_index, int)
        or isinstance(process_index, bool)
        or not 0 <= process_index < count
    ):
        raise GroupVerificationError("invalid receipt group process shard index")
    seen: set[str] = set()
    for index, shard in enumerate(shards):
        _ordered(shard, _OPEN_SHARD_FIELDS)
        sid = shard["session_id"]
        if (
            shard["shard_index"] != index
            or not isinstance(sid, str)
            or not re.fullmatch(re.escape(base) + r"\.run\.[0-9a-f]{32}", sid)
            or sid in seen
        ):
            raise GroupVerificationError(
                "duplicate or invalid receipt group shard member"
            )
        seen.add(sid)
    previous_id = opening.get("previous_group_id")
    previous_hash = opening.get("previous_open_manifest_sha256")
    if (previous_id == "") != (previous_hash == ""):
        raise GroupVerificationError("receipt group predecessor pair is incomplete")
    if previous_id and (
        not isinstance(previous_id, str)
        or not _HEX32.fullmatch(previous_id)
        or not isinstance(previous_hash, str)
        or not _HEX64.fullmatch(previous_hash)
        or previous_id == group_id
    ):
        raise GroupVerificationError("invalid receipt group predecessor binding")
    try:
        validate_timestamp(opening.get("created_at", ""))
    except (TypeError, ValueError) as exc:
        raise GroupVerificationError("invalid receipt group created_at") from exc
    _require_canonical_utc(opening["created_at"], "created_at")
    if not isinstance(opening.get("signer_key"), str) or not _HEX64.fullmatch(
        opening["signer_key"]
    ):
        raise GroupVerificationError("invalid receipt group signer key")


def _validate_close(
    closed: dict[str, Any], opening: dict[str, Any], open_hash: str, trusted: set[str]
) -> None:
    _verify_signature(closed, "close", trusted)
    if (
        closed.get("version") != 1
        or closed.get("kind") != "receipt_group_close"
        or closed.get("status") != "complete"
        or closed.get("group_id") != opening["group_id"]
        or closed.get("open_manifest_sha256") != open_hash
        or closed.get("signer_key") != opening["signer_key"]
    ):
        raise GroupVerificationError(
            "receipt group close does not bind opening manifest"
        )
    try:
        validate_timestamp(closed.get("closed_at", ""))
    except (TypeError, ValueError) as exc:
        raise GroupVerificationError("invalid receipt group closed_at") from exc
    _require_canonical_utc(closed["closed_at"], "closed_at")
    shards = closed.get("shards")
    if not isinstance(shards, list) or len(shards) != len(opening["shards"]):
        raise GroupVerificationError("receipt group close shard membership differs")
    for index, shard in enumerate(shards):
        _ordered(shard, _CLOSE_SHARD_FIELDS)
        if (
            shard.get("shard_index") != index
            or shard.get("session_id") != opening["shards"][index]["session_id"]
        ):
            raise GroupVerificationError(
                "receipt group close has duplicate or mismatched shard"
            )
        for field in (
            "final_chain_hash",
            "session_close_hash",
            "transcript_root_hash",
            "checkpoint_hash",
            "native_ael_final_hash",
        ):
            if not isinstance(shard.get(field), str) or not _HEX64.fullmatch(
                shard[field]
            ):
                raise GroupVerificationError(f"invalid receipt group close {field}")
        for field in (
            "final_chain_seq",
            "receipt_count",
            "native_ael_final_seq",
            "native_ael_record_count",
        ):
            value = shard.get(field)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                or value > (1 << 53) - 1
            ):
                raise GroupVerificationError(f"invalid receipt group close {field}")


def _validate_predecessor_claim(
    claim: dict[str, Any], index: int, session: str
) -> None:
    _ordered(claim, _PRED_FIELDS)
    seq = claim["final_chain_seq"]
    if (
        not isinstance(seq, int)
        or isinstance(seq, bool)
        or not 0 <= seq <= (1 << 53) - 1
    ):
        raise GroupVerificationError(
            f"receipt group transition predecessor shard {index} sequence is invalid"
        )
    if not isinstance(claim["final_chain_hash"], str) or not _HEX64.fullmatch(
        claim["final_chain_hash"]
    ):
        raise GroupVerificationError(
            f"receipt group transition predecessor shard {index} hash is invalid"
        )
    seal_hash = claim["recovery_seal_sha256"]
    if not isinstance(seal_hash, str) or (
        seal_hash and not _HEX64.fullmatch(seal_hash)
    ):
        raise GroupVerificationError(
            f"receipt group transition predecessor shard {index} seal digest is invalid"
        )
    if claim["shard_index"] != index or claim["session_id"] != session:
        raise GroupVerificationError(
            "receipt group transition has mismatched predecessor shard"
        )


def _record_hash(entry: dict[str, Any], detail_raw: bytes) -> str:
    version = entry.get("v")
    fields: list[str] = [
        str(version),
        str(entry.get("seq")),
        entry.get("ts", ""),
        entry.get("session_id", ""),
    ]
    if version == 3:
        fields.extend(
            (entry.get("chain_kind", ""), entry.get("writer_instance_id", ""))
        )
    fields.extend((entry.get("trace_id", ""), entry.get("type", "")))
    if version in (2, 3):
        fields.append(entry.get("event_kind", ""))
    fields.extend(
        (
            entry.get("transport", ""),
            entry.get("summary", ""),
            detail_raw.decode("utf-8"),
            entry.get("raw_ref", ""),
            entry.get("prev_hash", ""),
        )
    )
    return hashlib.sha256(
        b"\x00".join(str(value).encode("utf-8") for value in fields)
    ).hexdigest()


def _verify_checkpoints(entries: list[dict[str, Any]], pub: bytes) -> str:
    key = Ed25519PublicKey.from_public_bytes(pub)
    last_hash = ""
    for entry in entries:
        if entry.get("type") != "checkpoint":
            continue
        detail = entry.get("detail")
        signature = detail.get("signature") if isinstance(detail, dict) else None
        if not isinstance(signature, str):
            raise GroupVerificationError("group checkpoint lacks a signature")
        try:
            key.verify(bytes.fromhex(signature), entry.get("prev_hash", "").encode())
        except (ValueError, InvalidSignature) as exc:
            raise GroupVerificationError(
                "group checkpoint signature verification failed"
            ) from exc
        last_hash = entry.get("hash", "")
    return last_hash


def _parse_evidence_filename(name: str) -> tuple[str, int] | None:
    """Match evidencename.Parse, including its legacy sequence-zero fallback."""
    if not name.startswith("evidence-") or not name.endswith(".jsonl"):
        return None
    stem = name[len("evidence-") : -len(".jsonl")]
    found_session, separator, start_text = stem.rpartition("-")
    if not separator:
        return None
    if start_text and all("0" <= char <= "9" for char in start_text):
        # A uint64 needs at most 20 digits once leading zeros are removed.
        trimmed = start_text.lstrip("0") or "0"
        if len(trimmed) <= 20:
            start = int(trimmed)
            if start <= (1 << 64) - 1:
                return found_session, start
    return found_session, 0


def _session_evidence_paths(directory: Path, session: str) -> list[tuple[int, Path]]:
    paths: list[tuple[int, Path]] = []
    for candidate in directory.glob("evidence-*.jsonl"):
        parsed = _parse_evidence_filename(candidate.name)
        if parsed is not None and parsed[0] == session:
            paths.append((parsed[1], candidate))
    paths.sort(key=lambda item: item[0])
    if len({start for start, _ in paths}) != len(paths):
        raise GroupVerificationError("ambiguous evidence shard sequence start")
    if any(path.is_symlink() or not path.is_file() for _, path in paths):
        raise GroupVerificationError("receipt session has unexpected file membership")
    return paths


def _read_session_evidence(
    directory: Path, session: str, recovered: bool, include_bytes: bool = False
) -> tuple[list[tuple[int, Path]], list[bytes], list[dict[str, Any]]]:
    paths = _session_evidence_paths(directory, session)
    if not paths:
        raise GroupVerificationError("receipt session evidence is missing")
    if paths[0][0] != 0:
        raise GroupVerificationError("receipt session inventory starts after genesis")
    entries: list[dict[str, Any]] = []
    parts: list[bytes] = []
    prior = "genesis"
    for file_index, (start, path) in enumerate(paths):
        if path.stat().st_size > 128 * 1024 * 1024 or start != len(entries):
            raise GroupVerificationError("receipt session inventory sequence mismatch")
        if include_bytes:
            part = path.read_bytes()
            parts.append(part)
            stream = io.BytesIO(part)
        else:
            stream = path.open("rb")
        before_count = len(entries)
        torn = False
        with stream:
            for line in stream:
                if len(line) > _MAX_LINE:
                    raise GroupVerificationError(
                        "invalid receipt session inventory line"
                    )
                if not line.endswith(b"\n"):
                    if recovered and file_index + 1 == len(paths):
                        torn = True
                        break
                    raise GroupVerificationError(
                        "receipt group session has a torn segment"
                    )
                text = line[:-1].decode("utf-8")
                if _go_blank_line(text):
                    continue
                text = trim_go_space(text)
                try:
                    enforce_cross_language_number_range(parse_json_strict(text))
                except (StrictParseError, UnsafeNumberError) as exc:
                    raise GroupVerificationError(
                        f"invalid receipt session inventory line: {exc}"
                    ) from exc
                entry = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
                if (
                    not isinstance(entry, dict)
                    or entry.get("session_id") != session
                    or entry.get("seq") != len(entries)
                    or entry.get("prev_hash") != prior
                ):
                    raise GroupVerificationError(
                        "receipt session inventory sequence mismatch"
                    )
                span = object_member_span(text, 0, "detail")
                if span is None:
                    raise GroupVerificationError(
                        "receipt session inventory lacks detail"
                    )
                prior = _record_hash(entry, text[span[0] : span[1]].encode("utf-8"))
                if entry.get("hash") != prior:
                    raise GroupVerificationError(
                        "receipt shard session inventory recorder hash mismatch"
                    )
                entries.append(entry)
        if len(entries) == before_count and not torn:
            raise GroupVerificationError("empty receipt session inventory file")
    if not entries:
        raise GroupVerificationError("empty receipt session inventory file")
    return paths, parts, entries


def _verify_shard(
    directory: Path,
    opening: dict[str, Any],
    open_hash: str,
    index: int,
    claimed: dict[str, Any] | None,
    incomplete: bool = False,
    allow_torn: bool = False,
) -> dict[str, Any]:
    member = opening["shards"][index]
    session_id = member["session_id"]
    paths, parts, _ = _read_session_evidence(directory, session_id, allow_torn, True)
    raw_file = b"".join(parts)
    if len(raw_file) > 128 * 1024 * 1024:
        raise GroupVerificationError("receipt group shard is oversized")
    torn = not parts[-1].endswith(b"\n")
    if torn and not allow_torn:
        raise GroupVerificationError("receipt group shard has a torn tail")
    complete_bytes = raw_file
    parse_bytes = raw_file
    damage_offset = 0
    complete_record_count: int | None = None
    if torn:
        last_boundary = parts[-1].rfind(b"\n") + 1
        suffix = parts[-1][last_boundary:]
        if not suffix or b"\x00" in suffix:
            raise GroupVerificationError("receipt group shard has an invalid torn tail")
        parse_bytes = raw_file[: len(raw_file) - len(suffix)]
        if len(suffix) > _MAX_LINE:
            raise GroupVerificationError("receipt group torn tail exceeds line limit")
        damage_offset = last_boundary
        complete_bytes = raw_file[: len(raw_file) - len(suffix)]
        if not complete_bytes.endswith(b"\n"):
            raise GroupVerificationError(
                "receipt group torn prefix has no complete line"
            )
    rows: list[tuple[dict[str, Any], bytes]] = []
    prior = "genesis"
    action: list[dict[str, Any]] = []
    v2: list[dict[str, Any]] = []
    for line_no, line in enumerate(parse_bytes[:-1].split(b"\n"), 1):
        if len(line) > _MAX_LINE:
            raise GroupVerificationError(f"shard line {line_no} is oversized")
        try:
            text = line.decode("utf-8")
            if _go_blank_line(text):
                continue
            text = trim_go_space(text)
            enforce_cross_language_number_range(parse_json_strict(text))
            entry = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
        except Exception as exc:
            raise GroupVerificationError(
                f"shard line {line_no} JSON invalid: {exc}"
            ) from exc
        if (
            not isinstance(entry, dict)
            or entry.get("session_id") != session_id
            or entry.get("seq") != len(rows)
            or entry.get("prev_hash") != prior
        ):
            raise GroupVerificationError(
                f"shard line {line_no} recorder sequence mismatch"
            )
        span = object_member_span(text, 0, "detail")
        if span is None:
            raise GroupVerificationError(f"shard line {line_no} lacks detail")
        detail_raw = text[span[0] : span[1]].encode("utf-8")
        computed = _record_hash(entry, detail_raw)
        if entry.get("hash") != computed:
            raise GroupVerificationError(f"shard line {line_no} recorder hash mismatch")
        prior = computed
        rows.append((entry, detail_raw))
        if entry.get("type") in {ACTION_ENTRY_TYPE, EVIDENCE_ENTRY_TYPE}:
            detail = entry.get("detail")
            if not isinstance(detail, dict):
                raise GroupVerificationError(
                    f"shard line {line_no} receipt detail invalid"
                )
            ext_bytes = recorder_line_ext_bytes(text)
            if ext_bytes is not None and "ext" in detail:
                detail = SourcedReceipt(detail, ext_bytes)
            (
                v2 if detail.get("record_type") == "evidence_receipt_v2" else action
            ).append(detail)
    entries = [row[0] for row in rows]
    if torn:
        complete_record_count = len(rows)
    if len(entries) < 3:
        raise GroupVerificationError(
            f"receipt group shard {index} lacks gate and session open"
        )
    expected_binding = {
        "group_id": opening["group_id"],
        "shard_index": index,
        "session_id": session_id,
        "open_manifest_sha256": open_hash,
        "signer_key": opening["signer_key"],
        "previous_group_id": opening["previous_group_id"],
        "previous_open_manifest_sha256": opening["previous_open_manifest_sha256"],
    }
    if (
        entries[0].get("type") != "receipt_group_v1"
        or entries[0].get("detail") != expected_binding
    ):
        raise GroupVerificationError(
            f"receipt group shard {index} gate differs from manifest"
        )
    if entries[1].get("type") != "checkpoint" or entries[1].get("prev_hash") != entries[
        0
    ].get("hash"):
        raise GroupVerificationError(
            f"receipt group shard {index} gate is not checkpointed"
        )
    checkpoint_hash = _verify_checkpoints(entries, bytes.fromhex(opening["signer_key"]))
    for receipts in (action, v2):
        if receipts:
            result = verify_evidence_chain(receipts, opening["signer_key"])
            if not result.get("valid"):
                raise GroupVerificationError(
                    f"receipt group shard {index} signed receipt chain failed: "
                    f"{result.get('error', 'invalid')}"
                )
    if not action:
        raise GroupVerificationError("group shard has no signed v1 session open")
    first_control = action[0].get("action_record", {}).get("session_control", {})
    open_record = (
        first_control.get("open")
        if first_control.get("kind") == "session_open"
        else None
    )
    if (
        not isinstance(open_record, dict)
        or open_record.get("recorder_session") != session_id
        or open_record.get("group_binding") != expected_binding
    ):
        raise GroupVerificationError(
            f"receipt group shard {index} signed open binding differs"
        )
    run_nonce = open_record.get("run_nonce")
    if not isinstance(run_nonce, str):
        raise GroupVerificationError("group session open lacks AEL run nonce")
    closes = [
        r
        for r in action
        if r.get("action_record", {}).get("session_control", {}).get("kind")
        == "session_close"
    ]
    roots = [e for e in entries if e.get("type") == "transcript_root"]
    if incomplete and (torn or (not closes and not roots)):
        if not action:
            raise GroupVerificationError(
                "group predecessor lacks a signed receipt tail"
            )
        committed_count = (
            complete_record_count if complete_record_count is not None else len(rows)
        )
        committed_entries = [row[0] for row in rows[:committed_count]]
        committed_v1_count = sum(
            1
            for entry in committed_entries
            if entry.get("type") in {ACTION_ENTRY_TYPE, EVIDENCE_ENTRY_TYPE}
            and isinstance(entry.get("detail"), dict)
            and entry["detail"].get("record_type") != "evidence_receipt_v2"
        )
        committed_action = action[:committed_v1_count]
        if not committed_entries or not committed_action:
            raise GroupVerificationError(
                "group predecessor lacks a durable receipt tail"
            )
        tail = committed_action[-1]
        tail_seq = tail.get("action_record", {}).get("chain_seq")
        if not isinstance(tail_seq, int) or isinstance(tail_seq, bool) or tail_seq < 0:
            raise GroupVerificationError(
                "group predecessor receipt tail sequence is invalid"
            )
        last = committed_entries[-1]
        return {
            "session_id": session_id,
            "final_chain_seq": tail_seq,
            "final_chain_hash": receipt_hash(tail),
            "last_good_seq": last["seq"],
            "last_good_hash": last["hash"],
            "torn": torn,
            "shard": paths[-1][1].name,
            "shard_size": len(parts[-1]),
            "shard_sha256": hashlib.sha256(parts[-1]).hexdigest(),
            "damage_offset": damage_offset,
            "session_open_hash": receipt_hash(action[0]),
            "session_open_signer": action[0].get("signer_key"),
        }
    try:
        ael = verify_ael_run(directory, run_nonce, opening["signer_key"])
    except AELVerificationError as exc:
        raise GroupVerificationError(
            f"receipt group shard {index} native AEL failed: {exc}"
        ) from exc
    if (
        len(closes) != 1
        or len(roots) != 1
        or not checkpoint_hash
        or entries[-1].get("type") != "checkpoint"
    ):
        raise GroupVerificationError(
            f"receipt group shard {index} lacks signed close, root, or final checkpoint"
        )
    close_receipt = closes[0]
    close_entry_index = next(
        (
            i
            for i, entry in enumerate(entries)
            if entry.get("type") in {ACTION_ENTRY_TYPE, EVIDENCE_ENTRY_TYPE}
            and entry.get("detail") == close_receipt
        ),
        -1,
    )
    root_index = entries.index(roots[0])
    if (
        close_entry_index < 0
        or root_index != close_entry_index + 1
        or root_index + 2 != len(entries)
        or entries[root_index + 1].get("type") != "checkpoint"
    ):
        raise GroupVerificationError(
            "group close must be followed by transcript root and final checkpoint"
        )
    close = close_receipt["action_record"]["session_control"].get("close")
    root = roots[0].get("detail")
    tail_hash = receipt_hash(close_receipt)
    tail_seq = close_receipt["action_record"].get("chain_seq")
    receipt_count = len(action)
    if (
        not isinstance(close, dict)
        or not isinstance(root, dict)
        or root.get("session_id") != session_id
        or root.get("final_seq") != tail_seq
        or root.get("root_hash") != tail_hash
        or root.get("receipt_count") != receipt_count
        or close.get("receipt_count") != receipt_count
    ):
        raise GroupVerificationError("shard transcript root differs from signed close")
    actual = {
        "shard_index": index,
        "session_id": session_id,
        "final_chain_seq": tail_seq,
        "final_chain_hash": tail_hash,
        "receipt_count": receipt_count,
        "session_close_hash": tail_hash,
        "transcript_root_hash": roots[0].get("hash"),
        "checkpoint_hash": checkpoint_hash,
        "native_ael_final_seq": ael["final_seq"],
        "native_ael_final_hash": ael["final_hash"],
        "native_ael_record_count": ael["record_count"],
        "session_open_hash": receipt_hash(action[0]),
        "session_open_signer": action[0].get("signer_key"),
    }
    if claimed is not None:
        for field, value in claimed.items():
            if actual.get(field) != value:
                raise GroupVerificationError(
                    f"receipt group shard {index} close head differs at {field}"
                )
    return actual


def _verify_successor_transition(
    directory: Path,
    opening: dict[str, Any],
    open_hash: str,
    trusted: set[str],
    check_inventory: bool = True,
) -> None:
    previous_id = opening["previous_group_id"]
    if not previous_id:
        return
    predecessor, prev_raw = _strict_artifact(
        directory / f"receipt-group-{previous_id}-open.json", "open"
    )
    _verify_signature(predecessor, "open", trusted)
    _validate_open(predecessor, previous_id)
    prev_hash = _digest(prev_raw)
    if prev_hash != opening["previous_open_manifest_sha256"]:
        raise GroupVerificationError("receipt group predecessor open digest differs")
    close_path = directory / f"receipt-group-{previous_id}-close.json"
    close_hash = ""
    if _exists_nofollow(close_path):
        old_close, old_close_raw = _strict_artifact(close_path, "close")
        _validate_close(old_close, predecessor, prev_hash, trusted)
        close_hash = _digest(old_close_raw)
    transition, _ = _strict_artifact(
        directory / f"receipt-group-{opening['group_id']}-transition.json", "transition"
    )
    _verify_signature(transition, "transition", trusted)
    if (
        transition.get("version") != 1
        or transition.get("kind") != "receipt_group_transition"
        or transition.get("signer_key") != opening["signer_key"]
        or transition.get("new_group_id") != opening["group_id"]
        or transition.get("new_open_manifest_sha256") != open_hash
        or transition.get("previous_group_id") != previous_id
        or transition.get("previous_open_manifest_sha256") != prev_hash
        or transition.get("previous_close_manifest_sha256") != close_hash
    ):
        raise GroupVerificationError(
            "receipt group transition does not bind predecessor and successor"
        )
    try:
        validate_timestamp(transition.get("created_at", ""))
    except (TypeError, ValueError) as exc:
        raise GroupVerificationError(
            "invalid receipt group transition timestamp"
        ) from exc
    _require_canonical_utc(transition["created_at"], "transition created_at")
    preds = transition.get("predecessors")
    if not isinstance(preds, list) or len(preds) != len(predecessor["shards"]):
        raise GroupVerificationError(
            "receipt group transition predecessor membership differs"
        )
    for i, pred in enumerate(preds):
        _validate_predecessor_claim(pred, i, predecessor["shards"][i]["session_id"])
        if close_hash:
            old_close, _ = _strict_artifact(close_path, "close")
            head = _verify_shard(
                directory, predecessor, prev_hash, i, old_close["shards"][i]
            )
            if (
                pred.get("shard_index") != old_close["shards"][i]["shard_index"]
                or pred.get("session_id") != old_close["shards"][i]["session_id"]
                or pred.get("final_chain_seq")
                != old_close["shards"][i]["final_chain_seq"]
                or pred.get("final_chain_hash")
                != old_close["shards"][i]["final_chain_hash"]
                or pred.get("final_chain_seq") != head["final_chain_seq"]
                or pred.get("final_chain_hash") != head["final_chain_hash"]
                or pred.get("recovery_seal_sha256") != ""
            ):
                raise GroupVerificationError(
                    f"receipt group transition predecessor shard {i} "
                    "differs from signed close"
                )
        else:
            try:
                require_writer_gone(directory, predecessor["shards"][i]["session_id"])
            except RecoverySealError as exc:
                raise GroupVerificationError(
                    f"receipt group predecessor shard {i} writer state invalid: {exc}"
                ) from exc
            head = _verify_shard(
                directory,
                predecessor,
                prev_hash,
                i,
                None,
                incomplete=True,
                allow_torn=True,
            )
            if (
                pred.get("final_chain_seq") != head["final_chain_seq"]
                or pred.get("final_chain_hash") != head["final_chain_hash"]
            ):
                raise GroupVerificationError(
                    f"receipt group incomplete predecessor shard {i} differs"
                )
            if not head.get("torn", False):
                if pred.get("recovery_seal_sha256") != "":
                    raise GroupVerificationError(
                        f"receipt group predecessor shard {i} has "
                        "unnecessary recovery seal"
                    )
                continue
            seal_digest = pred.get("recovery_seal_sha256")
            if not isinstance(seal_digest, str) or not _HEX64.fullmatch(seal_digest):
                raise GroupVerificationError(
                    f"receipt group predecessor shard {i} lacks a valid "
                    "recovery seal digest"
                )
            successor_member = opening["shards"][i % len(opening["shards"])]
            successor_index = i % len(opening["shards"])
            successor_head = _verify_shard(
                directory, opening, open_hash, successor_index, None
            )
            expected = {
                "shard": head["shard"],
                "shard_size": head["shard_size"],
                "shard_sha256": head["shard_sha256"],
                "damage_offset": head["damage_offset"],
                "last_good_seq": head["last_good_seq"],
                "last_good_hash": head["last_good_hash"],
                "predecessor_tail_seq": head["final_chain_seq"],
                "predecessor_tail_hash": head["final_chain_hash"],
                "predecessor_signer_key": predecessor["signer_key"],
                "successor_signer_key": opening["signer_key"],
                "successor_open_hash": successor_head["session_open_hash"],
            }
            try:
                verify_recovery_seal(
                    directory,
                    seal_digest,
                    trusted,
                    expected,
                    predecessor_session=pred["session_id"],
                    successor_session=successor_member["session_id"],
                )
            except RecoverySealError as exc:
                raise GroupVerificationError(
                    f"receipt group predecessor shard {i} recovery seal invalid: {exc}"
                ) from exc
    if check_inventory:
        _verify_transition_inventory(
            directory, predecessor, prev_hash, close_hash, trusted
        )


def _verify_transition_inventory(
    directory: Path,
    opening: dict[str, Any],
    open_hash: str,
    close_hash: str,
    trusted: set[str],
) -> None:
    found = 0
    for path in directory.glob("receipt-group-*-transition.json"):
        transition, _ = _strict_artifact(path, "transition")
        filename_id = path.name[len("receipt-group-") : -len("-transition.json")]
        if (
            not _HEX32.fullmatch(filename_id)
            or transition.get("new_group_id") != filename_id
        ):
            raise GroupVerificationError(
                "receipt group transition file identity differs"
            )
        signer = transition.get("signer_key")
        if not isinstance(signer, str) or not _HEX64.fullmatch(signer):
            raise GroupVerificationError("invalid receipt group transition signer")
        refers_to_open = transition.get("previous_open_manifest_sha256") == open_hash
        _verify_signature(
            transition, "transition", trusted if refers_to_open else {signer}
        )
        if not refers_to_open:
            continue
        if (
            transition.get("previous_group_id") != opening["group_id"]
            or transition.get("previous_close_manifest_sha256") != close_hash
        ):
            raise GroupVerificationError(
                "receipt group transition has forged predecessor binding"
            )
        successor_id = transition.get("new_group_id")
        successor, successor_raw = _strict_artifact(
            directory / f"receipt-group-{successor_id}-open.json", "open"
        )
        _verify_signature(successor, "open", trusted)
        _validate_open(successor, successor_id)
        if (
            successor.get("previous_group_id") != opening["group_id"]
            or successor.get("previous_open_manifest_sha256") != open_hash
            or transition.get("new_open_manifest_sha256") != _digest(successor_raw)
            or signer != successor.get("signer_key")
        ):
            raise GroupVerificationError(
                "receipt group transition does not match signed successor open"
            )
        # The incoming verifier compares every claimed head with the signed
        # predecessor close (or the verified recovery seal). Reuse it here so
        # verification by predecessor ID enforces the same link.
        _verify_successor_transition(
            directory, successor, _digest(successor_raw), trusted, False
        )
        found += 1
    if found > 1:
        raise GroupVerificationError(
            "duplicate transition for receipt group predecessor"
        )


def _verify_ael_inventory(
    directory: Path, opening: dict[str, Any], trusted: set[str], incomplete: bool
) -> tuple[bool, bool]:
    """Every native run must have a signed session opening in this directory."""
    claims: dict[str, tuple[str, str, bool, str]] = {}
    recovered_sessions: set[str] = set()
    if opening["previous_group_id"]:
        predecessor, _ = _strict_artifact(
            directory / f"receipt-group-{opening['previous_group_id']}-open.json",
            "open",
        )
        _verify_signature(predecessor, "open", trusted)
        _validate_open(predecessor, opening["previous_group_id"])
        recovered_sessions = {member["session_id"] for member in predecessor["shards"]}
    sessions: set[str] = set()
    for path in directory.glob("evidence-*.jsonl"):
        parsed = _parse_evidence_filename(path.name)
        if parsed is not None:
            sessions.add(parsed[0])
    for session in sorted(sessions):
        _, _, entries = _read_session_evidence(
            directory, session, incomplete or session in recovered_sessions
        )
        gate = (
            entries[0].get("detail")
            if entries[0].get("type") == "receipt_group_v1"
            else None
        )
        gate_open = None
        if gate is not None:
            if not isinstance(gate, dict) or not isinstance(gate.get("group_id"), str):
                raise GroupVerificationError("invalid receipt group gate")
            group_id = gate["group_id"]
            gate_open, gate_raw = _strict_artifact(
                directory / f"receipt-group-{group_id}-open.json", "open"
            )
            _verify_signature(gate_open, "open", trusted)
            _validate_open(gate_open, group_id)
            index = gate.get("shard_index")
            expected = {
                "group_id": group_id,
                "shard_index": index,
                "session_id": session,
                "open_manifest_sha256": _digest(gate_raw),
                "signer_key": gate_open["signer_key"],
                "previous_group_id": gate_open["previous_group_id"],
                "previous_open_manifest_sha256": gate_open[
                    "previous_open_manifest_sha256"
                ],
            }
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or index < 0
                or index >= len(gate_open["shards"])
                or gate_open["shards"][index]["session_id"] != session
                or gate != expected
            ):
                raise GroupVerificationError(
                    "receipt group gate is not owned by a signed opening"
                )
        signed_open_seen = False
        for entry in entries:
            if entry.get("type") not in {ACTION_ENTRY_TYPE, EVIDENCE_ENTRY_TYPE}:
                continue
            receipt = entry.get("detail")
            if not isinstance(receipt, dict):
                raise GroupVerificationError("invalid receipt session inventory detail")
            control = receipt.get("action_record", {}).get("session_control", {})
            if control.get("kind") != "session_open":
                continue
            if signed_open_seen:
                raise GroupVerificationError(
                    "receipt session has multiple signed native AEL openings"
                )
            signed_open_seen = True
            signer = receipt.get("signer_key")
            run = control.get("open", {}).get("run_nonce")
            if (
                not isinstance(signer, str)
                or signer not in trusted
                or not verify_evidence_chain([receipt], signer).get("valid")
            ):
                raise GroupVerificationError(
                    "native AEL run has no signed session owner"
                )
            if run is None and gate is None:
                continue
            if not isinstance(run, str) or not _HEX32.fullmatch(run):
                raise GroupVerificationError(
                    "native AEL run has no signed session owner"
                )
            binding = control.get("open", {}).get("group_binding")
            if (gate is None and binding is not None) or (
                gate is not None
                and (binding != gate or signer != gate_open["signer_key"])
            ):
                raise GroupVerificationError(
                    "signed session open disagrees with recorder group gate"
                )
            if run in claims:
                raise GroupVerificationError(f"duplicate signed native AEL run {run!r}")
            completed = any(
                entry.get("type") == "transcript_root"
                or (
                    isinstance(entry.get("detail"), dict)
                    and entry["detail"]
                    .get("action_record", {})
                    .get("session_control", {})
                    .get("kind")
                    == "session_close"
                )
                for entry in entries
            )
            claims[run] = (
                signer,
                gate["group_id"] if gate is not None else "",
                completed,
                session,
            )
    check_group_ael_membership(
        [shard["session_id"] for shard in opening["shards"]],
        [
            session
            for _, group_id, _, session in claims.values()
            if group_id == opening["group_id"]
        ],
        incomplete,
    )
    for run in claims:
        path = directory / "ael" / run
        try:
            info = path.lstat()
        except OSError as exc:
            raise GroupVerificationError(
                f"native AEL run {run!r} claimed by a signed session_open is missing"
            ) from exc
        if not stat.S_ISDIR(info.st_mode):
            raise GroupVerificationError(
                f"native AEL run {run!r} claimed by a signed session_open is missing"
            )
    open_tail = False
    neighbor_open_tail = False
    for path in (directory / "ael").iterdir():
        if not _HEX32.fullmatch(path.name) or path.is_symlink() or not path.is_dir():
            raise GroupVerificationError("invalid native AEL run directory")
        if path.name not in claims:
            raise GroupVerificationError(
                f"native AEL run {path.name!r} has no signed session owner"
            )
        signer, group_id, completed, _session = claims[path.name]
        try:
            verify_ael_run(directory, path.name, signer, require_close=completed)
        except AELVerificationError as exc:
            raise GroupVerificationError(
                f"native AEL run {path.name!r} invalid: {exc}"
            ) from exc
        if not completed:
            if group_id == opening["group_id"]:
                open_tail = True
            else:
                neighbor_open_tail = True
    return open_tail, neighbor_open_tail


def check_group_ael_membership(
    signed: list[str], claimed: list[str], incomplete: bool
) -> None:
    """Require exact signed shard ownership for each complete group claim."""
    signed_sessions = set(signed)
    grouped_sessions: set[str] = set()
    for session in claimed:
        if session not in signed_sessions:
            raise GroupVerificationError(
                f"receipt group native AEL claim session {session!r} "
                "is outside signed shard membership"
            )
        if session in grouped_sessions:
            raise GroupVerificationError(
                f"receipt group native AEL session {session!r} has duplicate claims"
            )
        grouped_sessions.add(session)
    if not incomplete and grouped_sessions != signed_sessions:
        raise GroupVerificationError(
            f"receipt group native AEL claims = {len(grouped_sessions)}, "
            f"want {len(signed_sessions)}"
        )


def verify_receipt_group(
    directory: str | Path, group_id: str, trusted_keys: list[str] | set[str]
) -> dict[str, Any]:
    """Return a trusted whole-group verdict; incomplete is never success."""
    result: dict[str, Any] = {
        "group_id": group_id,
        "verdict": GROUP_INVALID,
        "shard_count": 0,
    }
    trusted = {key.lower() for key in trusted_keys}
    if not trusted:
        result["error"] = "receipt group verification requires a trusted signer key"
        return result
    root = Path(directory)
    try:
        root_info = root.lstat()
        if not stat.S_ISDIR(root_info.st_mode) or root.is_symlink():
            raise GroupVerificationError("receipt group path is not a real directory")
        ael_root = root / "ael"
        ael_info = ael_root.lstat()
        if not stat.S_ISDIR(ael_info.st_mode):
            raise GroupVerificationError(
                "receipt group AEL path is not a real directory"
            )
        before = _inventory(root)
        opening, open_raw = _strict_artifact(
            root / f"receipt-group-{group_id}-open.json", "open"
        )
        _verify_signature(opening, "open", trusted)
        _validate_open(opening, group_id)
        open_hash = _digest(open_raw)
        result.update(
            {"open_manifest_sha256": open_hash, "shard_count": len(opening["shards"])}
        )
        close_path = root / f"receipt-group-{group_id}-close.json"
        if _exists_nofollow(close_path):
            closed, close_raw = _strict_artifact(close_path, "close")
            _validate_close(closed, opening, open_hash, trusted)
            close_hash = _digest(close_raw)
            result["close_manifest_sha256"] = close_hash
            for i, claim in enumerate(closed["shards"]):
                _verify_shard(root, opening, open_hash, i, claim)
            _verify_successor_transition(root, opening, open_hash, trusted)
            result["verdict"] = GROUP_VALID
        else:
            close_hash = ""
            for i in range(len(opening["shards"])):
                session_id = opening["shards"][i]["session_id"]
                if not _session_evidence_paths(root, session_id):
                    continue  # The writer may have crashed before opening this shard.
                _verify_shard(
                    root, opening, open_hash, i, None, incomplete=True, allow_torn=True
                )
            result.update(
                {
                    "verdict": GROUP_INCOMPLETE,
                    "error": "receipt group has no signed close manifest",
                }
            )
        _verify_transition_inventory(root, opening, open_hash, close_hash, trusted)
        open_ael_tail, neighbor_ael_tail = _verify_ael_inventory(
            root, opening, trusted, not close_hash
        )
        if open_ael_tail and result["verdict"] == GROUP_VALID:
            result["verdict"] = GROUP_INCOMPLETE
            result["error"] = "native AEL run has an open recorder tail"
        elif neighbor_ael_tail and result["verdict"] == GROUP_VALID:
            result["error"] = (
                "predecessor or neighboring group is GROUP_INCOMPLETE: "
                "native AEL run has an open recorder tail"
            )
        if (
            result["verdict"] == GROUP_VALID
            and opening["previous_group_id"]
            and not _exists_nofollow(
                root / f"receipt-group-{opening['previous_group_id']}-close.json"
            )
        ):
            result["error"] = (
                "predecessor group is GROUP_INCOMPLETE: no signed close manifest"
            )
        if _inventory(root) != before:
            raise GroupVerificationError(
                "receipt group directory changed during verification"
            )
        if not os.path.samestat(root_info, root.stat()) or not os.path.samestat(
            ael_info, ael_root.stat()
        ):
            raise GroupVerificationError(
                "receipt group directory identity changed during verification"
            )
        return result
    except (
        OSError,
        GroupVerificationError,
        ReceiptError,
        AELVerificationError,
        CanonicalizeError,
        BadGrammarError,
        UnsafeNumberError,
        ValueError,
    ) as exc:
        result["verdict"] = GROUP_INVALID
        result["error"] = str(exc)
        return result


def _inventory(directory: Path) -> tuple[tuple[str, int, int, int], ...]:
    items = []
    paths = list(directory.iterdir())
    ael = directory / "ael"
    if ael.is_dir() and not ael.is_symlink():
        paths.extend(ael.rglob("*"))
    for path in paths:
        info = path.lstat()
        if path.is_symlink():
            raise GroupVerificationError("symlink in receipt group inventory")
        relative = str(path.relative_to(directory))
        items.append((relative, info.st_ino, info.st_size, info.st_mtime_ns))
    return tuple(sorted(items))
