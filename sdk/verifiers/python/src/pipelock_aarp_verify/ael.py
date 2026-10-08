# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Verifier for Pipelock's native Agent Evidence Level run artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .line_space import trim_go_space_bytes
from .number import (
    StrictParseError,
    UnsafeNumberError,
    enforce_cross_language_number_range,
    parse_json_strict,
)
from .receipt import _reject_duplicate_pairs
from .timestamp import validate_timestamp

_RUN = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_RECORD_BYTES = 1 << 20
_ZERO = "0" * 64


class AELVerificationError(ValueError):
    """A native AEL artifact failed verification."""


def _read_bounded_stream(stream: BinaryIO, limit: int) -> bytes:
    raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise AELVerificationError("native AEL artifact exceeds size limit during read")
    return raw


def _read_regular(path: Path, limit: int) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise AELVerificationError("native AEL artifact is not a regular file")
        if before.st_size > limit:
            raise AELVerificationError("native AEL artifact exceeds size limit")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not os.path.samestat(before, opened):
                raise AELVerificationError("native AEL artifact changed during open")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = _read_bounded_stream(stream, limit)
        finally:
            os.close(fd)
        after = path.stat()
    except OSError as exc:
        raise AELVerificationError(f"read native AEL artifact: {exc}") from exc
    if (
        len(raw) > limit
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise AELVerificationError("native AEL artifact changed during verification")
    return raw, before


def _same_int(value: Any, want: int) -> bool:
    """Match Go's typed integer decode: a JSON bool or float is not the integer."""
    return type(value) is int and value == want


def _is_int(value: Any) -> bool:
    return type(value) is int


def _json(raw: bytes, name: str) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
        enforce_cross_language_number_range(parse_json_strict(text))
        return json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        StrictParseError,
        UnsafeNumberError,
        ValueError,
    ) as exc:
        raise AELVerificationError(f"invalid native AEL {name}: {exc}") from exc


def _go_json(value: Any) -> bytes:
    # AEL payloads are decoded as Go maps by the verifier. encoding/json sorts
    # map keys lexicographically when it marshals those maps back to bytes.
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    text = text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    text = text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return text.encode("utf-8")


def _verify_ael_line(line: bytes, pub: bytes) -> dict[str, Any]:
    parts = line.split(b".")
    if len(parts) != 2:
        raise AELVerificationError("invalid native AEL compact record")
    try:
        payload = base64.urlsafe_b64decode(parts[0] + b"=" * (-len(parts[0]) % 4))
        sig = base64.urlsafe_b64decode(parts[1] + b"=" * (-len(parts[1]) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise AELVerificationError("invalid native AEL base64 encoding") from exc
    if (
        base64.urlsafe_b64encode(payload).rstrip(b"=") != parts[0]
        or len(payload) > _MAX_RECORD_BYTES
    ):
        raise AELVerificationError("invalid native AEL payload encoding")
    if base64.urlsafe_b64encode(sig).rstrip(b"=") != parts[1] or len(sig) != 64:
        raise AELVerificationError("invalid native AEL signature encoding")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, payload)
    except InvalidSignature as exc:
        raise AELVerificationError("native AEL signature verification failed") from exc
    value = _json(payload, "record")
    if not isinstance(value, dict) or _go_json(value) != payload:
        raise AELVerificationError("native AEL payload is not canonical JSON")
    return value


def verify_ael_run(
    recorder_dir: str | Path, run: str, signer_hex: str, *, require_close: bool = True
) -> dict[str, Any]:
    """Verify signed AEL records; an open run may have one torn final line."""
    if not _RUN.fullmatch(run):
        raise AELVerificationError("invalid native AEL run nonce")
    if not _HEX64.fullmatch(signer_hex):
        raise AELVerificationError("invalid native AEL signer")
    pub = bytes.fromhex(signer_hex)
    key_id = hashlib.sha256(pub).hexdigest()
    root = Path(recorder_dir)
    run_dir = root / "ael" / run
    for directory in (root / "ael", run_dir, run_dir / "keys", run_dir / "recorders"):
        try:
            info = directory.lstat()
        except OSError as exc:
            raise AELVerificationError(
                f"native AEL directory missing: {directory}"
            ) from exc
        if not stat.S_ISDIR(info.st_mode):
            raise AELVerificationError("native AEL directory is missing or redirected")

    manifest_raw, _ = _read_regular(run_dir / "manifest.json", 4096)
    manifest = _json(manifest_raw, "manifest")
    expected = {
        "ael_format": 1,
        "coverage": "mediated-only",
        "custody": "same-process",
        "recorders": [
            {
                "file": "recorders/pipelock.jsonl",
                "id": "pipelock",
                "key": key_id,
                "run": run,
            }
        ],
        "runs": [run],
    }
    if manifest != expected or _go_json(manifest) != manifest_raw:
        raise AELVerificationError("native AEL manifest differs from signed run layout")
    key_raw, _ = _read_regular(run_dir / "keys" / f"{key_id}.pub", 128)
    if key_raw != base64.b64encode(pub):
        raise AELVerificationError(
            "native AEL published key differs from trusted signer"
        )

    path = run_dir / "recorders" / "pipelock.jsonl"
    raw, before = _read_regular(path, 256 * 1024 * 1024)
    if not raw.endswith(b"\n") and require_close:
        raise AELVerificationError("native AEL stream has torn final line")
    complete = raw.rsplit(b"\n", 1)[0] if b"\n" in raw else b""
    fragment = raw[len(complete) + 1 :] if b"\n" in raw else raw
    # Go reads each record through a 1 MiB buffer: a terminated line may be at
    # most 1 MiB including its newline, and an unterminated fragment must still
    # fit the buffer. The bound applies before any trimming, so a blank line
    # cannot slip past it.
    if len(fragment) >= _MAX_RECORD_BYTES:
        raise AELVerificationError("native AEL record exceeds limit")
    previous = _ZERO
    count = 0
    closed = False
    for line in complete.split(b"\n") if complete else []:
        if len(line) + 1 > _MAX_RECORD_BYTES:
            raise AELVerificationError("native AEL stream has torn or oversized line")
        line = trim_go_space_bytes(line)
        if not line:
            continue
        if not line or len(line) > _MAX_RECORD_BYTES:
            raise AELVerificationError("native AEL record is empty or oversized")
        if closed:
            raise AELVerificationError("native AEL has records after close")
        record = _verify_ael_line(line, pub)
        if (
            not _same_int(record.get("v"), 1)
            or record.get("run") != run
            or record.get("recorder") != "pipelock"
            or record.get("key") != key_id
            or record.get("prev") != previous
            or not _same_int(record.get("seq"), count)
            or not isinstance(record.get("ts"), str)
        ):
            raise AELVerificationError(
                f"native AEL record {count} breaks run binding or chain"
            )
        _validate_record(record, count, previous)
        payload_part = line.split(b".", 1)[0]
        payload = base64.urlsafe_b64decode(
            payload_part + b"=" * (-len(payload_part) % 4)
        )
        previous = hashlib.sha256(payload).hexdigest()
        count += 1
        closed = record["type"] == "close"
    if require_close and (not closed or count < 2):
        raise AELVerificationError("native AEL run has no signed close")
    if closed and not raw.endswith(b"\n"):
        raise AELVerificationError(
            "native AEL stream has no complete opening or continues after close"
        )
    try:
        after = path.stat()
    except OSError as exc:
        raise AELVerificationError(
            "native AEL stream changed during verification"
        ) from exc
    if (
        not os.path.samestat(before, after)
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise AELVerificationError("native AEL stream changed during verification")
    return {
        "final_seq": max(count - 1, 0),
        "final_hash": previous,
        "record_count": count,
    }


def _validate_record(record: dict[str, Any], seq: int, prev: str) -> None:
    kind = record.get("type")
    base = {"key", "prev", "recorder", "run", "seq", "ts", "type", "v"}
    if kind == "open":
        allowed = base | {"hmax", "htol"}
        if (
            seq != 0
            or not _is_int(record.get("hmax"))
            or not _is_int(record.get("htol"))
            or record["hmax"] < 0
            or record["htol"] < 0
            or record["htol"] > record["hmax"]
        ):
            raise AELVerificationError("invalid native AEL open")
    elif kind == "activity":
        allowed = base | {"event"}
        event = record.get("event")
        if (
            not isinstance(event, dict)
            or set(event) != {"class", "dir", "id"}
            or not isinstance(event.get("class"), str)
            or not isinstance(event.get("id"), str)
            or not isinstance(event.get("dir"), str)
            or not event["class"]
            or not event["id"]
            or event["dir"] not in {"in", "out", "internal"}
        ):
            raise AELVerificationError("invalid native AEL activity")
    elif kind == "heartbeat":
        allowed = base
    elif kind == "close":
        allowed = base | {"count", "head"}
        if not _same_int(record.get("count"), seq + 1) or record.get("head") != prev:
            raise AELVerificationError("native AEL close head or count differs")
    else:
        raise AELVerificationError("unknown native AEL record type")
    if (seq == 0) != (kind == "open") or set(record) != allowed:
        raise AELVerificationError("invalid native AEL lifecycle or fields")
    timestamp = record.get("ts")
    if not isinstance(timestamp, str):
        raise AELVerificationError("invalid native AEL timestamp")
    try:
        validate_timestamp(timestamp)
    except ValueError as exc:
        raise AELVerificationError("invalid native AEL timestamp") from exc
    if not timestamp.endswith("Z") or re.search(r"\.\d*0Z$", timestamp):
        raise AELVerificationError(
            "native AEL timestamp is not canonical UTC RFC3339Nano"
        )
