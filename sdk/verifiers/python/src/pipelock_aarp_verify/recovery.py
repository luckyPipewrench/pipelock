# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Verification helpers for signed recorder recovery seals."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .number import (
    StrictParseError,
    UnsafeNumberError,
    enforce_cross_language_number_range,
    parse_json_strict,
)
from .receipt import _reject_duplicate_pairs
from .timestamp import validate_timestamp

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_INTEGER = (1 << 53) - 1
_GENESIS = "genesis"
_DOMAIN = b"pipelock-recovery-seal-v1\x00"
_FIELDS = (
    "kind",
    "version",
    "predecessor_session",
    "shard",
    "shard_size",
    "shard_sha256",
    "damage_offset",
    "last_good_seq",
    "last_good_hash",
    "predecessor_tail_seq",
    "predecessor_tail_hash",
    "predecessor_signer_key",
    "successor_session",
    "successor_signer_key",
    "successor_open_hash",
    "observed_at",
    "signature",
)


class RecoverySealError(ValueError):
    """A recovery seal or the evidence it claims failed verification."""


def _go_json(value: dict[str, Any]) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    raw = raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    raw = raw.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return raw.encode("utf-8")


def _strict_seal(raw: bytes) -> dict[str, Any]:
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise RecoverySealError("recovery seal must end in one canonical newline")
    body = raw[:-1]
    try:
        text = body.decode("utf-8", errors="strict")
        enforce_cross_language_number_range(parse_json_strict(text))
        seal = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        StrictParseError,
        UnsafeNumberError,
        ValueError,
    ) as exc:
        raise RecoverySealError(f"invalid recovery seal JSON: {exc}") from exc
    if not isinstance(seal, dict) or tuple(seal) != _FIELDS:
        raise RecoverySealError("recovery seal fields or order differ from schema")
    if _go_json(seal) != body:
        raise RecoverySealError("recovery seal is not canonical published JSON")
    return seal


def _unsigned_bytes(seal: dict[str, Any]) -> bytes:
    unsigned = {field: seal[field] for field in _FIELDS if field != "signature"}
    return _DOMAIN + _go_json(unsigned)


def _safe_uint(value: Any, field: str) -> None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > _SAFE_INTEGER
    ):
        raise RecoverySealError(f"invalid recovery seal {field}")


def _session_base(session: str) -> str | None:
    match = re.fullmatch(r"(.+)\.run\.[0-9a-f]{32}", session)
    return match.group(1) if match else None


def _validate(seal: dict[str, Any], trusted: set[str]) -> None:
    if (
        seal["kind"] != "recovery_seal"
        or seal["version"] != 1
        or isinstance(seal["version"], bool)
    ):
        raise RecoverySealError("unsupported recovery seal kind or version")
    predecessor = seal["predecessor_session"]
    successor = seal["successor_session"]
    if (
        not isinstance(predecessor, str)
        or not predecessor.strip()
        or "/" in predecessor
        or "\\" in predecessor
        or not isinstance(successor, str)
        or not successor.strip()
        or "/" in successor
        or "\\" in successor
        or _session_base(predecessor) is None
        or _session_base(predecessor) != _session_base(successor)
        or predecessor == successor
    ):
        raise RecoverySealError("recovery seal sessions do not share a base")
    shard = seal["shard"]
    if (
        not isinstance(shard, str)
        or "/" in shard
        or "\\" in shard
        or not shard.startswith(f"evidence-{predecessor}-")
        or not shard.endswith(".jsonl")
    ):
        raise RecoverySealError("recovery seal shard identity mismatch")
    for field in (
        "shard_size",
        "damage_offset",
        "last_good_seq",
        "predecessor_tail_seq",
    ):
        _safe_uint(seal[field], field)
    if seal["shard_size"] == 0 or seal["damage_offset"] >= seal["shard_size"]:
        raise RecoverySealError("invalid recovery seal damage offset")
    for field in ("shard_sha256", "successor_open_hash"):
        if not isinstance(seal[field], str) or not _HEX64.fullmatch(seal[field]):
            raise RecoverySealError(f"invalid recovery seal {field}")
    for field in ("last_good_hash", "predecessor_tail_hash"):
        value = seal[field]
        if value != _GENESIS and (
            not isinstance(value, str) or not _HEX64.fullmatch(value)
        ):
            raise RecoverySealError(f"invalid recovery seal {field}")
    for field in ("predecessor_signer_key", "successor_signer_key"):
        if not isinstance(seal[field], str) or not _HEX64.fullmatch(seal[field]):
            raise RecoverySealError(f"invalid recovery seal {field}")
    if seal["successor_signer_key"] not in trusted:
        raise RecoverySealError("recovery seal successor signer is not trusted")
    timestamp = seal["observed_at"]
    try:
        validate_timestamp(timestamp)
    except (TypeError, ValueError) as exc:
        raise RecoverySealError("invalid recovery seal observed_at") from exc
    if (
        not isinstance(timestamp, str)
        or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", timestamp)
        or re.search(r"\.\d*0Z$", timestamp)
    ):
        raise RecoverySealError("recovery seal observed_at is not canonical UTC")
    signature = seal["signature"]
    if (
        not isinstance(signature, str)
        or not signature.startswith("ed25519:")
        or signature[8:] != signature[8:].lower()
    ):
        raise RecoverySealError("invalid recovery seal signature format")
    try:
        raw_signature = bytes.fromhex(signature[8:])
        public_key = bytes.fromhex(seal["successor_signer_key"])
        if len(raw_signature) != 64 or len(public_key) != 32:
            raise ValueError("invalid key or signature length")
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            raw_signature, _unsigned_bytes(seal)
        )
    except (ValueError, InvalidSignature) as exc:
        raise RecoverySealError("recovery seal signature verification failed") from exc


def _read_regular(path: Path, limit: int) -> bytes:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise RecoverySealError(
                "recovery seal artifact is not a bounded regular file"
            )
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if not os.path.samestat(before, opened):
                raise RecoverySealError("recovery seal artifact changed during open")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(limit + 1)
        finally:
            os.close(fd)
        after = path.stat()
    except OSError as exc:
        raise RecoverySealError(f"read recovery seal evidence: {exc}") from exc
    if (
        len(raw) > limit
        or not os.path.samestat(before, after)
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise RecoverySealError("recovery seal evidence changed during verification")
    return raw


def require_writer_gone(directory: Path, session: str) -> None:
    path = directory / f"writer-{session}.lock"
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise RecoverySealError("predecessor writer lock is not a regular file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise RecoverySealError("cannot prove predecessor writer is gone") from exc
    try:
        import fcntl

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RecoverySealError("predecessor writer is still active") from exc
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
    except ImportError as exc:
        raise RecoverySealError(
            "platform cannot prove predecessor writer is gone"
        ) from exc
    finally:
        os.close(fd)


def verify_recovery_seal(
    directory: Path,
    seal_digest: str,
    trusted: set[str],
    expected: dict[str, Any],
    *,
    predecessor_session: str,
    successor_session: str,
) -> dict[str, Any]:
    """Verify the signed seal against both observed shard bytes and successor open."""
    require_writer_gone(directory, predecessor_session)
    raw = _read_regular(directory / f"chain-link-{predecessor_session}.json", 64 * 1024)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != seal_digest:
        raise RecoverySealError("recovery seal digest differs from transition")
    seal = _strict_seal(raw)
    _validate(seal, trusted)
    if (
        seal["predecessor_session"] != predecessor_session
        or seal["successor_session"] != successor_session
        or seal["predecessor_signer_key"] != expected["predecessor_signer_key"]
        or seal["successor_signer_key"] != expected["successor_signer_key"]
        or seal["successor_open_hash"] != expected["successor_open_hash"]
    ):
        raise RecoverySealError("recovery seal successor or signer binding differs")
    for field in (
        "shard",
        "shard_size",
        "shard_sha256",
        "damage_offset",
        "last_good_seq",
        "last_good_hash",
        "predecessor_tail_seq",
        "predecessor_tail_hash",
    ):
        if seal[field] != expected[field]:
            raise RecoverySealError(
                f"recovery seal {field} differs from observed evidence"
            )
    return seal
