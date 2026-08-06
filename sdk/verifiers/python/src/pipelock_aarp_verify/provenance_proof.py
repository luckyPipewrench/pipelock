# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Experimental, fixture-only evidence-provenance proof verifier.

This module deliberately has no production receipt integration.  It consumes
only the signed fixture wrapper used by the four verifier conformance gate.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import struct
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .number import IJSONNumber, StrictParseError, parse_json_strict
from .provenance import PROFILE_DIGEST
from .provenance import Recipe as TransformRecipe

FIXTURE_FORMAT = "pipelock-evidence-provenance-verification-fixture/v1"
PROOF_VERSION = "pipelock-evidence-provenance-proof/v1"
GENESIS = "genesis"
TRUST_ROOTS = "fixture supplied; self-attested; not authenticated"
_MAX_INPUT = 2 << 20
_MAX_OUTPUT = 1 << 20
# Fixture-wide ceilings prevent a multi-entry chain from multiplying otherwise
# bounded per-recipe work.
_MAX_FIXTURE_SOURCE_REFERENCES = 128
_MAX_FIXTURE_MATCH_CHECKS = 4096
_MAX_FIXTURE_RECIPE_PROCESSING_BYTES = 64 << 20
MAX_FIXTURE_BYTES = 16 << 20
_MAX_FIXTURE_JSON_DEPTH = 64
_MAX_FIXTURE_ENTRIES = 32
_MAX_VERIFICATION_SOURCES = 32
_MAX_PROOF_SOURCES = 32
_MAX_MATCHES_PER_SOURCE = 1024
_MAX_SIGNED_BYTES = 1 << 20
_MAX_SOURCE_BYTES = 2 << 20
_MAX_TOTAL_SOURCE_BYTES = 16 << 20
_MAX_ARTIFACT_BYTES = 2 << 20
_OP_BYTES = {
    "identity": 1,
    "url_component": 2,
    "percent_decode": 3,
    "dlp_normalize": 4,
    "lowercase": 5,
    "invisible_strip": 6,
    "hex_decode": 7,
    "base32_decode": 8,
    "base64_decode": 9,
    "leetspeak": 10,
    "vowel_fold": 11,
    "query_unescape": 12,
    "invisible_space": 13,
    "matching_normalize": 14,
    "hex_decode_liberal": 15,
    "base32_decode_liberal": 16,
    "base64_decode_liberal": 17,
    "encoded_token_normalize": 18,
    "text_segment": 19,
    "html_entity_decode": 20,
    "whitespace_compact": 21,
    "url_noise_strip": 22,
    "ordered_query_concat": 23,
    "query_subsequence": 24,
    "hostname_dot_remove": 25,
    "encoded_run": 26,
    "canary_canonicalize": 27,
}
_COMPONENT_BYTES = {
    "": 0,
    "url": 1,
    "hostname": 2,
    "path": 3,
    "query_key": 4,
    "query_value": 5,
    "raw_query": 6,
}


@dataclass
class _FixtureWork:
    source_references: int = 0
    match_checks: int = 0
    recipe_processing_bytes: int = 0

    def charge_recipe_processing(self, size: int) -> None:
        if size > _MAX_FIXTURE_RECIPE_PROCESSING_BYTES - self.recipe_processing_bytes:
            raise _FixtureWorkLimitError
        self.recipe_processing_bytes += size


class _FixtureWorkLimitError(Exception):
    """Raised before a fixture-wide transform operation would exceed its budget."""


_PROOF_KEYS = {"version", "transform_profile_digest", "sources", "producer"}
_SOURCE_KEYS = {"source_ordinal", "source_id", "recipe", "view_commitment", "matches"}
_MATCH_KEYS = {
    "match_ordinal",
    "byte_start",
    "byte_end",
    "match_class",
    "match_commitment",
}
_RECIPE_KEYS = {"transform_profile_digest", "operations"}
_OP_KEYS = {
    "kind",
    "component",
    "selector",
    "occurrence",
    "passes",
    "profile",
    "decode_padding",
    "alphabet",
    "indices",
    "minimum_length",
}
_PRODUCER_KEYS = {"binary_digest", "ruleset_digest"}


class ProvenanceError(Exception):
    """A proof failure with a stable comparable-output stage."""

    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


def _exact_dict(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProvenanceError("proof_structure", f"{label} has an invalid field set")
    return value


def _fields(
    value: Any, required: set[str], optional: set[str], label: str
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or not required.issubset(value)
        or not set(value).issubset(required | optional)
    ):
        raise ProvenanceError("proof_structure", f"{label} has an invalid field set")
    return value


def _require_str(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ProvenanceError("proof_structure", f"{label} must be a string")
    return value


def _uint(value: Any, label: str) -> int:
    if not isinstance(value, IJSONNumber) or not value.literal.isdigit():
        raise ProvenanceError("proof_structure", f"{label} must be an unsigned integer")
    result = int(value.literal)
    if result > (1 << 64) - 1:
        raise ProvenanceError("proof_structure", f"{label} exceeds uint64")
    return result


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ProvenanceError("proof_structure", f"{label} must be a boolean")
    return value


def _utf8(value: str, label: str) -> bytes:
    try:
        return value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise ProvenanceError("proof_structure", f"{label} is not UTF-8") from exc


def _b64(value: Any, label: str, max_bytes: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a base64 string")
    if max_bytes is not None and len(value) > ((max_bytes + 2) // 3) * 4:
        raise ValueError(f"{label} exceeds byte limit")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} is not base64") from exc
    if max_bytes is not None and len(decoded) > max_bytes:
        raise ValueError(f"{label} exceeds byte limit")
    return decoded


def _hex(value: Any, label: str, size: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be hex")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} is not hex") from exc
    if raw.hex() != value or (size is not None and len(raw) != size):
        raise ValueError(f"{label} has an invalid length or spelling")
    return raw


def _digest(value: Any, label: str, prefix: str = "sha256:") -> str:
    text = _require_str(value, label)
    encoded = text.removeprefix(prefix)
    if (
        not text.startswith(prefix)
        or len(encoded) != 64
        or any(c not in "0123456789abcdef" for c in encoded)
    ):
        raise ProvenanceError("proof_structure", f"{label} is not a canonical digest")
    return text


def _frame(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


def _transform_recipe(recipe: dict[str, Any]) -> TransformRecipe:
    def plain(value: Any) -> Any:
        if isinstance(value, IJSONNumber):
            return int(value.literal)
        if isinstance(value, list):
            return [plain(item) for item in value]
        if isinstance(value, dict):
            return {key: plain(item) for key, item in value.items()}
        return value

    try:
        transformed = TransformRecipe.from_json(
            recipe.get("transform_profile_digest"), plain(recipe.get("operations"))
        )
        transformed.validate()
        return transformed
    except (TypeError, ValueError) as exc:
        raise ProvenanceError("proof_structure", str(exc)) from exc


def _recipe_bytes(recipe: dict[str, Any]) -> bytes:
    _transform_recipe(recipe)
    profile = _require_str(recipe["transform_profile_digest"], "recipe profile")
    if profile == "":
        raise ProvenanceError("proof_structure", "missing transform profile digest")
    if profile != PROFILE_DIGEST:
        raise ProvenanceError("proof_structure", "unknown transform profile")
    operations = recipe["operations"]
    if not isinstance(operations, list):
        raise ProvenanceError("proof_structure", "recipe operations must be an array")
    result = (
        _frame(b"pipelock/evidence-provenance/recipe/v1")
        + _frame(_utf8(profile, "recipe profile"))
        + _frame(struct.pack(">Q", len(operations)))
    )
    for index, raw in enumerate(operations):
        operation = _fields(
            raw, {"kind"}, _OP_KEYS - {"kind"}, f"recipe operation {index}"
        )
        kind = _require_str(operation["kind"], "operation kind")
        component = _require_str(operation.get("component", ""), "operation component")
        selector = _require_str(operation.get("selector", ""), "operation selector")
        occurrence = _uint(
            operation.get("occurrence", IJSONNumber("0")), "operation occurrence"
        )
        passes = _uint(operation.get("passes", IJSONNumber("0")), "operation passes")
        profile_name = _require_str(operation.get("profile", ""), "operation profile")
        padding = _bool(
            operation.get("decode_padding", False), "operation decode_padding"
        )
        alphabet = _require_str(operation.get("alphabet", ""), "operation alphabet")
        indices_raw = operation.get("indices", [])
        if not isinstance(indices_raw, list):
            raise ProvenanceError(
                "proof_structure", "operation indices must be an array"
            )
        indices = bytes(_uint(item, "operation index") for item in indices_raw)
        minimum_length = _uint(
            operation.get("minimum_length", IJSONNumber("0")),
            "operation minimum_length",
        )
        encoded = b"".join(
            (
                _frame(bytes([_OP_BYTES[kind]])),
                _frame(bytes([_COMPONENT_BYTES[component]])),
                _frame(_utf8(selector, "operation selector")),
                _frame(struct.pack(">I", occurrence)),
                _frame(bytes([passes])),
                _frame(_utf8(profile_name, "operation profile")),
                _frame(bytes([1 if padding else 0])),
            )
        )
        if _OP_BYTES[kind] >= 12:
            encoded += b"".join(
                (
                    _frame(_utf8(alphabet, "operation alphabet")),
                    _frame(indices),
                    _frame(struct.pack(">I", minimum_length)),
                )
            )
        result += _frame(encoded)
    return result


def _apply_recipe(
    recipe: dict[str, Any], source: bytes, work: _FixtureWork | None = None
) -> bytes:
    transformed = _transform_recipe(recipe)
    try:
        charge = None if work is None else work.charge_recipe_processing
        return transformed.apply_bytes(source, charge).encode()
    except (TypeError, ValueError) as exc:
        raise ProvenanceError("view_reproduction", str(exc)) from exc


def _validate_intervals(
    view: bytes | None,
    matches: list[tuple[int, int]],
    *,
    stage: str = "location",
) -> None:
    """Validate the proof profile's byte-coordinate interval invariants."""
    if view is not None:
        try:
            view.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ProvenanceError(stage, "view: invalid UTF-8") from exc
    previous_start = previous_end = -1
    for start, end in matches:
        if end <= start:
            raise ProvenanceError(stage, "byte end must be greater than byte start")
        if view is not None:
            if end > len(view):
                raise ProvenanceError(stage, "interval out of bounds")
            if (start != 0 and view[start] & 0xC0 == 0x80) or (
                end != len(view) and view[end] & 0xC0 == 0x80
            ):
                raise ProvenanceError(stage, "interval splits UTF-8 code point")
        if previous_start >= 0:
            if start < previous_start:
                raise ProvenanceError(stage, "intervals are unsorted")
            if start == previous_start:
                raise ProvenanceError(stage, "duplicate interval start")
            if start < previous_end:
                raise ProvenanceError(stage, "intervals overlap")
        previous_start, previous_end = start, end


def _commit(key: bytes, domain: str, parts: Iterable[bytes]) -> str:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(_frame(domain.encode("ascii")))
    for part in parts:
        mac.update(_frame(part))
    return "hmac-sha256:" + mac.hexdigest()


def _output(
    signature: str = "not_checked",
    chain: str = "not_checked",
    artifacts: str = "attested_unchecked",
    source_commitment: str = "not_checked",
    view_reproduction: str = "not_checked",
    location: str = "not_checked",
    match_commitment: str = "not_checked",
    overall: str = "incomplete",
    failure_stage: str = "",
) -> dict[str, Any]:
    value = {
        "trust_roots": TRUST_ROOTS,
        "authenticated_provenance": False,
        "signature": signature,
        "chain": chain,
        "artifacts": artifacts,
        "source_commitment": source_commitment,
        "view_reproduction": view_reproduction,
        "location": location,
        "match_commitment": match_commitment,
        "overall": overall,
    }
    if failure_stage:
        value["failure_stage"] = failure_stage
    return value


def _invalid(stage: str, current: dict[str, Any]) -> dict[str, Any]:
    if stage in current:
        current[stage] = "invalid" if stage in {"signature", "chain"} else "mismatch"
    if stage == "view_commitment":
        # The report has a single commitment-result field. Its mismatch is
        # retained while failure_stage identifies which commitment failed.
        current["match_commitment"] = "mismatch"
    current["overall"] = "invalid"
    current["failure_stage"] = stage
    return current


def _parse_signed(signed: bytes) -> dict[str, Any]:
    try:
        value = parse_json_strict(signed, _MAX_FIXTURE_JSON_DEPTH)
    except (UnicodeDecodeError, StrictParseError, RecursionError) as exc:
        raise ProvenanceError(
            "proof_structure", "signed bytes are not strict UTF-8 JSON"
        ) from exc
    return _exact_dict(
        value,
        {"chain_seq", "chain_prev_hash", "critical_features", "proof"},
        "signed assertion",
    )


def _verify_entry(
    entry: Any,
    index: int,
    public_key: bytes,
    commitment_key: bytes | None,
    sources: dict[str, bytes],
    binary_b64: str | None,
    ruleset_b64: str | None,
    previous_signed: bytes | None,
    work: _FixtureWork,
    reconstructed_views: dict[tuple[str, bytes], bytes],
) -> dict[str, Any]:
    result = _output()
    try:
        entry = _exact_dict(entry, {"signed_b64", "signature"}, "entry")
        signed = _b64(entry["signed_b64"], "signed_b64", _MAX_SIGNED_BYTES)
        signed_object = _parse_signed(signed)
        signature = _require_str(entry["signature"], "signature")
        if not signature.startswith("ed25519:"):
            raise ValueError("signature prefix")
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _hex(signature[8:], "signature", 64), signed
        )
        result["signature"] = "verified"
    except ProvenanceError:
        return _invalid("proof_structure", result)
    except (InvalidSignature, ValueError, TypeError):
        return _invalid("signature", result)
    try:
        sequence = _uint(signed_object["chain_seq"], "chain_seq")
        previous = _require_str(signed_object["chain_prev_hash"], "chain_prev_hash")
        expected_previous = (
            GENESIS
            if previous_signed is None
            else "sha256:" + hashlib.sha256(previous_signed).hexdigest()
        )
        if sequence != index or previous != expected_previous:
            return _invalid("chain", result)
        result["chain"] = "verified"
    except ProvenanceError:
        return _invalid("chain", result)
    critical = signed_object["critical_features"]
    if not isinstance(critical, list) or critical != ["evidence_provenance"]:
        return _invalid("critical_features", result)
    try:
        proof = _exact_dict(signed_object["proof"], _PROOF_KEYS, "proof")
        if _require_str(proof["version"], "proof version") != PROOF_VERSION:
            raise ProvenanceError("proof_structure", "unsupported proof version")
        if (
            _require_str(proof["transform_profile_digest"], "proof profile")
            != PROFILE_DIGEST
        ):
            raise ProvenanceError("proof_structure", "unknown proof profile")
        producer = _fields(proof["producer"], set(), _PRODUCER_KEYS, "producer")
        source_list = proof["sources"]
        if not isinstance(source_list, list):
            raise ProvenanceError("proof_structure", "proof sources must be an array")
        if len(source_list) > _MAX_PROOF_SOURCES:
            raise ProvenanceError("proof_structure", "proof exceeds source limit")
        parsed_sources = []
        source_ids: set[str] = set()
        ordinals: set[int] = set()
        last_ordinal = -1
        for source in source_list:
            work.source_references += 1
            if work.source_references > _MAX_FIXTURE_SOURCE_REFERENCES:
                raise ProvenanceError(
                    "proof_structure", "fixture exceeds source-reference limit"
                )
            source = _fields(source, _SOURCE_KEYS - {"matches"}, {"matches"}, "source")
            source_id = _require_str(source["source_id"], "source id")
            _utf8(source_id, "source id")
            ordinal = _uint(source["source_ordinal"], "source ordinal")
            recipe = _exact_dict(source["recipe"], _RECIPE_KEYS, "recipe")
            recipe_bytes = _recipe_bytes(recipe)
            if (
                _require_str(recipe["transform_profile_digest"], "recipe profile")
                != proof["transform_profile_digest"]
            ):
                raise ProvenanceError(
                    "proof_structure", "recipe profile differs from proof"
                )
            view_commitment = _digest(
                source["view_commitment"], "view commitment", "hmac-sha256:"
            )
            if (
                not source_id
                or source_id in source_ids
                or ordinal in ordinals
                or ordinal <= last_ordinal
            ):
                raise ProvenanceError(
                    "proof_structure", "source identities or ordinals are invalid"
                )
            matches = source.get("matches", [])
            if not isinstance(matches, list):
                raise ProvenanceError("proof_structure", "matches must be an array")
            if len(matches) > _MAX_MATCHES_PER_SOURCE:
                raise ProvenanceError(
                    "proof_structure", "proof source exceeds match limit"
                )
            work.match_checks += len(matches)
            if work.match_checks > _MAX_FIXTURE_MATCH_CHECKS:
                raise ProvenanceError(
                    "proof_structure", "fixture exceeds match-check limit"
                )
            parsed_matches = []
            previous_ordinal = -1
            for match in matches:
                match = _exact_dict(match, _MATCH_KEYS, "match")
                match_ordinal = _uint(match["match_ordinal"], "match ordinal")
                start = _uint(match["byte_start"], "byte start")
                end = _uint(match["byte_end"], "byte end")
                match_class = _require_str(match["match_class"], "match class")
                _utf8(match_class, "match class")
                if match_class == "":
                    raise ProvenanceError("proof_structure", "match class is required")
                match_commitment = _digest(
                    match["match_commitment"], "match commitment", "hmac-sha256:"
                )
                if match_ordinal <= previous_ordinal:
                    raise ProvenanceError(
                        "proof_structure", "match ordering or interval is invalid"
                    )
                parsed_matches.append(
                    (match_ordinal, start, end, match_class, match_commitment)
                )
                previous_ordinal = match_ordinal
            _validate_intervals(
                None,
                [(match[1], match[2]) for match in parsed_matches],
                stage="proof_structure",
            )
            parsed_sources.append(
                (
                    ordinal,
                    source_id,
                    recipe,
                    recipe_bytes,
                    view_commitment,
                    parsed_matches,
                )
            )
            source_ids.add(source_id)
            ordinals.add(ordinal)
            last_ordinal = ordinal
    except ProvenanceError:
        return _invalid("proof_structure", result)
    binary_digest = producer.get("binary_digest")
    ruleset_digest = producer.get("ruleset_digest")
    try:
        if binary_digest is not None:
            _digest(binary_digest, "binary digest")
        if ruleset_digest is not None:
            _digest(ruleset_digest, "ruleset digest")
    except ProvenanceError:
        return _invalid("proof_structure", result)
    try:
        binary = (
            None
            if binary_digest is None or binary_b64 is None
            else _b64(binary_b64, "binary", _MAX_ARTIFACT_BYTES)
        )
        ruleset = (
            None
            if ruleset_digest is None or ruleset_b64 is None
            else _b64(ruleset_b64, "ruleset", _MAX_ARTIFACT_BYTES)
        )
    except ValueError:
        return _invalid("artifacts", result)
    binary_mismatch = (
        binary_digest is not None
        and binary is not None
        and binary_digest != "sha256:" + hashlib.sha256(binary).hexdigest()
    )
    ruleset_mismatch = (
        ruleset_digest is not None
        and ruleset is not None
        and ruleset_digest != "sha256:" + hashlib.sha256(ruleset).hexdigest()
    )
    if binary_mismatch or ruleset_mismatch:
        return _invalid("artifacts", result)
    if (binary_digest is not None and binary is None) or (
        ruleset_digest is not None and ruleset is None
    ):
        result["artifacts"] = "attested_unchecked"
    elif binary_digest is None and ruleset_digest is None:
        result["artifacts"] = "not_attested"
    else:
        result["artifacts"] = "matched"
    unavailable_source = any(
        source_id not in sources for _, source_id, _, _, _, _ in parsed_sources
    )
    for (
        ordinal,
        source_id,
        recipe,
        recipe_bytes,
        view_commitment,
        matches,
    ) in parsed_sources:
        source = sources.get(source_id)
        if source is None:
            continue
        try:
            key = (source_id, recipe_bytes)
            view = reconstructed_views.get(key)
            if view is None:
                view = _apply_recipe(recipe, source, work)
                reconstructed_views[key] = view
        except _FixtureWorkLimitError:
            return _invalid("proof_structure", result)
        except (ProvenanceError, UnicodeError):
            return _invalid("view_reproduction", result)
        result["view_reproduction"] = "reproduced"
        try:
            _validate_intervals(view, [(match[1], match[2]) for match in matches])
        except ProvenanceError:
            invalid = _invalid("location", result)
            if unavailable_source:
                invalid["view_reproduction"] = "not_checked"
                invalid["location"] = "not_checked"
                invalid["match_commitment"] = "not_checked"
            return invalid
        result["location"] = "exact_coordinates"
        if commitment_key is not None:
            computed_view = _commit(
                commitment_key,
                "pipelock/evidence-provenance/view/v1",
                [
                    struct.pack(">Q", ordinal),
                    source_id.encode(),
                    proof["transform_profile_digest"].encode(),
                    recipe_bytes,
                    view,
                ],
            )
            if not hmac.compare_digest(computed_view, view_commitment):
                if unavailable_source:
                    result["view_reproduction"] = "not_checked"
                    result["location"] = "not_checked"
                return _invalid("view_commitment", result)
            for match_ordinal, start, end, match_class, match_commitment in matches:
                computed_match = _commit(
                    commitment_key,
                    "pipelock/evidence-provenance/match/v1",
                    [
                        source_id.encode(),
                        proof["transform_profile_digest"].encode(),
                        recipe_bytes,
                        view_commitment.encode(),
                        struct.pack(">Q", match_ordinal),
                        struct.pack(">Q", start),
                        struct.pack(">Q", end),
                        match_class.encode(),
                    ],
                )
                if not hmac.compare_digest(computed_match, match_commitment):
                    if unavailable_source:
                        result["view_reproduction"] = "not_checked"
                        result["location"] = "not_checked"
                    return _invalid("match_commitment", result)
            result["match_commitment"] = "opened"
    if unavailable_source:
        # A missing source leaves the receipt incomplete, but does not prevent
        # us from detecting a mismatch in a later source that is available.
        result["view_reproduction"] = "not_checked"
        result["location"] = "not_checked"
        result["match_commitment"] = "not_checked"
    return result


def verify_fixture(data: bytes) -> tuple[dict[str, Any], int]:
    """Verify the fixture wrapper and return one aggregate staged report."""
    try:
        if len(data) > MAX_FIXTURE_BYTES:
            raise ValueError("fixture exceeds byte limit")
        wrapper = parse_json_strict(data, _MAX_FIXTURE_JSON_DEPTH)
        wrapper = _exact_dict(wrapper, {"format", "entries", "verification"}, "fixture")
        if _require_str(wrapper["format"], "format") != FIXTURE_FORMAT:
            raise ValueError("unsupported fixture format")
        entries = wrapper["entries"]
        verification = _fields(
            wrapper["verification"],
            {"signer_public_key_hex"},
            {"commitment_key_hex", "sources", "binary_b64", "ruleset_b64"},
            "verification",
        )
        source_inputs = verification.get("sources", [])
        if (
            not isinstance(entries, list)
            or not entries
            or not isinstance(source_inputs, list)
        ):
            raise ValueError("entries and sources must be arrays")
        if len(entries) > _MAX_FIXTURE_ENTRIES:
            raise ValueError("fixture exceeds entry limit")
        if len(source_inputs) > _MAX_VERIFICATION_SOURCES:
            raise ValueError("verification exceeds source limit")
        public_key = _hex(
            verification["signer_public_key_hex"], "signer public key", 32
        )
        commitment_key = (
            None
            if verification.get("commitment_key_hex") is None
            else _hex(verification["commitment_key_hex"], "commitment key")
        )
        if commitment_key is not None and len(commitment_key) < 32:
            raise ValueError("commitment key is too short")
        sources: dict[str, bytes] = {}
        total_source_bytes = 0
        for item in source_inputs:
            item = _exact_dict(item, {"source_id", "bytes_b64"}, "source input")
            source_id = _require_str(item["source_id"], "source input id")
            if not source_id or source_id in sources:
                raise ValueError("source input IDs must be unique")
            source_bytes = _b64(item["bytes_b64"], "source bytes", _MAX_SOURCE_BYTES)
            total_source_bytes += len(source_bytes)
            if total_source_bytes > _MAX_TOTAL_SOURCE_BYTES:
                raise ValueError("verification sources exceed byte limit")
            sources[source_id] = source_bytes
        binary_b64 = verification.get("binary_b64")
        ruleset_b64 = verification.get("ruleset_b64")
        if binary_b64 is not None and not isinstance(binary_b64, str):
            raise ValueError("binary must be base64")
        if ruleset_b64 is not None and not isinstance(ruleset_b64, str):
            raise ValueError("ruleset must be base64")
    except (
        StrictParseError,
        UnicodeDecodeError,
        RecursionError,
        ValueError,
        ProvenanceError,
    ):
        return _invalid("proof_structure", _output()), 1
    aggregate = _output(
        signature="verified", chain="verified", artifacts="not_attested"
    )
    all_reproduced = True
    all_located = True
    all_commitments_opened = True
    previous_signed = None
    work = _FixtureWork()
    reconstructed_views: dict[tuple[str, bytes], bytes] = {}
    for index, entry in enumerate(entries):
        result = _verify_entry(
            entry,
            index,
            public_key,
            commitment_key,
            sources,
            binary_b64,
            ruleset_b64,
            previous_signed,
            work,
            reconstructed_views,
        )
        if result["overall"] == "invalid":
            return result, 1
        if result["artifacts"] == "attested_unchecked":
            aggregate["artifacts"] = "attested_unchecked"
        elif (
            result["artifacts"] == "matched"
            and aggregate["artifacts"] != "attested_unchecked"
        ):
            aggregate["artifacts"] = "matched"
        all_reproduced = all_reproduced and result["view_reproduction"] == "reproduced"
        all_located = all_located and result["location"] == "exact_coordinates"
        all_commitments_opened = (
            all_commitments_opened and result["match_commitment"] == "opened"
        )
        try:
            previous_signed = (
                _b64(entry["signed_b64"], "signed_b64", _MAX_SIGNED_BYTES)
                if isinstance(entry, dict)
                else None
            )
        except ValueError:
            previous_signed = None
    aggregate["view_reproduction"] = "reproduced" if all_reproduced else "not_checked"
    aggregate["location"] = "exact_coordinates" if all_located else "not_checked"
    aggregate["match_commitment"] = (
        "opened" if all_commitments_opened else "not_checked"
    )
    return aggregate, 0


def compact_fixture_json(data: bytes) -> tuple[str, int]:
    """Render the exact compact JSON consumed by the differential gate."""
    output, exit_code = verify_fixture(data)
    return json.dumps(output, separators=(",", ":"), ensure_ascii=False), exit_code
