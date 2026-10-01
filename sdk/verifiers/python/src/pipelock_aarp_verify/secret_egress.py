# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Structural secret-egress evidence validation, ported from the Go contract.

Acceptance does not establish registry membership, policy authorization, producer
coverage, persistence, or enforcement success. In particular, observed release
may disagree with intent: such evidence must remain representable.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .rawjson import object_member_span

SECRET_EGRESS_PAYLOAD_KIND = "secret_egress_decision_v1"

_ENVELOPE_REQUIRED = {
    "record_type",
    "receipt_version",
    "payload_kind",
    "canonicalization",
    "crit",
    "event_id",
    "timestamp",
    "signature",
    "chain_seq",
    "chain_prev_hash",
    "policy_hash",
    "payload",
}
_ENVELOPE_OPTIONAL_STRINGS = {
    "principal",
    "actor",
    "active_manifest_hash",
    "contract_hash",
    "selector_id",
}
_CANONICALIZATION_FIELDS = {
    "jcs_profile",
    "jcs_version",
    "hash_alg",
    "sig_alg",
    "redaction_ruleset_id",
    "redaction_ruleset_version",
    "redaction_ruleset_hash",
}
_SIGNATURE_FIELDS = {"signer_key_id", "key_purpose", "algorithm", "signature"}
_MAX_EXACT_INTEGER = (1 << 53) - 1

_IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_SIGNATURE = re.compile(r"ed25519:[0-9a-f]{128}")
_DECISION_FIELDS = {
    "version",
    "action_id",
    "decision_id",
    "site_id",
    "plane",
    "transport",
    "location",
    "view",
    "boundary",
    "phase",
    "destination_kind",
    "pattern_class",
    "rule_id",
    "finding_disposition",
    "planned_byte_form",
    "authorization",
    "persistence_policy",
}
_TRANSPORT_BOUNDARIES = {
    "fetch": {"upstream_request"},
    "forward": {"upstream_request"},
    "connect": {"tunnel_admission"},
    "intercept": {"upstream_request"},
    "reverse": {"upstream_request"},
    "websocket": {"upstream_request", "upstream_frame"},
    "mcp_stdio": {"upstream_request", "tool_dispatch"},
    "mcp_http_upstream": {"upstream_request", "tool_dispatch"},
    "mcp_ws": {"upstream_request", "tool_dispatch"},
    "mcp_http_listener": {"upstream_request", "tool_dispatch"},
}
_LOCATIONS = {"url", "header", "body", "tool_arguments", "envelope", "frame"}
_VIEWS = {"original", "normalized", "post_transform", "reassembled", "authorization"}
_ORIGINS = {"builtin", "operator"}
_FALLBACK_REASONS = {
    "unparseable_body",
    "no_safe_raw_span",
    "unsupported_encoding",
    "unsupported_shape",
    "opaque_arguments",
}


class SecretEgressError(ValueError):
    """The secret-egress payload violates the structural contract."""


def _object(
    value: Any, required: set[str], optional: set[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SecretEgressError(f"{label} must be an object")
    if value.keys() - required - optional:
        raise SecretEgressError(f"{label} has an unknown field")
    if required - value.keys():
        raise SecretEgressError(f"{label} is missing a required field")
    if any(child is None for child in value.values()):
        raise SecretEgressError(f"{label} cannot contain null")
    return value


def _enum(value: Any, allowed: set[str] | dict[str, Any], label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise SecretEgressError(f"invalid {label}")
    return value


def _matches(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise SecretEgressError(f"invalid {label}")
    return value


def validate_payload(value: Any, event_id: str) -> None:
    """Validate the new payload without treating a registry hash as membership."""
    payload = _object(value, {"registry_hash", "decision"}, set(), "payload")
    _matches(payload["registry_hash"], _SHA256, "registry_hash")
    validate_decision(payload["decision"])
    decision = payload["decision"]
    if event_id in (decision["action_id"], decision["decision_id"]):
        raise SecretEgressError("event_id must differ from action_id and decision_id")


def _nonempty_string(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise SecretEgressError(f"invalid {label}")


def _canonical_timestamp(value: str) -> bool:
    match = re.fullmatch(
        r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{0,8}[1-9])?Z",
        value,
    )
    if match is None or value == "0001-01-01T00:00:00Z":
        return False
    year, month, day, hour, minute, second = map(int, match.groups())
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return (
        1 <= month <= 12
        and 1 <= day <= days[month - 1]
        and hour < 24
        and minute < 60
        and second < 60
    )


def _integer(value: Any, minimum: int, label: str) -> None:
    if type(value) is not int or not minimum <= value <= _MAX_EXACT_INTEGER:
        raise SecretEgressError(f"invalid {label}")


def validate_envelope(value: Any) -> None:
    """Enforce the new kind's wire profile without changing legacy receipt kinds."""
    envelope = _object(
        value,
        _ENVELOPE_REQUIRED,
        _ENVELOPE_OPTIONAL_STRINGS | {"delegation_chain", "contract_generation"},
        "envelope",
    )
    if (
        envelope["record_type"] != "evidence_receipt_v2"
        or type(envelope["receipt_version"]) is not int
        or envelope["receipt_version"] != 2
        or envelope["payload_kind"] != SECRET_EGRESS_PAYLOAD_KIND
    ):
        raise SecretEgressError("invalid secret-egress envelope identity")
    for name in {"event_id", "timestamp", "chain_prev_hash", "policy_hash"}:
        _nonempty_string(envelope[name], name)
    if not _canonical_timestamp(envelope["timestamp"]):
        raise SecretEgressError("invalid canonical UTC timestamp")
    _matches(envelope["policy_hash"], _SHA256, "policy_hash")
    for name in _ENVELOPE_OPTIONAL_STRINGS & envelope.keys():
        _nonempty_string(envelope[name], name)
    _integer(envelope["chain_seq"], 0, "chain_seq")
    if "contract_generation" in envelope:
        _integer(envelope["contract_generation"], 1, "contract_generation")
    if "delegation_chain" in envelope:
        chain = envelope["delegation_chain"]
        if not isinstance(chain, list) or not chain:
            raise SecretEgressError("invalid delegation_chain")
        for item in chain:
            _nonempty_string(item, "delegation_chain entry")
    crit = envelope["crit"]
    if (
        not isinstance(crit, list)
        or len(crit) != 2
        or "canonicalization" not in crit
        or SECRET_EGRESS_PAYLOAD_KIND not in crit
    ):
        raise SecretEgressError("invalid critical features")
    for name, fields in [
        ("canonicalization", _CANONICALIZATION_FIELDS),
        ("signature", _SIGNATURE_FIELDS),
    ]:
        nested = _object(envelope[name], fields, set(), name)
        for field in fields:
            _nonempty_string(nested[field], f"{name}.{field}")
    _matches(
        envelope["signature"]["signature"], _SIGNATURE, "lowercase signature encoding"
    )


def validate_source(receipt: dict[str, Any], raw: str, start: int = 0) -> None:
    """Check the new wire profile and nested Decision source bounds.

    The caller has already parsed strict JSON. Inspect original numeric tokens
    before lossy values reach verification, and retain the nested source limit.
    """
    if not any(
        (key.lower() == "payload_kind" and value == SECRET_EGRESS_PAYLOAD_KIND)
        or (
            key.lower() == "crit"
            and isinstance(value, list)
            and all(isinstance(item, str) for item in value)
            and SECRET_EGRESS_PAYLOAD_KIND in value
        )
        for key, value in receipt.items()
    ):
        return
    validate_envelope(receipt)
    # Candidate wire profile: producer timestamps are unescaped ASCII tokens.
    # Go's time.Time JSON decoder does not unescape the timestamp string value.
    timestamp = object_member_span(raw, start, "timestamp")
    if (
        timestamp is None
        or raw[timestamp[0] : timestamp[1]] != '"' + receipt["timestamp"] + '"'
    ):
        raise SecretEgressError("invalid raw timestamp spelling")
    for name in ["receipt_version", "chain_seq", "contract_generation"]:
        span = object_member_span(raw, start, name)
        if span is None:
            continue
        literal = raw[span[0] : span[1]]
        if (
            literal != "2"
            if name == "receipt_version"
            else re.fullmatch(r"0|[1-9][0-9]*", literal) is None
        ):
            raise SecretEgressError(f"invalid {name} spelling")
    payload = object_member_span(raw, start, "payload")
    if payload is None:
        return
    decision = object_member_span(raw, payload[0], "decision")
    if (
        decision is not None
        and len(raw[decision[0] : decision[1]].encode("utf-8")) > 16384
    ):
        raise SecretEgressError("invalid evidence decision size")


def validate_decision(value: Any) -> None:
    """Match egressevidence.ParseDecision's typed shape and semantic checks."""
    decision = _object(
        value,
        _DECISION_FIELDS,
        {"destination_ref", "destination_redaction", "outcome", "rewrite_fallback"},
        "decision",
    )
    if type(decision["version"]) is not int or decision["version"] != 1:
        raise SecretEgressError("unsupported evidence decision version")
    action_id = _matches(decision["action_id"], _UUID, "action_id")
    decision_id = _matches(decision["decision_id"], _UUID, "decision_id")
    if action_id == decision_id:
        raise SecretEgressError("action_id and decision_id must differ")
    _matches(decision["site_id"], _IDENTIFIER, "site_id")
    _enum(decision["plane"], {"proxy"}, "plane")
    transport = _enum(decision["transport"], _TRANSPORT_BOUNDARIES, "transport")
    _enum(decision["location"], _LOCATIONS, "location")
    _enum(decision["view"], _VIEWS, "view")
    _enum(decision["boundary"], _TRANSPORT_BOUNDARIES[transport], "transport boundary")
    _enum(decision["pattern_class"], {"core_floor", "configured"}, "pattern_class")
    _matches(decision["rule_id"], _IDENTIFIER, "rule_id")
    destination_kind = _enum(
        decision["destination_kind"], {"network", "local_process"}, "destination_kind"
    )
    retained = "destination_ref" in decision
    redacted = "destination_redaction" in decision
    if retained == redacted:
        raise SecretEgressError(
            "destination requires exactly one reference or redaction"
        )
    if (destination_kind == "local_process") != (transport == "mcp_stdio"):
        raise SecretEgressError("destination kind and transport disagree")
    if retained:
        if destination_kind == "network":
            if not _canonical_host(decision["destination_ref"]):
                raise SecretEgressError("invalid canonical network destination")
        else:
            _matches(
                decision["destination_ref"], _IDENTIFIER, "local process reference"
            )
    else:
        redaction = _object(
            decision["destination_redaction"],
            {"reason"},
            set(),
            "destination_redaction",
        )
        _enum(
            redaction["reason"],
            {"classified_sensitive"},
            "destination redaction reason",
        )
    # Redaction withholds identity. It implies neither a shared destination,
    # complete attribution, nor a collection-coverage gap.
    planned = _enum(
        decision["planned_byte_form"],
        {"none", "original", "transformed"},
        "planned_byte_form",
    )
    _validate_finding(decision, planned)
    if "rewrite_fallback" in decision:
        fallback = _object(
            decision["rewrite_fallback"],
            {"reason", "policy_ref", "policy_origin"},
            set(),
            "rewrite_fallback",
        )
        _enum(fallback["reason"], _FALLBACK_REASONS, "rewrite fallback reason")
        _matches(
            fallback["policy_ref"], _IDENTIFIER, "rewrite fallback policy reference"
        )
        _enum(fallback["policy_origin"], _ORIGINS, "rewrite fallback policy origin")
    _enum(
        decision["persistence_policy"],
        {"required_before_action", "best_effort"},
        "persistence_policy",
    )
    phase = _enum(decision["phase"], {"intent", "outcome"}, "phase")
    if phase == "intent":
        if "outcome" in decision:
            raise SecretEgressError("intent cannot contain observed byte outcome")
    elif "outcome" not in decision:
        raise SecretEgressError("outcome observation is missing")
    else:
        outcome = _object(
            decision["outcome"], {"release", "byte_form"}, set(), "outcome"
        )
        release = _enum(
            outcome["release"], {"none", "partial", "complete", "unknown"}, "release"
        )
        byte_form = _enum(
            outcome["byte_form"],
            {"none", "original", "transformed", "unknown"},
            "byte_form",
        )
        if (release == "none") != (byte_form == "none"):
            raise SecretEgressError("observed release and byte form disagree")


def _validate_finding(decision: dict[str, Any], planned: str) -> None:
    finding = _enum(
        decision["finding_disposition"],
        {"block", "redact", "observe", "authorize", "exempt"},
        "finding_disposition",
    )
    if finding == "block" and planned != "none":
        raise SecretEgressError("block intent cannot plan byte release")
    if finding == "redact" and planned == "original":
        raise SecretEgressError("redact intent cannot plan original byte release")
    expected = {"authorize": "authorization", "exempt": "exemption"}.get(
        finding, "none"
    )
    authority = _object(
        decision["authorization"], {"kind"}, {"ref", "origin"}, "authorization"
    )
    _enum(authority["kind"], {expected}, "finding authorization kind")
    if expected == "none":
        if "ref" in authority or "origin" in authority:
            raise SecretEgressError(
                "non-authorized finding has an authority reference or origin"
            )
    else:
        _matches(authority.get("ref"), _IDENTIFIER, "authority reference")
        _enum(authority.get("origin"), _ORIGINS, "authority origin")


def _canonical_host(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 253
        or value.lower() != value
    ):
        return False
    ip = _parse_ip_literal(value)
    if ip is not None:
        return str(ip) == value
    if re.fullmatch(r"[0-9]+|0x[0-9a-f]*", value.rsplit(".", 1)[-1]):
        return False
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is not None
        for label in value.split(".")
    )


def _parse_ip_literal(
    host: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Match destination.ParseIPLiteral, including its legacy IPv4 spellings.

    DNS syntax is checked by the caller after parsing, including the new
    numeric-looking final-label restriction. No name resolution is performed.
    """
    host = host.strip().split("%", 1)[0].removesuffix(".")
    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        return ip
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) > 4:
        return None
    widths = {1: (32,), 2: (8, 24), 3: (8, 8, 16), 4: (8, 8, 8, 8)}[len(parts)]
    packed = 0
    for part, bits in zip(parts, widths, strict=True):
        component = _inet_aton_component(part, bits)
        if component is None:
            return None
        packed = (packed << bits) | component
    if len(parts) == 4 and not any(
        part.startswith(("0x", "0X")) or (len(part) > 1 and part[0] == "0")
        for part in parts
    ):
        return None
    return ipaddress.IPv4Address(packed)


def _inet_aton_component(part: str, bits: int) -> int | None:
    base, digits, pattern = 10, part, r"[0-9]+"
    if part.startswith(("0x", "0X")):
        base, digits, pattern = 16, part[2:], r"[0-9a-fA-F]+"
    elif len(part) > 1 and part[0] == "0":
        base, digits, pattern = 8, part[1:], r"[0-7]+"
    if re.fullmatch(pattern, digits) is None:
        return None
    value = int(digits, base)
    return value if value < 1 << bits else None
