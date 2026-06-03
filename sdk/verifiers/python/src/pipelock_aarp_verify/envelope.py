# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""AARP envelope parsing and the signed-payload digest.

Ports ``internal/aarp/envelope.py`` and ``internal/aarp/chain.py``. The envelope
is decoded with strict semantics: duplicate keys at any depth, trailing tokens,
unsafe numbers, and unknown fields in AARP-controlled objects are all fatal. The
``ext`` map is a free, unsigned extension bag and is not schema-checked.

The signed payload is ``{profile, subject, assertion, crit_ext?, chain?}`` — not
the signatures (signatures never sign each other) and not ``ext`` (advisory,
ignored safely). Its JCS-canonical bytes are the "identical canonical payload
bytes" every parallel signature binds.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .canonical import canonicalize
from .number import (
    BadGrammarError,
    StrictParseError,
    UnsafeNumberError,
    enforce_safe_numbers,
    parse_json_strict,
    parse_seq,
    validate_hex256,
    validate_uint64_string,
)
from .suite import (
    PROFILE,
    check_critical_extensions,
)
from .timestamp import validate_timestamp
from .trustdomain import validate_trust_domain_name

# Alias used by the chain module: a validated uint64 typed-string -> its value.
parse_seq_value = parse_seq

# Domain separator for the assurance-assertion signature.
CONTEXT_ASSERTION = "pipelock-aarp-v0.1/assurance-assertion"

# Genesis prior-hash sentinel: 64 hex zeros ("no prior receipt"). A genesis link
# carries seq "0".
GENESIS_PRIOR_HASH = "0" * 64

# Known receipt types for Subject.receipt_type.
KNOWN_RECEIPT_TYPES = {"action_receipt_v1", "evidence_receipt_v2"}

# Allowed key sets for each AARP-controlled object. Unknown keys are fatal,
# mirroring Go's DisallowUnknownFields on these structs.
_SUBJECT_KEYS = {
    "action_record_sha256",
    "receipt_envelope_sha256",
    "receipt_signer_key",
    "receipt_type",
}
_ASSERTION_KEYS = {
    "claimed",
    "mediator_id",
    "trust_domain",
    "complete_mediation",
    "evidence_refs",
    "issued_at",
}
_CHAIN_KEYS = {"issuer_id", "seq", "prior_hash"}
_PROTECTED_KEYS = {
    "profile",
    "canon",
    "alg",
    "key_type",
    "key_id",
    "signer_role",
    "crit",
}
_SIGNATURE_KEYS = {"protected", "sig"}
_ENVELOPE_KEYS = {
    "profile",
    "subject",
    "assertion",
    "chain",
    "signatures",
    "crit_ext",
    "ext",
}


class SchemaError(Exception):
    """The envelope is structurally invalid (envelope-fatal)."""


class UnknownFieldError(Exception):
    """An AARP-controlled object carried a field outside its schema (fatal)."""


class ChainSchemaError(Exception):
    """A chain link is structurally invalid (envelope-fatal)."""


def _require_str(obj: dict[str, Any], key: str, where: str) -> str:
    v = obj.get(key)
    if not isinstance(v, str):
        raise SchemaError(f"{where}.{key} must be a string")
    return v


def _check_unknown(obj: dict[str, Any], allowed: set[str], where: str) -> None:
    for key in obj:
        if key not in allowed:
            raise UnknownFieldError(f"unknown field {key!r} in {where}")


class ProtectedHeader:
    """Per-signature suite descriptor (the signed ``protected`` object)."""

    __slots__ = (
        "profile",
        "canon",
        "alg",
        "key_type",
        "key_id",
        "signer_role",
        "crit",
    )

    def __init__(self, raw: dict[str, Any]) -> None:
        _check_unknown(raw, _PROTECTED_KEYS, "signature.protected")
        self.profile = _require_str(raw, "profile", "protected")
        self.canon = _require_str(raw, "canon", "protected")
        self.alg = _require_str(raw, "alg", "protected")
        self.key_type = _require_str(raw, "key_type", "protected")
        self.key_id = _require_str(raw, "key_id", "protected")
        self.signer_role = _require_str(raw, "signer_role", "protected")
        crit_raw = raw.get("crit", [])
        if not isinstance(crit_raw, list) or not all(
            isinstance(c, str) for c in crit_raw
        ):
            raise SchemaError("signature.protected.crit must be a string array")
        self.crit = list(crit_raw)

    def to_signed_dict(self) -> dict[str, Any]:
        """Return the object that is canonicalized into the signing input.

        ``crit`` is omitted when empty, matching the Go ``json:"crit,omitempty"``
        tag so the signed bytes match the producer's.
        """
        out: dict[str, Any] = {
            "profile": self.profile,
            "canon": self.canon,
            "alg": self.alg,
            "key_type": self.key_type,
            "key_id": self.key_id,
            "signer_role": self.signer_role,
        }
        if self.crit:
            out["crit"] = list(self.crit)
        return out


class Signature:
    """One parallel protected signature over the shared payload digest."""

    __slots__ = ("protected", "sig")

    def __init__(self, raw: dict[str, Any]) -> None:
        _check_unknown(raw, _SIGNATURE_KEYS, "signature")
        prot = raw.get("protected")
        if not isinstance(prot, dict):
            raise SchemaError("signature.protected must be an object")
        self.protected = ProtectedHeader(prot)
        self.sig = _require_str(raw, "sig", "signature")


class Subject:
    """The immutable receipt this assurance envelope appraises, by digest."""

    __slots__ = (
        "action_record_sha256",
        "receipt_envelope_sha256",
        "receipt_signer_key",
        "receipt_type",
    )

    def __init__(self, raw: dict[str, Any]) -> None:
        _check_unknown(raw, _SUBJECT_KEYS, "subject")
        self.action_record_sha256 = _require_str(raw, "action_record_sha256", "subject")
        self.receipt_envelope_sha256 = _require_str(
            raw, "receipt_envelope_sha256", "subject"
        )
        self.receipt_signer_key = _require_str(raw, "receipt_signer_key", "subject")
        self.receipt_type = _require_str(raw, "receipt_type", "subject")

    def validate(self) -> None:
        try:
            validate_hex256(self.action_record_sha256)
        except BadGrammarError as exc:
            raise SchemaError(f"subject.action_record_sha256: {exc}") from exc
        try:
            validate_hex256(self.receipt_envelope_sha256)
        except BadGrammarError as exc:
            raise SchemaError(f"subject.receipt_envelope_sha256: {exc}") from exc
        try:
            validate_hex256(self.receipt_signer_key)
        except BadGrammarError as exc:
            raise SchemaError(f"subject.receipt_signer_key: {exc}") from exc
        if self.receipt_type not in KNOWN_RECEIPT_TYPES:
            raise SchemaError(f"unknown subject.receipt_type {self.receipt_type!r}")

    def to_signed_dict(self) -> dict[str, Any]:
        return {
            "action_record_sha256": self.action_record_sha256,
            "receipt_envelope_sha256": self.receipt_envelope_sha256,
            "receipt_signer_key": self.receipt_signer_key,
            "receipt_type": self.receipt_type,
        }


class Assertion:
    """The producer's claim set about the subject (the shared signed payload)."""

    __slots__ = (
        "claimed",
        "mediator_id",
        "trust_domain",
        "complete_mediation",
        "evidence_refs",
        "issued_at",
        "_has_trust_domain",
        "_has_evidence_refs",
    )

    def __init__(self, raw: dict[str, Any]) -> None:
        _check_unknown(raw, _ASSERTION_KEYS, "assertion")
        claimed_raw = raw.get("claimed", [])
        if not isinstance(claimed_raw, list) or not all(
            isinstance(c, str) for c in claimed_raw
        ):
            raise SchemaError("assertion.claimed must be a string array")
        self.claimed = list(claimed_raw)
        self.mediator_id = _require_str(raw, "mediator_id", "assertion")
        self._has_trust_domain = "trust_domain" in raw
        self.trust_domain = raw.get("trust_domain", "")
        if self._has_trust_domain and not isinstance(self.trust_domain, str):
            raise SchemaError("assertion.trust_domain must be a string")
        cm = raw.get("complete_mediation", False)
        if not isinstance(cm, bool):
            raise SchemaError("assertion.complete_mediation must be a bool")
        self.complete_mediation = cm
        self._has_evidence_refs = "evidence_refs" in raw
        ev_raw = raw.get("evidence_refs", [])
        if not isinstance(ev_raw, list) or not all(isinstance(e, str) for e in ev_raw):
            raise SchemaError("assertion.evidence_refs must be a string array")
        self.evidence_refs = list(ev_raw)
        self.issued_at = _require_str(raw, "issued_at", "assertion")

    def validate(self) -> None:
        if self.mediator_id == "":
            raise SchemaError("assertion.mediator_id is required")
        try:
            validate_timestamp(self.issued_at)
        except BadGrammarError as exc:
            raise SchemaError(f"assertion.issued_at: {exc}") from exc
        if self.trust_domain != "":
            try:
                validate_trust_domain_name(self.trust_domain)
            except Exception as exc:  # noqa: BLE001 - mirror Go's wrap-and-fatal
                raise SchemaError(f"assertion.trust_domain: {exc}") from exc

    def to_signed_dict(self) -> dict[str, Any]:
        """Match Go's json tags: trust_domain and evidence_refs are omitempty.

        Go omits ``trust_domain`` and ``evidence_refs`` when empty (the zero
        value for a string / nil slice). ``claimed`` and ``complete_mediation``
        are always present; ``claimed`` serializes ``null`` when nil but the
        corpus always supplies an array, and Go's struct field is a non-omitempty
        slice that marshals ``[]`` only when non-nil. We reproduce the observed
        wire form: ``claimed`` always present as the array given.
        """
        out: dict[str, Any] = {
            "claimed": list(self.claimed),
            "mediator_id": self.mediator_id,
            "complete_mediation": self.complete_mediation,
            "issued_at": self.issued_at,
        }
        if self.trust_domain != "":
            out["trust_domain"] = self.trust_domain
        if self.evidence_refs:
            out["evidence_refs"] = list(self.evidence_refs)
        return out


class ChainLink:
    """Places an envelope in an issuer's append-only, hash-chained stream."""

    __slots__ = ("issuer_id", "seq", "prior_hash")

    def __init__(self, raw: dict[str, Any]) -> None:
        _check_unknown(raw, _CHAIN_KEYS, "chain")
        self.issuer_id = _require_str(raw, "issuer_id", "chain")
        self.seq = _require_str(raw, "seq", "chain")
        self.prior_hash = _require_str(raw, "prior_hash", "chain")

    def validate(self) -> None:
        if self.issuer_id == "":
            raise ChainSchemaError("chain.issuer_id is required")
        try:
            validate_uint64_string(self.seq)
        except BadGrammarError as exc:
            raise ChainSchemaError(f"chain.seq: {exc}") from exc
        try:
            validate_hex256(self.prior_hash)
        except BadGrammarError as exc:
            raise ChainSchemaError(f"chain.prior_hash: {exc}") from exc
        if self.seq == "0" and self.prior_hash != GENESIS_PRIOR_HASH:
            raise ChainSchemaError(
                "genesis link (seq 0) must carry the zero prior hash"
            )
        if self.seq != "0" and self.prior_hash == GENESIS_PRIOR_HASH:
            raise ChainSchemaError(
                f"non-genesis link (seq {self.seq}) must not carry the genesis "
                "prior hash"
            )

    def to_signed_dict(self) -> dict[str, Any]:
        return {
            "issuer_id": self.issuer_id,
            "seq": self.seq,
            "prior_hash": self.prior_hash,
        }


class Envelope:
    """The top-level AARP assurance artifact."""

    __slots__ = (
        "profile",
        "subject",
        "assertion",
        "chain",
        "signatures",
        "crit_ext",
        "ext",
    )

    def __init__(self, raw: dict[str, Any]) -> None:
        _check_unknown(raw, _ENVELOPE_KEYS, "envelope")
        self.profile = _require_str(raw, "profile", "envelope")
        subj = raw.get("subject")
        if not isinstance(subj, dict):
            raise SchemaError("envelope.subject must be an object")
        self.subject = Subject(subj)
        asrt = raw.get("assertion")
        if not isinstance(asrt, dict):
            raise SchemaError("envelope.assertion must be an object")
        self.assertion = Assertion(asrt)
        self.chain: ChainLink | None = None
        if "chain" in raw and raw["chain"] is not None:
            if not isinstance(raw["chain"], dict):
                raise SchemaError("envelope.chain must be an object")
            self.chain = ChainLink(raw["chain"])
        sigs_raw = raw.get("signatures")
        if not isinstance(sigs_raw, list):
            raise SchemaError("envelope.signatures must be an array")
        self.signatures = [self._make_sig(s) for s in sigs_raw]
        crit_raw = raw.get("crit_ext", [])
        if not isinstance(crit_raw, list) or not all(
            isinstance(c, str) for c in crit_raw
        ):
            raise SchemaError("envelope.crit_ext must be a string array")
        self.crit_ext = list(crit_raw)
        # ext is a free, unsigned bag — not schema-checked.
        self.ext = raw.get("ext")

    @staticmethod
    def _make_sig(s: Any) -> Signature:
        if not isinstance(s, dict):
            raise SchemaError("each signature must be an object")
        return Signature(s)

    def payload_signed_dict(self) -> dict[str, Any]:
        """The exact set of fields every signature covers.

        Mirrors Go's ``payload`` struct: profile, subject, assertion, crit_ext
        (always present), then chain (omitempty).

        ``crit_ext`` is NOT omitempty: a nil/absent envelope crit_ext normalizes
        to ``[]`` so the signed canonical bytes always carry ``"crit_ext": []``
        (never omitted, never null). Go's ``payload()`` does the same nil->[]
        normalization; without it the computed payload digest diverges from Go
        and every signature fails to verify.
        """
        out: dict[str, Any] = {
            "profile": self.profile,
            "subject": self.subject.to_signed_dict(),
            "assertion": self.assertion.to_signed_dict(),
            "crit_ext": list(self.crit_ext),
        }
        if self.chain is not None:
            out["chain"] = self.chain.to_signed_dict()
        return out

    def canonical_payload(self) -> bytes:
        return canonicalize(self.payload_signed_dict())

    def payload_digest(self) -> str:
        return hashlib.sha256(self.canonical_payload()).hexdigest()

    def validate_payload_parts(self) -> None:
        if self.profile != PROFILE:
            raise SchemaError(f"profile {self.profile!r}, want {PROFILE!r}")
        self.subject.validate()
        self.assertion.validate()
        if self.chain is not None:
            self.chain.validate()
        check_critical_extensions(self.crit_ext)


def unmarshal(data: bytes | str) -> Envelope:
    """Parse a JSON-encoded envelope with full strict semantics.

    Rejects duplicate keys at any depth, trailing tokens, unsafe numbers, and
    unknown fields in AARP-controlled objects.
    """
    tree = parse_json_strict(data)
    # Reject any raw JSON number outside the I-JSON safe range anywhere in the
    # envelope before structural decoding (cross-language canonicalization hazard).
    enforce_safe_numbers(tree)
    if not isinstance(tree, dict):
        raise SchemaError("envelope must be a JSON object")
    return Envelope(tree)


def signing_input(payload_digest: str, header: ProtectedHeader) -> bytes:
    """Build the canonical bytes one signature signs.

    The object is ``{context, payload_sha256, protected}``; JCS sorts the keys.
    """
    obj = {
        "context": CONTEXT_ASSERTION,
        "payload_sha256": payload_digest,
        "protected": header.to_signed_dict(),
    }
    return canonicalize(obj)


# Re-export for callers that catch number-safety failures during unmarshal.
__all__ = [
    "Envelope",
    "Signature",
    "ProtectedHeader",
    "Subject",
    "Assertion",
    "ChainLink",
    "SchemaError",
    "UnknownFieldError",
    "ChainSchemaError",
    "StrictParseError",
    "UnsafeNumberError",
    "unmarshal",
    "signing_input",
    "GENESIS_PRIOR_HASH",
    "CONTEXT_ASSERTION",
]
