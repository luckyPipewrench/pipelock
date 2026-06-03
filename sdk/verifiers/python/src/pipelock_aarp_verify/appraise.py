# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Envelope appraisal, claim classification, and the comparable output.

Ports ``internal/aarp/verify.py``, ``appraise.py``, and ``comparable.py``. The
appraisal never reports "trusted" or "safe"; it reports which claims the verifier
could cryptographically confirm, grouped by axis, plus the fixed does_not_assert
list. Per-signature problems are reported per signature, never as an envelope
rejection, so one bad parallel signature cannot mask a good one.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonicalize
from .envelope import Envelope, ProtectedHeader, Signature, signing_input
from .suite import (
    CANON_ID,
    IMPLEMENTED_ALGS,
    KEY_TYPE_FOR_ALG,
    KNOWN_SIGNER_ROLES,
    PROFILE,
    MalformedSuiteError,
    UnknownCriticalExtensionError,
    UnknownSuiteError,
    check_critical_extensions,
)

ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64

# Axis names grouping verified claims by the kind of proof they rest on.
AXIS_IDENTITY = "identity"
AXIS_INTEGRITY = "integrity"
AXIS_FRESHNESS = "freshness"

# Verified-claim names.
CLAIM_ASSERTION_SIGNATURE_VALID = "assertion_signature_valid"
CLAIM_MEDIATOR_KEY_PINNED = "mediator_key_pinned"
CLAIM_CHAIN_LINK_PRESENT = "chain_link_present"
CLAIM_WORKLOAD_IDENTITY_VERIFIED = "workload_identity_verified"
CLAIM_X509_SVID_BOUND = "x509_svid_bound"
CLAIM_SVID_VALID_AT_ACTION_TIME = "svid_valid_at_action_time"

# Per-signature status enum.
SIG_VERIFIED = "verified"
SIG_FAILED = "failed"
SIG_UNKNOWN_KEY = "unknown_key"
SIG_UNIMPLEMENTED = "unimplemented"
SIG_UNKNOWN_SUITE = "unknown_suite"
SIG_MALFORMED = "malformed"

# The fixed set of properties an AARP appraisal never asserts.
DOES_NOT_ASSERT = [
    "efficacy",
    "absence_of_bypass",
    "complete_mediation",
    "policy_correctness",
    "action_safety",
]

# Producer claim -> required verified claims (all must be present to confirm).
# None means structurally claim-only in v0.1 (never verifiable).
CLAIM_VERIFIED_BY: dict[str, list[str] | None] = {
    "mediated": [CLAIM_MEDIATOR_KEY_PINNED],
    "complete-mediation": None,
    "complete_mediation": None,
    CLAIM_WORKLOAD_IDENTITY_VERIFIED: [CLAIM_WORKLOAD_IDENTITY_VERIFIED],
    CLAIM_X509_SVID_BOUND: [CLAIM_X509_SVID_BOUND],
    CLAIM_SVID_VALID_AT_ACTION_TIME: [CLAIM_SVID_VALID_AT_ACTION_TIME],
    "transparency_inclusion": None,
}


@dataclass
class TrustEntry:
    """Binds a signing key id to an authority namespace, never a bare key."""

    mediator_id: str = ""
    role: str = ""
    trust_domain: str = ""


@dataclass
class VerifyOptions:
    """The verifier's pinned trust. Never anything fetched live."""

    trusted_keys: dict[str, bytes] = field(default_factory=dict)
    trust: dict[str, TrustEntry] = field(default_factory=dict)


@dataclass
class SignatureResult:
    """The appraisal of one parallel signature."""

    key_id: str
    alg: str
    signer_role: str
    status: str
    reason: str = ""


@dataclass
class Appraisal:
    """The AARP verifier result."""

    profile: str = PROFILE
    assertion_signed: bool = False
    signatures: list[SignatureResult] = field(default_factory=list)
    assurance_claimed: list[str] = field(default_factory=list)
    verified_claims: list[str] = field(default_factory=list)
    claimed_unverified: list[str] = field(default_factory=list)
    axes: dict[str, list[str]] = field(default_factory=dict)
    does_not_assert: list[str] = field(default_factory=lambda: list(DOES_NOT_ASSERT))
    warnings: list[str] = field(default_factory=list)

    def add_verified(self, claim: str, axis: str) -> None:
        self.verified_claims.append(claim)
        self.axes.setdefault(axis, []).append(claim)


class EnvelopeFatalError(Exception):
    """The envelope is fatal to appraise (schema/profile/canon/crit-ext)."""


def _validate_structure(env: Envelope) -> None:
    """Envelope-fatal schema checks that must hold before per-signature appraisal.

    Only fields inside the SIGNED payload are envelope-fatal here: the payload
    parts (which include the top-level profile and the envelope-level
    critical-extension list) and a non-empty signature set. Per-signature suite
    fields (a signature's protected profile, canon, alg, key trust, and its own
    critical-extension list) are deliberately NOT checked here — they are
    per-signature outcomes appraised in ``_appraise_signature``. The signatures
    array is not itself signed, so a man-in-the-middle can append a junk
    signature; making a bad protected header envelope-fatal would let that append
    deny a legitimately-signed envelope.
    """
    env.validate_payload_parts()
    if len(env.signatures) == 0:
        raise EnvelopeFatalError("envelope has no signatures")


def verify(env: Envelope, opts: VerifyOptions) -> Appraisal:
    """Appraise an envelope. Raises EnvelopeFatalError for envelope-fatal cases.

    Envelope-fatal means a violation in the SIGNED payload: a schema error, the
    top-level profile mismatch, an unsafe number, an unknown AARP field, a bad
    typed-string grammar, or an unknown/malformed envelope-level critical
    extension. Per-signature suite problems (a signature's protected
    profile/canon, an unknown or unimplemented alg, its own critical extensions,
    an untrusted key, or an invalid signature) are reported per signature and
    never raise here, so one bad parallel signature cannot mask a good one.
    """
    ap = _appraise_core(env, opts)
    _classify_claims(ap)
    return ap


def _appraise_core(env: Envelope, opts: VerifyOptions) -> Appraisal:
    _validate_structure(env)
    digest = env.payload_digest()

    ap = Appraisal()
    ap.assurance_claimed = list(env.assertion.claimed)

    verified: list[tuple[str, str]] = []  # (key_id, role)
    for s in env.signatures:
        res, ok = _appraise_signature(s, digest, opts)
        ap.signatures.append(res)
        if ok:
            verified.append((s.protected.key_id, s.protected.signer_role))

    if verified:
        ap.assertion_signed = True
        ap.add_verified(CLAIM_ASSERTION_SIGNATURE_VALID, AXIS_INTEGRITY)
        if _mediator_key_pinned(env.assertion, verified, opts.trust):
            ap.add_verified(CLAIM_MEDIATOR_KEY_PINNED, AXIS_IDENTITY)
        if env.chain is not None:
            ap.add_verified(CLAIM_CHAIN_LINK_PRESENT, AXIS_INTEGRITY)
    else:
        ap.warnings.append(
            "no signature verified under a trusted key; all assurance claims "
            "are untrusted input"
        )
    return ap


def _appraise_signature(
    s: Signature, digest: str, opts: VerifyOptions
) -> tuple[SignatureResult, bool]:
    """Verify one parallel signature. Never falls back to a different suite."""
    h: ProtectedHeader = s.protected
    res = SignatureResult(
        key_id=h.key_id, alg=h.alg, signer_role=h.signer_role, status=""
    )

    # Per-signature suite identity. A wrong profile/canon or an unknown critical
    # extension in THIS signature's protected header makes only this signature
    # unverifiable — it never rejects the envelope, so an appended junk signature
    # cannot deny a verifiable sibling. (The signed top-level profile and
    # crit_ext are checked envelope-fatal in _validate_structure.)
    if h.profile != PROFILE:
        res.status = SIG_UNKNOWN_SUITE
        res.reason = f"profile {h.profile!r} != {PROFILE!r}"
        return res, False
    if h.canon != CANON_ID:
        res.status = SIG_UNKNOWN_SUITE
        res.reason = f"canon {h.canon!r} != {CANON_ID!r}"
        return res, False
    try:
        check_critical_extensions(h.crit)
    except UnknownCriticalExtensionError as exc:
        res.status, res.reason = SIG_UNKNOWN_SUITE, str(exc)
        return res, False
    except MalformedSuiteError as exc:
        res.status, res.reason = SIG_MALFORMED, str(exc)
        return res, False

    if h.key_id == "":
        res.status, res.reason = SIG_MALFORMED, "empty key_id"
        return res, False
    if h.signer_role not in KNOWN_SIGNER_ROLES:
        res.status, res.reason = SIG_MALFORMED, "unknown signer_role"
        return res, False
    want_key_type = KEY_TYPE_FOR_ALG.get(h.alg)
    if want_key_type is None:
        res.status, res.reason = (
            SIG_UNKNOWN_SUITE,
            "unrecognized algorithm; no fallback",
        )
        return res, False
    if h.key_type != want_key_type:
        res.status = SIG_MALFORMED
        res.reason = f"key_type {h.key_type!r} != {want_key_type!r} required by alg"
        return res, False
    if h.alg not in IMPLEMENTED_ALGS:
        res.status, res.reason = (
            SIG_UNIMPLEMENTED,
            "recognized suite, verifier not yet built",
        )
        return res, False

    # Implemented suite: Ed25519.
    pub = opts.trusted_keys.get(h.key_id)
    if pub is None:
        res.status, res.reason = SIG_UNKNOWN_KEY, "key_id not in trusted set"
        return res, False
    if len(pub) != ED25519_PUBLIC_KEY_SIZE:
        res.status, res.reason = SIG_MALFORMED, "trusted key has wrong size"
        return res, False
    try:
        message = signing_input(digest, h)
    except Exception as exc:  # noqa: BLE001 - mirror Go's malformed-on-error
        res.status, res.reason = SIG_MALFORMED, f"signing input: {exc}"
        return res, False
    raw = _decode_sig_wire(h.alg, s.sig)
    if raw is None:
        res.status, res.reason = SIG_MALFORMED, "signature wire malformed"
        return res, False
    if len(raw) != ED25519_SIGNATURE_SIZE:
        res.status, res.reason = (
            SIG_FAILED,
            "signature does not verify over canonical bytes",
        )
        return res, False
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(raw, message)
    except InvalidSignature:
        res.status, res.reason = (
            SIG_FAILED,
            "signature does not verify over canonical bytes",
        )
        return res, False
    res.status = SIG_VERIFIED
    return res, True


def _decode_sig_wire(alg: str, wire: str) -> bytes | None:
    """Split an "<alg>:<base64-std>" signature into raw bytes, or None if bad."""
    prefix = alg + ":"
    if not wire.startswith(prefix):
        return None
    try:
        return base64.standard_b64decode(wire[len(prefix) :])
    except (binascii.Error, ValueError):
        return None


def _mediator_key_pinned(
    assertion: Any, verified: list[tuple[str, str]], trust: dict[str, TrustEntry]
) -> bool:
    """Whether a verifying signature is trust-bound to the asserted mediator."""
    for key_id, role in verified:
        entry = trust.get(key_id)
        if entry is None:
            continue
        if entry.mediator_id != assertion.mediator_id:
            continue
        if entry.trust_domain != "" and entry.trust_domain != assertion.trust_domain:
            continue
        if entry.role != "" and entry.role != role:
            continue
        return True
    return False


def _classify_claims(ap: Appraisal) -> None:
    """Fill claimed_unverified from producer claims the verifier did not confirm."""
    verified = set(ap.verified_claims)
    seen: set[str] = set()
    for claimed in ap.assurance_claimed:
        if claimed in seen:
            continue
        seen.add(claimed)
        if claimed not in CLAIM_VERIFIED_BY:
            ap.claimed_unverified.append(claimed)
            ap.warnings.append(
                "unknown assurance claim reported claim-only: " + claimed
            )
            continue
        required = CLAIM_VERIFIED_BY[claimed]
        if not required:  # None or empty list -> never verifiable
            ap.claimed_unverified.append(claimed)
            continue
        if all(r in verified for r in required):
            continue
        ap.claimed_unverified.append(claimed)


def _sorted_unique(items: list[str]) -> list[str]:
    return sorted(set(items))


def comparable_appraisal(ap: Appraisal) -> bytes:
    """Project an Appraisal onto the cross-language comparison surface (JCS bytes).

    EXCLUDES warnings, per-signature reason text, and assurance_claimed. The
    signatures array preserves envelope order; all other arrays are sorted and
    deduplicated.
    """
    sigs: list[Any] = [
        {
            "alg": s.alg,
            "key_id": s.key_id,
            "signer_role": s.signer_role,
            "status": s.status,
        }
        for s in ap.signatures
    ]
    axes: dict[str, Any] = {}
    for axis, claims in ap.axes.items():
        if not claims:
            continue
        axes[axis] = _sorted_unique(claims)
    obj = {
        "profile": ap.profile,
        "assertion_signed": ap.assertion_signed,
        "signatures": sigs,
        "verified_claims": _sorted_unique(ap.verified_claims),
        "claimed_unverified": _sorted_unique(ap.claimed_unverified),
        "axes": axes,
        "does_not_assert": _sorted_unique(ap.does_not_assert),
    }
    return canonicalize(obj)


# Bind so a caller can treat suite/crit-ext failures as fatal uniformly.
FATAL_EXCEPTIONS = (
    EnvelopeFatalError,
    UnknownSuiteError,
    UnknownCriticalExtensionError,
)
