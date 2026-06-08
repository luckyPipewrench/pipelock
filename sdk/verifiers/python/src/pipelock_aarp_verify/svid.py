# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""X.509-SVID attestation, ported from ``internal/svid/svid.go`` and
``internal/aarp/attest.go``.

This module appraises an X.509-SVID workload-identity **proof-of-possession
binding** on top of the envelope appraisal. It is additive: it never changes the
envelope contract, never makes an envelope fatal, and never removes a core claim.
When ALL nine validation steps pass on a signed assertion, exactly three claims
are added (``signing_workload_svid_chain_validated``,
``signing_workload_svid_bound``, ``signing_workload_svid_valid_at_action_time``);
a single failure withholds all three and the
envelope appraisal is untouched.

Two distinct trust surfaces meet here:

  - ``evidence`` is producer-supplied and attacker-controlled. Every structural
    or cryptographic problem in it is appraised **fail-closed**: no claim, no
    exception escaping to the caller, never a non-zero exit.
  - ``verify`` is the verifier's pinned context (trust domain, action time,
    bundle history). A malformed pinned bundle (bad DER, inverted/empty window,
    empty domain) is an operator-configuration error: it raises
    :class:`SVIDConfigError`, which the CLI maps to exit 2 — never a fixture
    verdict.

The pinned trust-bundle history is point-in-time and offline. An SVID is
validated against the bundle generation authoritative at ``action_time`` (not
"now"), so a historical short-lived credential still validates for its action.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtensionOID

from .appraise import (
    AXIS_FRESHNESS,
    AXIS_IDENTITY,
    CLAIM_SIGNING_WORKLOAD_SVID_BOUND,
    CLAIM_SIGNING_WORKLOAD_SVID_CHAIN_VALIDATED,
    CLAIM_SIGNING_WORKLOAD_SVID_VALID_AT_ACTION_TIME,
    DNA_DEPLOYMENT_ENFORCEMENT_FROM_IDENTITY,
    DNA_NETWORK_NON_BYPASS_FROM_IDENTITY,
    Appraisal,
    VerifyOptions,
    _appraise_core,
    _classify_claims,
)
from .canonical import canonicalize
from .envelope import Envelope
from .timestamp import validate_timestamp

# ContextSVIDBinding is the domain separator for the SVID proof-of-possession
# binding. It is a signed field of the binding payload, so a signature made to
# bind one receipt can never be replayed as evidence for another.
CONTEXT_SVID_BINDING = "pipelock-aarp-v0.1/svid-receipt-binding"

# Profile string embedded in the binding payload.
PROFILE_AARP = "aarp/v0.1"

# minNonceBytes is the minimum SVID-binding nonce size: 128 bits.
MIN_NONCE_BYTES = 16

# SVID binding algorithm identifiers. The binding signature is made by the SVID
# leaf's private key, so the algorithm follows the leaf key type.
BINDING_ALG_ECDSA_P256_SHA256 = "ecdsa-p256-sha256"
BINDING_ALG_ED25519 = "ed25519"

# SPIFFE URI scheme prefix.
_SPIFFE_SCHEME = "spiffe://"

# Strict SPIFFE-ID grammar character sets, mirroring go-spiffe v2.6.0's
# spiffeid.FromString / ValidatePath under the DEFAULT build (no
# spiffeid_charset_backcompat tag). The backcompat charset (sub-delims, '~',
# gen-delims) is disabled by default, so the conformant sets are:
#
#   - trust domain (authority): lowercase letters, digits, and '.', '-', '_'.
#     Uppercase is rejected (go-spiffe lowercases nothing here — it rejects).
#   - path segment: letters (both cases), digits, and '.', '-', '_'.
#
# A loose `startswith("spiffe://")` check accepts dot-segment paths
# (".."/".") and other malformed SANs that go-spiffe rejects at parse time;
# accepting them would let a producer inflate an identity claim on a
# non-conformant SPIFFE ID. We mirror the strict grammar instead.
_SPIFFE_TD_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-_")
_SPIFFE_PATH_SEGMENT_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"
)


class SVIDConfigError(Exception):
    """Operator-configuration error in the pinned bundle/verify context (exit 2).

    The pinned bundle is trusted input. A malformed bundle (bad DER, inverted or
    empty window, empty trust domain, non-CA authority) is misconfiguration, not
    an attack the appraisal should silently absorb.
    """


class SVIDBindingError(Exception):
    """The SVID evidence/binding did not verify (fail-closed; no claim added).

    Everything in ``evidence`` is attacker-controlled, so this is caught inside
    :func:`add_svid_claims`: it withholds the three SVID claims and records a
    warning, never propagating to the caller or the exit code.
    """


# --------------------------------------------------------------------------
# Pinned trust-bundle history (ports internal/svid Generation / History).
# --------------------------------------------------------------------------


@dataclass
class _PinnedGen:
    """One pinned trust-bundle generation bound to a trust domain."""

    not_before: datetime.datetime
    not_after: datetime.datetime | None  # None == open-ended / current
    authorities: list[x509.Certificate]


class TrustBundleHistory:
    """Append-only, time-ordered set of pinned bundle generations for one domain.

    Construction enforces a monotonic, non-overlapping timeline; a divergent pin
    is rejected as a fork. Mirrors ``internal/svid.TrustBundleHistory``.
    """

    def __init__(self, trust_domain: str) -> None:
        self.trust_domain = _parse_trust_domain(trust_domain)
        self._gens: list[_PinnedGen] = []

    def append_gen(
        self,
        not_before: datetime.datetime,
        not_after: datetime.datetime | None,
        authorities: list[x509.Certificate],
    ) -> None:
        """Append one generation, enforcing the append-only / non-overlap rule."""
        _validate_generation_window(not_before, not_after)
        if not authorities:
            raise SVIDConfigError("generation has no trust authorities")
        for cert in authorities:
            _validate_authority(cert)

        if self._gens:
            last = self._gens[-1]
            # New generation must begin strictly after the previous one began.
            if not_before <= last.not_before:
                raise SVIDConfigError(
                    "generation starts at or before the previous generation"
                )
            if last.not_after is None:
                # Previous generation was open-ended: a legitimate forward
                # rotation closes it at the new generation's start.
                last.not_after = not_before
            elif not_before < last.not_after:
                # Previous generation was already closed: a new generation
                # starting before its end would overlap pinned history.
                raise SVIDConfigError("generation overlaps a closed generation")

        self._gens.append(_PinnedGen(not_before, not_after, list(authorities)))

    def bundle_at(self, at: datetime.datetime) -> list[x509.Certificate] | None:
        """Return the authorities authoritative at ``at``, or None if uncovered."""
        for g in self._gens:
            if at < g.not_before:
                continue
            if g.not_after is None or at < g.not_after:
                return g.authorities
        return None


@dataclass
class SVIDVerifyOptions:
    """The verifier's pinned trust context for one SVID binding."""

    trust_domain: str = ""
    history: TrustBundleHistory | None = None
    action_time: datetime.datetime | None = None
    allowed_spiffe_ids: list[str] = field(default_factory=list)


@dataclass
class _Validated:
    """Result of a successful point-in-time SVID validation."""

    spiffe_id: str
    leaf: x509.Certificate


# --------------------------------------------------------------------------
# Helpers shared with the Go svid package semantics.
# --------------------------------------------------------------------------


def _parse_trust_domain(s: str) -> str:
    """Validate a SPIFFE trust domain name (DNS name, not an IP).

    Mirrors ``internal/svid.parseTrustDomain``: go-spiffe lowercases and accepts
    IP literals, so a numeric host could impersonate a domain — reject it.
    """
    if s == "":
        raise SVIDConfigError("invalid trust domain: empty")
    host = s
    if host.startswith(_SPIFFE_SCHEME):
        host = host[len(_SPIFFE_SCHEME) :]
    if host == "":
        raise SVIDConfigError(f"invalid trust domain {s!r}")
    # go-spiffe permits lowercase letters, digits, and '.', '-', '_'.
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-_")
    for c in host:
        if c not in allowed:
            raise SVIDConfigError(f"invalid trust domain {s!r}: bad character {c!r}")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise SVIDConfigError(
            f"trust domain must be a DNS name, not an IP address: {s!r}"
        )
    return host


def _validate_generation_window(
    not_before: datetime.datetime, not_after: datetime.datetime | None
) -> None:
    """Reject an unset notBefore and an inverted window (matches Go)."""
    if not_before is None:
        raise SVIDConfigError("generation notBefore must be set")
    if not_after is not None and not_after <= not_before:
        raise SVIDConfigError("generation notAfter must be after notBefore")


def _validate_authority(cert: x509.Certificate) -> None:
    """Require a CA with cert-sign key usage (matches ``internal/svid``)."""
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        is_ca = bool(getattr(bc, "ca", False))
    except x509.ExtensionNotFound:
        is_ca = False
    if not is_ca:
        raise SVIDConfigError("trust authority certificate is not a CA")
    # Go: a non-zero KeyUsage that lacks KeyUsageCertSign is rejected; an absent
    # KeyUsage extension (zero) is permitted.
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if not ku.key_cert_sign:
            raise SVIDConfigError(
                "trust authority certificate lacks cert-sign key usage"
            )
    except x509.ExtensionNotFound:
        pass


def _validate_spiffe_path(path: str) -> None:
    """Reject a non-conformant SPIFFE path (ports go-spiffe ``ValidatePath``).

    An empty path is valid (a trust-domain-only ID). Otherwise the path MUST
    start with '/', each '/'-separated segment MUST be non-empty (no ``//``),
    MUST NOT be a dot-segment (``.`` or ``..``), and every character MUST be in
    the conformant path-segment set. A trailing slash is rejected. This mirrors
    spiffeid.ValidatePath exactly, including the dot-segment check that a loose
    parser would miss (the s17 fixture: ``spiffe://example.org/workload/../imposter``).
    """
    if path == "":
        return
    if path[0] != "/":
        raise SVIDBindingError("SPIFFE path has no leading slash")
    segment_start = 0
    end = 0
    for end in range(len(path)):
        c = path[end]
        if c == "/":
            seg = path[segment_start:end]
            if seg == "/":
                raise SVIDBindingError("SPIFFE path cannot contain empty segments")
            if seg in ("/.", "/.."):
                raise SVIDBindingError("SPIFFE path cannot contain dot segments")
            segment_start = end
            continue
        if c not in _SPIFFE_PATH_SEGMENT_CHARS:
            raise SVIDBindingError(f"SPIFFE path has a bad segment character {c!r}")
    end += 1  # account for the exclusive range stop, mirroring Go's segmentEnd
    last = path[segment_start:end]
    if last == "/":
        raise SVIDBindingError("SPIFFE path cannot have a trailing slash")
    if last in ("/.", "/.."):
        raise SVIDBindingError("SPIFFE path cannot contain dot segments")


def _parse_spiffe_id(uri: str) -> tuple[str, str]:
    """Parse and validate a SPIFFE ID, returning (trust_domain, path).

    Mirrors go-spiffe v2.6.0 ``spiffeid.FromString``: the scheme MUST be exactly
    ``spiffe://``; the authority (up to the first '/') is the trust domain and
    MUST be non-empty with only conformant lowercase chars (no userinfo '@', no
    port ':', no uppercase); the remainder is the path, validated by
    :func:`_validate_spiffe_path`. A query ('?') or fragment ('#') is not part of
    the conformant grammar — those characters are not in the trust-domain or
    path-segment sets, so they are rejected as bad characters. Returns the
    components on success; raises :class:`SVIDBindingError` otherwise.
    """
    if not uri.startswith(_SPIFFE_SCHEME):
        raise SVIDBindingError(f"SPIFFE ID {uri!r} does not use the spiffe scheme")
    pathidx = len(_SPIFFE_SCHEME)
    while pathidx < len(uri):
        c = uri[pathidx]
        if c == "/":
            break
        if c not in _SPIFFE_TD_CHARS:
            raise SVIDBindingError(
                f"SPIFFE ID {uri!r} has a bad trust-domain character {c!r}"
            )
        pathidx += 1
    if pathidx == len(_SPIFFE_SCHEME):
        raise SVIDBindingError(f"SPIFFE ID {uri!r} has an empty trust domain")
    trust_domain = uri[len(_SPIFFE_SCHEME) : pathidx]
    path = uri[pathidx:]
    _validate_spiffe_path(path)
    return trust_domain, path


def _spiffe_id_from_cert(leaf: x509.Certificate) -> str:
    """Return the leaf's single well-formed SPIFFE URI SAN.

    Mirrors go-spiffe ``x509svid.IDFromCert``: an X.509-SVID MUST carry exactly
    one URI SAN, and that URI MUST be a valid SPIFFE ID per the strict grammar
    (:func:`_parse_spiffe_id`). Zero, more than one, a non-SPIFFE URI, or a
    structurally malformed SPIFFE ID (dot-segment path, bad characters, empty
    trust domain) is not an SVID at all.
    """
    try:
        san = leaf.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound as exc:
        raise SVIDBindingError("leaf has no subjectAltName extension") from exc
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1:
        raise SVIDBindingError(f"leaf must have exactly one URI SAN, found {len(uris)}")
    uri = uris[0]
    # Strict parse: rejects dot-segments, bad chars, empty/uppercase trust
    # domain, userinfo, port, query, and fragment — matching go-spiffe.
    _parse_spiffe_id(uri)
    return uri


def _spiffe_trust_domain(spiffe_id: str) -> str:
    """Extract the validated trust-domain (authority) component of a SPIFFE ID."""
    trust_domain, _ = _parse_spiffe_id(spiffe_id)
    return trust_domain


def _as_utc(dt: datetime.datetime) -> datetime.datetime:
    """Normalize a datetime to timezone-aware UTC.

    cryptography's ``*_utc`` properties already return aware UTC; action_time is
    parsed aware. This guards against any naive value sneaking in.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.UTC)
    return dt.astimezone(datetime.UTC)


def _validate_svid(
    leaf: x509.Certificate,
    chain: list[x509.Certificate],
    opts: SVIDVerifyOptions,
) -> _Validated:
    """Offline, point-in-time X.509-SVID validation (ports svid.ValidateSVID).

    The corpus is single-CA, leaf-directly-under-root (no intermediates), so the
    chain is verified by finding a bundle CA authoritative at action_time that
    (a) signed the leaf and (b) is itself within its validity window at
    action_time, with the leaf also within its window.
    """
    if opts.action_time is None:
        raise SVIDConfigError("validation time (action_time) is required")
    if opts.history is None:
        raise SVIDConfigError("pinned trust bundle history is required")
    at = _as_utc(opts.action_time)
    want_td = opts.history.trust_domain

    # Extract the SPIFFE ID up front: a certificate without exactly one
    # well-formed SPIFFE URI SAN is not an SVID at all.
    spiffe_id = _spiffe_id_from_cert(leaf)
    leaf_td = _spiffe_trust_domain(spiffe_id)
    if leaf_td != want_td:
        raise SVIDBindingError(f"SVID trust domain {leaf_td!r}, expected {want_td!r}")

    authorities = opts.history.bundle_at(at)
    if authorities is None:
        raise SVIDBindingError(
            "no pinned bundle authoritative at " + at.strftime("%Y-%m-%dT%H:%M:%SZ")
        )

    _verify_chain_at(leaf, chain, authorities, at)
    return _Validated(spiffe_id=spiffe_id, leaf=leaf)


def _within_window(cert: x509.Certificate, at: datetime.datetime) -> bool:
    not_before = _as_utc(cert.not_valid_before_utc)
    not_after = _as_utc(cert.not_valid_after_utc)
    return not_before <= at <= not_after


def _verify_chain_at(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    authorities: list[x509.Certificate],
    at: datetime.datetime,
) -> None:
    """Verify the leaf chains to a pinned CA, all valid at ``at``.

    Single-CA scope: the corpus has no intermediates, so the leaf must be signed
    directly by one of the pinned root authorities. Both the leaf and the signing
    CA must be inside their validity windows at the action time.
    """
    if not _within_window(leaf, at):
        raise SVIDBindingError("leaf not valid at the requested time")

    last_err: Exception | None = None
    for ca in authorities:
        if not _within_window(ca, at):
            last_err = SVIDBindingError("CA not valid at the requested time")
            continue
        try:
            _verify_signed_by(leaf, ca)
        except Exception as exc:  # noqa: BLE001 - try the next authority
            last_err = exc
            continue
        # An intermediate-bearing chain is out of corpus scope; if present, the
        # leaf-under-root single-CA assumption does not hold and validation fails
        # closed rather than silently accepting an unvalidated middle.
        if intermediates:
            raise SVIDBindingError(
                "multi-certificate chain is out of single-CA corpus scope"
            )
        return
    if last_err is not None:
        raise SVIDBindingError(
            f"chain does not validate to a pinned bundle: {last_err}"
        )
    raise SVIDBindingError("chain does not validate to a pinned bundle")


def _verify_signed_by(child: x509.Certificate, issuer: x509.Certificate) -> None:
    """Verify ``child``'s signature under ``issuer``'s public key.

    Issuer/subject DN must match (Go's x509 path build requires it), then the
    signature over the child's tbs bytes must verify under the issuer key.
    """
    if child.issuer != issuer.subject:
        raise SVIDBindingError("leaf issuer does not match CA subject")
    pub = issuer.public_key()
    tbs = child.tbs_certificate_bytes
    sig = child.signature
    sig_hash = child.signature_hash_algorithm
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(sig, tbs, ec.ECDSA(sig_hash))
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        pub.verify(sig, tbs)
    elif isinstance(pub, rsa.RSAPublicKey):
        pub.verify(sig, tbs, padding.PKCS1v15(), sig_hash)
    else:
        raise SVIDBindingError("unsupported CA public key type")


# --------------------------------------------------------------------------
# Binding payload + proof-of-possession verification.
# --------------------------------------------------------------------------


def binding_canonical(env: Envelope, ev: dict[str, Any], spiffe_id: str) -> bytes:
    """JCS-canonical bytes of the binding payload the leaf key signs.

    The assurance_assertion_sha256 is the SHA-256 of the JCS-canonical SIGNED
    payload — the same digest the envelope signatures cover.
    """
    bp = {
        "action_record_sha256": env.subject.action_record_sha256,
        "assurance_assertion_sha256": env.payload_digest(),
        "context": CONTEXT_SVID_BINDING,
        "issued_at": str(ev.get("issued_at", "")),
        "mediator_id": env.assertion.mediator_id,
        "nonce": str(ev.get("nonce", "")),
        "profile": PROFILE_AARP,
        "receipt_envelope_sha256": env.subject.receipt_envelope_sha256,
        "receipt_signer_key": env.subject.receipt_signer_key,
        "spiffe_id": spiffe_id,
    }
    return canonicalize(bp)


def _hex_sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _verify_leaf_signature(
    leaf: x509.Certificate, alg: str, msg: bytes, sig: bytes
) -> None:
    """Verify a proof-of-possession signature under the leaf public key.

    Dispatches on the declared algorithm AND the actual key type; a declared
    algorithm that does not match the key type fails closed. For ECDSA the leaf
    key MUST be curve P-256 (SECP256R1): ASN.1 ECDSA verification is
    curve-agnostic, so without this explicit check a P-384/P-521 leaf would
    verify under an alg id that promises P-256.
    """
    pub = leaf.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        if alg != BINDING_ALG_ECDSA_P256_SHA256:
            raise SVIDBindingError(f"binding alg {alg!r} does not match ECDSA leaf key")
        if not isinstance(pub.curve, ec.SECP256R1):
            raise SVIDBindingError(
                f"ECDSA leaf curve {pub.curve.name}, binding alg requires P-256"
            )
        # cryptography expects the ASN.1/DER ECDSA signature and hashes the
        # message itself; pass the raw message under ECDSA(SHA256).
        # cryptography raises InvalidSignature on a bad signature and may raise
        # ValueError/other on a malformed DER signature; both fail closed.
        try:
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        except Exception as exc:  # noqa: BLE001 - bad/malformed sig -> fail closed
            raise SVIDBindingError("ECDSA proof-of-possession does not verify") from exc
        return
    if isinstance(pub, ed25519.Ed25519PublicKey):
        if alg != BINDING_ALG_ED25519:
            raise SVIDBindingError(
                f"binding alg {alg!r} does not match Ed25519 leaf key"
            )
        try:
            pub.verify(sig, msg)
        except InvalidSignature as exc:
            raise SVIDBindingError(
                "Ed25519 proof-of-possession does not verify"
            ) from exc
        return
    raise SVIDBindingError(f"unsupported SVID leaf key type {type(pub).__name__}")


def _decode_b64_std(s: str, what: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SVIDBindingError(f"{what}: base64: {exc}") from exc


def _load_leaf(ev: dict[str, Any]) -> tuple[x509.Certificate, list[x509.Certificate]]:
    """Parse the leaf DER (and any intermediates) from the evidence."""
    leaf_b64 = ev.get("leaf_der_b64")
    if not isinstance(leaf_b64, str) or leaf_b64 == "":
        raise SVIDBindingError("empty leaf certificate DER")
    leaf_der = _decode_b64_std(leaf_b64, "leaf_der_b64")
    if len(leaf_der) == 0:
        raise SVIDBindingError("empty leaf certificate DER")
    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
    except Exception as exc:  # noqa: BLE001 - malformed DER -> fail closed
        raise SVIDBindingError(f"leaf_der_b64: parse certificate: {exc}") from exc
    chain: list[x509.Certificate] = []
    chain_b64 = ev.get("chain_der_b64") or []
    for i, c in enumerate(chain_b64):
        der = _decode_b64_std(str(c), f"chain_der_b64[{i}]")
        try:
            chain.append(x509.load_der_x509_certificate(der))
        except Exception as exc:  # noqa: BLE001
            raise SVIDBindingError(
                f"chain_der_b64[{i}]: parse certificate: {exc}"
            ) from exc
    return leaf, chain


def verify_svid_binding(
    env: Envelope, ev: dict[str, Any], opts: SVIDVerifyOptions
) -> str:
    """Verify the SVID evidence is a genuine, receipt-bound X.509-SVID PoP proof.

    Fail-closed: any structural problem, chain-validation failure,
    digest/signer/spiffe mismatch, or bad proof-of-possession signature raises
    :class:`SVIDBindingError` and confirms nothing. Returns the validated SPIFFE
    ID on success. Runs the nine spec steps in order, stopping at the first
    failure.
    """
    # Step 1: evidence.type must be "x509".
    ev_type = ev.get("type")
    if ev_type != "x509":
        raise SVIDBindingError(
            f"evidence type {ev_type!r} (only x509 counts as verified attestation)"
        )

    issued_at = ev.get("issued_at")
    if not isinstance(issued_at, str):
        raise SVIDBindingError("issued_at must be a string")
    # Step 2: issued_at must be valid RFC3339Nano.
    try:
        validate_timestamp(issued_at)
    except Exception as exc:  # noqa: BLE001 - any grammar failure -> fail closed
        raise SVIDBindingError(f"issued_at: {exc}") from exc

    # Step 3: nonce must be base64url (no padding), decoding to >= 16 bytes.
    nonce = ev.get("nonce")
    if not isinstance(nonce, str):
        raise SVIDBindingError("nonce must be a string")
    try:
        nonce_bytes = _b64url_nopad_decode(nonce)
    except Exception as exc:  # noqa: BLE001
        raise SVIDBindingError(f"nonce not base64url: {exc}") from exc
    if len(nonce_bytes) < MIN_NONCE_BYTES:
        raise SVIDBindingError(
            f"nonce {len(nonce_bytes)} bytes, want >= {MIN_NONCE_BYTES}"
        )

    # Step 4: binding.context must equal the domain separator.
    binding = ev.get("binding")
    if not isinstance(binding, dict):
        raise SVIDBindingError("binding must be an object")
    if binding.get("context") != CONTEXT_SVID_BINDING:
        raise SVIDBindingError(f"binding context {binding.get('context')!r}")

    leaf, chain = _load_leaf(ev)

    # Step 5: offline point-in-time chain validation at action_time, plus the
    # single-URI SPIFFE SAN and trust-domain == verify.trust_domain checks.
    validated = _validate_svid(leaf, chain, opts)

    # Step 6: claimed spiffe_id must equal the validated URI SAN (no
    # substitution), and be permitted by allowed_spiffe_ids when non-empty.
    claimed_spiffe = ev.get("spiffe_id")
    if claimed_spiffe != validated.spiffe_id:
        raise SVIDBindingError(
            f"evidence spiffe_id {claimed_spiffe!r} != validated "
            f"{validated.spiffe_id!r}"
        )
    if not _spiffe_id_permitted(validated.spiffe_id, opts.allowed_spiffe_ids):
        raise SVIDBindingError(
            f"spiffe_id not permitted by trust policy: {validated.spiffe_id!r}"
        )

    # Step 7: assertion.trust_domain must be present and == verify.trust_domain.
    if env.assertion.trust_domain == "":
        raise SVIDBindingError(
            "assertion.trust_domain is required with an SVID binding"
        )
    if env.assertion.trust_domain != opts.trust_domain:
        raise SVIDBindingError(
            f"assertion trust_domain {env.assertion.trust_domain!r} != validated "
            f"SVID trust domain {opts.trust_domain!r}"
        )

    # Step 8: issued_at must fall within the leaf [NotBefore, NotAfter] window,
    # compared at FULL nanosecond precision (Go uses time.Time nanoseconds). A
    # microsecond-truncated datetime would wrongly accept an issued_at one
    # nanosecond past a whole-second leaf expiry (the s19 fixture).
    issued_ns = _rfc3339nano_to_ns(issued_at)
    leaf_nb_ns = _datetime_to_ns(validated.leaf.not_valid_before_utc)
    leaf_na_ns = _datetime_to_ns(validated.leaf.not_valid_after_utc)
    if issued_ns < leaf_nb_ns or issued_ns > leaf_na_ns:
        raise SVIDBindingError(
            f"binding issued_at {issued_at} outside the SVID leaf validity window"
        )

    # Step 9: the proof-of-possession signature must verify under the leaf key.
    canonical = binding_canonical(env, ev, validated.spiffe_id)
    declared_digest = binding.get("payload_sha256")
    if isinstance(declared_digest, str) and declared_digest != "":
        if declared_digest != _hex_sha256(canonical):
            raise SVIDBindingError("binding payload_sha256 mismatch")
    sig_b64 = binding.get("signature_b64")
    if not isinstance(sig_b64, str):
        raise SVIDBindingError("binding signature_b64 must be a string")
    sig = _decode_b64_std(sig_b64, "binding signature")
    alg = binding.get("alg")
    if not isinstance(alg, str):
        raise SVIDBindingError("binding alg must be a string")
    _verify_leaf_signature(validated.leaf, alg, canonical, sig)
    return validated.spiffe_id


def _b64url_nopad_decode(s: str) -> bytes:
    """Decode base64url WITHOUT padding, rejecting any '=' padding (matches Go).

    Go's ``base64.RawURLEncoding`` rejects padding characters outright, so a nonce
    carrying '=' is malformed, not merely tolerated.
    """
    if "=" in s:
        raise ValueError("unexpected padding in raw base64url")
    if any(c in s for c in "+/"):
        raise ValueError("standard-base64 character in base64url value")
    pad = (-len(s)) % 4
    return base64.b64decode(
        (s + ("=" * pad)).encode("ascii"), altchars=b"-_", validate=True
    )


def _parse_rfc3339nano(s: str) -> datetime.datetime:
    """Parse an RFC3339Nano timestamp to an aware UTC datetime.

    Already validated by validate_timestamp. Python's ``datetime`` has only
    microsecond resolution, so this truncates sub-microsecond fractional digits.
    That is fine for the bundle/action-time generation lookup (generations are
    pinned at whole-second-ish boundaries), but it is NOT safe for the leaf
    validity-window check in step 8, where a sub-microsecond difference is
    security-relevant — use :func:`_rfc3339nano_to_ns` there instead.
    """
    iso = s
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    # Python 3.12 fromisoformat handles offsets and fractional seconds; trim to
    # microsecond precision for any nanosecond input it cannot represent.
    try:
        dt = datetime.datetime.fromisoformat(iso)
    except ValueError:
        # Trim fractional seconds to 6 digits as a fallback.
        if "." in iso:
            head, tail = iso.split(".", 1)
            # tail is digits then offset; keep up to 6 frac digits.
            frac = ""
            rest = ""
            for i, ch in enumerate(tail):
                if ch.isdigit():
                    frac += ch
                else:
                    rest = tail[i:]
                    break
            iso = head + "." + frac[:6] + rest
            dt = datetime.datetime.fromisoformat(iso)
        else:
            raise
    return _as_utc(dt)


def _datetime_to_ns(dt: datetime.datetime) -> int:
    """Whole nanoseconds since the Unix epoch for an aware datetime.

    ``datetime`` carries at most microsecond resolution, so the result is a
    microsecond multiple. Used for the leaf-window bounds, which originate from
    X.509 ``notBefore``/``notAfter`` (whole-second granularity in practice).
    """
    aware = _as_utc(dt)
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)
    delta = aware - epoch
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + (
        delta.microseconds * 1_000
    )


def _rfc3339nano_to_ns(s: str) -> int:
    """Nanoseconds since the Unix epoch for an RFC3339Nano timestamp.

    Preserves the FULL nanosecond fraction (Python ``datetime`` cannot, so
    :func:`_parse_rfc3339nano` would lose the sub-microsecond digits). Go's
    ``time.Parse(time.RFC3339Nano, ...)`` keeps nanosecond precision, so the
    leaf validity-window comparison in step 8 must too: the s19 fixture stamps
    ``issued_at`` one nanosecond past a whole-second leaf ``notAfter``, and Go
    rejects it. The timestamp is pre-validated by ``validate_timestamp``.

    Fractional digits beyond nanosecond precision (>9) are truncated, matching
    Go, which represents ``time.Time`` at nanosecond resolution.
    """
    iso = s
    frac_ns = 0
    if "." in iso:
        # Split off the fractional-seconds digits without disturbing the zone.
        head, tail = iso.split(".", 1)
        digits = ""
        rest = ""
        for i, ch in enumerate(tail):
            if ch.isdigit():
                digits += ch
            else:
                rest = tail[i:]
                break
        # Truncate to nanosecond precision (9 digits), then scale to ns.
        nano_digits = digits[:9]
        frac_ns = int(nano_digits.ljust(9, "0")) if nano_digits else 0
        iso = head + rest
    # Parse the now-fractionless timestamp (whole seconds + zone) to an integer
    # second count, then add the nanosecond fraction back.
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    whole = datetime.datetime.fromisoformat(iso)
    return _datetime_to_ns(whole) + frac_ns


def _spiffe_id_permitted(spiffe_id: str, allowed: list[str]) -> bool:
    """Empty allowed set permits any validated SPIFFE ID in the trust domain."""
    if not allowed:
        return True
    return spiffe_id in allowed


# --------------------------------------------------------------------------
# Claim attachment (ports internal/aarp.addSVIDClaims).
# --------------------------------------------------------------------------


def add_svid_claims(
    ap: Appraisal, env: Envelope, ev: dict[str, Any], opts: SVIDVerifyOptions
) -> None:
    """Attach the three SVID claims only on a signed assertion whose binding verifies.

    Never removes a core claim, never makes the envelope fatal, never inflates.
    An unsigned assertion gets a warning and nothing attached. A signed assertion
    whose binding fails attaches nothing (the producer's workload_identity_verified
    claim then lands in claimed_unverified via the standard classifier).
    """
    if not ap.assertion_signed:
        ap.warnings.append(
            "SVID evidence present but assertion not signed; workload identity "
            "reported claim-only"
        )
        return
    try:
        verify_svid_binding(env, ev, opts)
    except SVIDBindingError as exc:
        ap.warnings.append("SVID attestation did not verify: " + str(exc))
        return
    except Exception as exc:  # noqa: BLE001 - defense-in-depth fail-closed
        # Evidence is attacker-controlled: any unexpected error verifying it must
        # withhold the SVID claims, never make the envelope fatal. The typed
        # SVIDBindingError path above covers the known cases; this guards against
        # a parser/crypto surprise being weaponized into an envelope rejection.
        ap.warnings.append("SVID attestation did not verify: " + str(exc))
        return
    ap.add_verified(CLAIM_SIGNING_WORKLOAD_SVID_CHAIN_VALIDATED, AXIS_IDENTITY)
    ap.add_verified(CLAIM_SIGNING_WORKLOAD_SVID_BOUND, AXIS_IDENTITY)
    ap.add_verified(CLAIM_SIGNING_WORKLOAD_SVID_VALID_AT_ACTION_TIME, AXIS_FRESHNESS)
    # A verified signing-workload identity is NOT a deployment or non-bypass proof.
    ap.add_does_not_assert(
        DNA_NETWORK_NON_BYPASS_FROM_IDENTITY,
        DNA_DEPLOYMENT_ENFORCEMENT_FROM_IDENTITY,
    )


def appraise_with_svid(
    env: Envelope,
    ev: dict[str, Any],
    opts: VerifyOptions,
    svid_opts: SVIDVerifyOptions,
) -> Appraisal:
    """Core appraisal then, when SVID evidence is present, the SVID claims.

    Ports ``internal/aarp.AppraiseWithSVID``: appraise core, add SVID claims
    (only on a signed assertion whose binding verifies), then classify producer
    claims. Raises only the envelope-fatal exceptions ``_appraise_core`` raises;
    an SVID failure is absorbed by :func:`add_svid_claims` and never propagates.
    """
    ap = _appraise_core(env, opts)
    add_svid_claims(ap, env, ev, svid_opts)
    _classify_claims(ap)
    ap.finalize()
    return ap


# --------------------------------------------------------------------------
# Sidecar parsing (ports cmd/pipelock-verifier/aarp_svid.go loadSVIDFile).
# --------------------------------------------------------------------------

# Allowed keys per object, mirroring Go's DisallowUnknownFields on these structs.
# evidence is decoded straight into aarp.SVIDEvidence; verify is the pinned trust.
_EVIDENCE_KEYS = {
    "type",
    "spiffe_id",
    "leaf_der_b64",
    "chain_der_b64",
    "nonce",
    "issued_at",
    "binding",
}
_BINDING_KEYS = {"alg", "context", "payload_sha256", "signature_b64"}
_VERIFY_KEYS = {"trust_domain", "action_time", "allowed_spiffe_ids", "bundle"}
_BUNDLE_GEN_KEYS = {"not_before", "not_after", "authorities_der_b64"}
_SIDECAR_KEYS = {"evidence", "verify"}


def _reject_unknown(obj: dict[str, Any], allowed: set[str], where: str) -> None:
    for key in obj:
        if key not in allowed:
            raise SVIDConfigError(f"unknown field {key!r} in {where}")


def load_svid_file(path: str) -> tuple[dict[str, Any], SVIDVerifyOptions]:
    """Read a --svid sidecar into producer evidence and pinned SVID options.

    Strict parse: rejects unknown fields and trailing data after the JSON value
    (mirroring Go's DisallowUnknownFields + trailing-token check). A structural
    problem in the operator-pinned bundle (bad DER, unparseable window, empty
    domain) raises :class:`SVIDConfigError` (exit 2), never a fixture verdict —
    the bundle is trusted input. Attacks live in the evidence, appraised
    fail-closed by :func:`verify_svid_binding`.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise SVIDConfigError(f"read svid file: {exc}") from exc

    # Strict parse: reject duplicate keys, then reject trailing tokens by using a
    # decoder that consumes exactly one value and asserting nothing follows.
    dec = json.JSONDecoder(object_pairs_hook=_no_dup_keys)
    text = data.decode("utf-8")
    try:
        sf, end = dec.raw_decode(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise SVIDConfigError(f"parse svid file: {exc}") from exc
    if text[end:].strip() != "":
        raise SVIDConfigError(
            "parse svid file: unexpected trailing data after JSON value"
        )
    if not isinstance(sf, dict):
        raise SVIDConfigError("parse svid file: top-level value is not an object")
    _reject_unknown(sf, _SIDECAR_KEYS, "svid file")

    evidence = sf.get("evidence")
    if not isinstance(evidence, dict):
        raise SVIDConfigError("parse svid file: evidence must be an object")
    _reject_unknown(evidence, _EVIDENCE_KEYS, "evidence")
    binding = evidence.get("binding")
    if binding is not None:
        if not isinstance(binding, dict):
            raise SVIDConfigError("parse svid file: evidence.binding must be an object")
        _reject_unknown(binding, _BINDING_KEYS, "evidence.binding")

    verify = sf.get("verify")
    if not isinstance(verify, dict):
        raise SVIDConfigError("parse svid file: verify must be an object")
    _reject_unknown(verify, _VERIFY_KEYS, "verify")

    trust_domain = str(verify.get("trust_domain", ""))
    history = TrustBundleHistory(trust_domain)
    bundle = verify.get("bundle") or []
    if not isinstance(bundle, list):
        raise SVIDConfigError("parse svid file: verify.bundle must be an array")
    for i, gen in enumerate(bundle):
        if not isinstance(gen, dict):
            raise SVIDConfigError(f"parse svid file: bundle[{i}] must be an object")
        _reject_unknown(gen, _BUNDLE_GEN_KEYS, f"bundle[{i}]")
        nb_raw = gen.get("not_before")
        if not isinstance(nb_raw, str):
            raise SVIDConfigError(f"bundle[{i}].not_before must be a string")
        try:
            not_before = _parse_bundle_time(nb_raw)
        except Exception as exc:  # noqa: BLE001
            raise SVIDConfigError(f"bundle[{i}].not_before: {exc}") from exc
        not_after: datetime.datetime | None = None
        na_raw = gen.get("not_after", "")
        if na_raw != "" and na_raw is not None:
            if not isinstance(na_raw, str):
                raise SVIDConfigError(f"bundle[{i}].not_after must be a string")
            try:
                not_after = _parse_bundle_time(na_raw)
            except Exception as exc:  # noqa: BLE001
                raise SVIDConfigError(f"bundle[{i}].not_after: {exc}") from exc
        auth_b64 = gen.get("authorities_der_b64") or []
        if not isinstance(auth_b64, list):
            raise SVIDConfigError(f"bundle[{i}].authorities_der_b64 must be an array")
        authorities: list[x509.Certificate] = []
        for j, der_b64 in enumerate(auth_b64):
            if not isinstance(der_b64, str):
                raise SVIDConfigError(
                    f"bundle[{i}].authorities_der_b64[{j}] must be a string"
                )
            try:
                der = base64.b64decode(der_b64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise SVIDConfigError(
                    f"bundle[{i}].authorities_der_b64[{j}]: {exc}"
                ) from exc
            try:
                authorities.append(x509.load_der_x509_certificate(der))
            except Exception as exc:  # noqa: BLE001
                raise SVIDConfigError(
                    f"bundle[{i}].authorities_der_b64[{j}]: parse certificate: {exc}"
                ) from exc
        try:
            history.append_gen(not_before, not_after, authorities)
        except SVIDConfigError as exc:
            raise SVIDConfigError(f"bundle[{i}]: {exc}") from exc

    action_raw = verify.get("action_time")
    if not isinstance(action_raw, str):
        raise SVIDConfigError("verify.action_time must be a string")
    try:
        action_time = _parse_bundle_time(action_raw)
    except Exception as exc:  # noqa: BLE001
        raise SVIDConfigError(f"verify.action_time: {exc}") from exc

    allowed = verify.get("allowed_spiffe_ids") or []
    if not isinstance(allowed, list) or not all(isinstance(a, str) for a in allowed):
        raise SVIDConfigError("verify.allowed_spiffe_ids must be a string array")

    opts = SVIDVerifyOptions(
        trust_domain=trust_domain,
        history=history,
        action_time=action_time,
        allowed_spiffe_ids=list(allowed),
    )
    return evidence, opts


def _no_dup_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """object_pairs_hook that rejects duplicate keys at any depth (Go-strict)."""
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r} in JSON object")
        out[k] = v
    return out


def _parse_bundle_time(s: str) -> datetime.datetime:
    """Parse an RFC3339Nano bundle/action time to aware UTC.

    The bundle is operator-pinned trust, so a bad timestamp here is a config
    error (the caller wraps it as SVIDConfigError). Matches Go's
    time.Parse(time.RFC3339Nano, ...) acceptance via the shared validator.
    """
    validate_timestamp(s)
    return _parse_rfc3339nano(s)
