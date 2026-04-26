#!/usr/bin/env python3
"""Cross-implementation verifier for v2.4 learn-and-lock golden vectors.

Loads each Go-emitted golden fixture, independently recomputes the JCS
preimage in Python, and verifies the Ed25519 PureEdDSA signature against
the RFC 8032 test public key. Proves byte-identical canonicalization
between the Go and Python implementations.

Usage:
    python3 verify.py <golden-dir>
    python3 verify.py --fingerprint
    python3 verify.py --recovery-authorization <path>
    python3 verify.py --root-transition <path>

Exits 0 on success, 1 on any verification failure.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SIG_PREFIX = "ed25519:"
FINGERPRINT_ALGORITHM = "sha256"

# sha256:<64 lowercase hex chars>
_SHA256_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def load_test_pubkey(golden_dir: Path) -> bytes:
    keys_path = golden_dir / "ed25519_test_keys.json"
    with keys_path.open() as f:
        keys = json.load(f)
    return bytes.fromhex(keys["public_key_hex"])


def strip_sig_prefix(sig_str: str) -> bytes:
    if not sig_str.startswith(SIG_PREFIX):
        raise ValueError(f"signature lacks ed25519: prefix: {sig_str!r}")
    return bytes.fromhex(sig_str[len(SIG_PREFIX):])


def verify_envelope(fixture: Path, pubkey: bytes) -> tuple[bool, str]:
    """Verify an envelope-style fixture (body + signature wrapper).

    Returns (ok, message).
    """
    with fixture.open() as f:
        envelope = json.load(f)

    if "body" not in envelope:
        return False, "missing body field"

    body = envelope["body"]
    preimage = jcs.canonicalize(body)

    pk = Ed25519PublicKey.from_public_bytes(pubkey)

    if "signature" in envelope:
        sig = strip_sig_prefix(envelope["signature"])
        try:
            pk.verify(sig, preimage)
            return True, ""
        except InvalidSignature as e:
            return False, f"verify failed: {e}"
    elif "signatures" in envelope:
        sigs = envelope["signatures"]
        # Fail closed on a missing-signature envelope. An empty list would
        # otherwise skip the verify loop and silently return ok, even though
        # no Ed25519.verify() ever ran. Cross-implementation oracles must
        # never have a "no signatures = OK" path.
        if not sigs:
            return False, "empty signatures array"
        for i, sig_obj in enumerate(sigs):
            sig = strip_sig_prefix(sig_obj["signature"])
            try:
                pk.verify(sig, preimage)
            except InvalidSignature as e:
                return False, f"signatures[{i}] verify failed: {e}"
        return True, ""
    else:
        return False, "no signature field"


def verify_evidence_receipt(fixture: Path, pubkey: bytes) -> tuple[bool, str]:
    """EvidenceReceipt is its own envelope: signature is a sibling field
    inside the receipt struct. Preimage = receipt with signature zeroed."""
    with fixture.open() as f:
        receipt = json.load(f)

    sig_obj = receipt.get("signature")
    if not sig_obj or not sig_obj.get("signature"):
        return False, "missing signature.signature"

    sig = strip_sig_prefix(sig_obj["signature"])

    # Zero the signature object for preimage computation.
    receipt_copy = dict(receipt)
    # The four fields below MUST mirror the Go SignatureProof struct in
    # internal/contract/receipt/receipt.go. If a field is added there, add it
    # here too with the JSON-zero-value of its type, otherwise the Python
    # preimage will diverge from Go and signature verification will fail.
    receipt_copy["signature"] = {
        "signer_key_id": "",
        "key_purpose": "",
        "algorithm": "",
        "signature": "",
    }
    preimage = jcs.canonicalize(receipt_copy)

    pk = Ed25519PublicKey.from_public_bytes(pubkey)
    try:
        pk.verify(sig, preimage)
        return True, ""
    except InvalidSignature as e:
        return False, f"verify failed: {e}"


def fingerprint(pubkey_bytes: bytes) -> str:
    """Pipelock canonical key fingerprint: "sha256:" + lowercase hex of
    sha256 over the raw 32-byte ed25519 public key.

    Cross-implementation: the Go Fingerprint() function computes the same
    value byte for byte. Changing this format requires a roster
    schema_version bump.
    """
    if len(pubkey_bytes) != 32:
        raise ValueError(
            f"expected 32-byte ed25519 public key, got {len(pubkey_bytes)}"
        )
    import hashlib

    return FINGERPRINT_ALGORITHM + ":" + hashlib.sha256(pubkey_bytes).hexdigest()


def verify_fingerprint(pubkey_hex: str, expected_fingerprint: str) -> None:
    """Decode a hex public key, compute its fingerprint, and compare to expected.

    Raises ValueError on mismatch or invalid input.
    """
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    computed = fingerprint(pubkey_bytes)
    if computed != expected_fingerprint:
        raise ValueError(
            f"fingerprint mismatch: computed {computed}, expected {expected_fingerprint}"
        )


def _parse_rfc3339(s: str) -> datetime:
    """Parse an RFC 3339 timestamp string into a timezone-aware datetime.

    Raises ValueError on malformed input.
    """
    return datetime.fromisoformat(s)


def verify_recovery_authorization(
    envelope_json_bytes: bytes,
    recovery_root_pubkey_bytes: bytes,
    pinned_recovery_root_fingerprint: str,
    now_iso: str,
) -> dict:
    """Verify a recovery_authorization envelope.

    Performs:
      - Structural validation matching Go RecoveryAuthorizationBody.Validate()
      - Time-window check using now_iso
      - Fingerprint pinning
      - Ed25519 signature verification over JCS-canonicalized body

    Returns the parsed body dict on success; raises ValueError on failure.
    """
    envelope = json.loads(envelope_json_bytes)

    if "body" not in envelope:
        raise ValueError("missing body field")
    if "signature" not in envelope:
        raise ValueError("missing signature field")

    body = envelope["body"]

    # Structural validation.
    if body.get("schema_version") != 1:
        raise ValueError(
            f"unsupported schema_version: {body.get('schema_version')}"
        )
    if not body.get("reason"):
        raise ValueError("reason is required")
    if not body.get("operator_identity"):
        raise ValueError("operator_identity is required")

    target_hash = body.get("target_roster_hash", "")
    if not _SHA256_HASH_RE.match(target_hash):
        raise ValueError(f"target_roster_hash format invalid: {target_hash!r}")

    # Parse timestamps (raises ValueError on bad format).
    issued_at = _parse_rfc3339(body["issued_at"])
    expires_at = _parse_rfc3339(body["expires_at"])
    now = _parse_rfc3339(now_iso)

    # Time-window checks.
    if now < issued_at:
        raise ValueError(
            f"recovery authorization issued_at is in the future: "
            f"now={now_iso}, issued_at={body['issued_at']}"
        )
    if now > expires_at:
        raise ValueError(
            f"recovery authorization is expired: "
            f"now={now_iso}, expires_at={body['expires_at']}"
        )
    delta = expires_at - now
    if delta.total_seconds() > 3600:
        raise ValueError(
            f"recovery authorization expires more than 1h in the future: "
            f"delta={delta}"
        )

    # Fingerprint pinning.
    computed_fp = fingerprint(recovery_root_pubkey_bytes)
    if computed_fp != pinned_recovery_root_fingerprint:
        raise ValueError(
            f"fingerprint mismatch: computed {computed_fp}, "
            f"pinned {pinned_recovery_root_fingerprint}"
        )

    # Signature verification.
    preimage = jcs.canonicalize(body)
    sig = strip_sig_prefix(envelope["signature"])
    pk = Ed25519PublicKey.from_public_bytes(recovery_root_pubkey_bytes)
    try:
        pk.verify(sig, preimage)
    except InvalidSignature as e:
        raise ValueError(f"signature verify failed: {e}") from e

    return body


def verify_root_transition(
    envelope_json_bytes: bytes,
    old_pubkey_bytes: bytes,
    new_pubkey_bytes: bytes,
    pinned_old_fingerprint: str = "",
) -> dict:
    """Verify a root_transition envelope with dual signatures.

    Performs:
      - Structural validation matching Go RootTransitionBody.Validate()
      - Fingerprint matching for both old and new keys
      - Optional operator-pin check (if pinned_old_fingerprint is non-empty)
      - Dual Ed25519 signature verification over JCS-canonicalized body

    Returns the parsed body dict on success; raises ValueError on failure.
    """
    envelope = json.loads(envelope_json_bytes)

    if "body" not in envelope:
        raise ValueError("missing body field")
    if "old_signature" not in envelope:
        raise ValueError("missing old_signature field")
    if "new_signature" not in envelope:
        raise ValueError("missing new_signature field")

    body = envelope["body"]

    # Structural validation.
    if body.get("schema_version") != 1:
        raise ValueError(
            f"unsupported schema_version: {body.get('schema_version')}"
        )

    root_kind = body.get("root_kind", "")
    if root_kind not in ("roster-root", "recovery-root"):
        raise ValueError(f"root_kind must be roster-root or recovery-root: {root_kind!r}")

    old_fp = body.get("old_fingerprint", "")
    new_fp = body.get("new_fingerprint", "")
    if not _SHA256_HASH_RE.match(old_fp):
        raise ValueError(f"old_fingerprint format invalid: {old_fp!r}")
    if not _SHA256_HASH_RE.match(new_fp):
        raise ValueError(f"new_fingerprint format invalid: {new_fp!r}")
    if old_fp == new_fp:
        raise ValueError("old_fingerprint and new_fingerprint must differ")

    _parse_rfc3339(body["effective_at"])  # validates format

    if not body.get("reason"):
        raise ValueError("reason is required")

    # Fingerprint matching.
    computed_old_fp = fingerprint(old_pubkey_bytes)
    if computed_old_fp != old_fp:
        raise ValueError(
            f"old key fingerprint mismatch: computed {computed_old_fp}, "
            f"body has {old_fp}"
        )
    computed_new_fp = fingerprint(new_pubkey_bytes)
    if computed_new_fp != new_fp:
        raise ValueError(
            f"new key fingerprint mismatch: computed {computed_new_fp}, "
            f"body has {new_fp}"
        )

    # Optional operator-pin check.
    if pinned_old_fingerprint and old_fp != pinned_old_fingerprint:
        raise ValueError(
            f"old_fingerprint does not match operator-pinned fingerprint: "
            f"body={old_fp}, pinned={pinned_old_fingerprint}"
        )

    # Dual signature verification.
    preimage = jcs.canonicalize(body)

    old_sig = strip_sig_prefix(envelope["old_signature"])
    old_pk = Ed25519PublicKey.from_public_bytes(old_pubkey_bytes)
    try:
        old_pk.verify(old_sig, preimage)
    except InvalidSignature as e:
        raise ValueError(f"old_signature verify failed: {e}") from e

    new_sig = strip_sig_prefix(envelope["new_signature"])
    new_pk = Ed25519PublicKey.from_public_bytes(new_pubkey_bytes)
    try:
        new_pk.verify(new_sig, preimage)
    except InvalidSignature as e:
        raise ValueError(f"new_signature verify failed: {e}") from e

    return body


# Map fixture filename -> verifier function.
VERIFIERS = {
    "valid_contract.json": verify_envelope,
    "valid_active_manifest.json": verify_envelope,
    "valid_compile_manifest.json": verify_envelope,
    "valid_tombstone.json": verify_envelope,
    "valid_key_roster.json": verify_envelope,
    "valid_verification_metadata.json": verify_envelope,
    "valid_evidence_receipt_proxy_decision.json": verify_evidence_receipt,
}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify.py <golden-dir>", file=sys.stderr)
        return 2

    golden_dir = Path(argv[1])
    if not golden_dir.is_dir():
        print(f"not a directory: {golden_dir}", file=sys.stderr)
        return 2

    pubkey = load_test_pubkey(golden_dir)

    failures = 0
    for fixture_name, verifier in sorted(VERIFIERS.items()):
        fixture = golden_dir / fixture_name
        if not fixture.exists():
            print(f"FAIL {fixture_name}: file missing")
            failures += 1
            continue
        ok, msg = verifier(fixture, pubkey)
        if ok:
            print(f"OK {fixture_name}")
        else:
            print(f"FAIL {fixture_name}: {msg}")
            failures += 1

    if failures > 0:
        print(f"{failures} failure(s)")
        return 1
    print("all golden vectors verified")
    return 0


def smoke_test_fingerprint() -> int:
    """Standalone smoke test for the fingerprint function.

    Uses the RFC 8032 section 7.1 test vector 1 public key.
    The expected value must match the Go rfcTestPubFingerprint constant.
    """
    rfc_pubkey_hex = (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    expected = (
        "sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"
    )
    try:
        verify_fingerprint(rfc_pubkey_hex, expected)
        print(f"OK fingerprint: {expected}")
        return 0
    except ValueError as e:
        print(f"FAIL fingerprint: {e}")
        return 1


# --- Deterministic key seeds (must match Go golden_vectors_test.go) ---

# Recovery-root seed (same as Go goldenRecoveryRootSeedHex).
_GOLDEN_RECOVERY_ROOT_SEED_HEX = (
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)

# New-root seed for root-transition (same as Go goldenNewRootSeedHex).
_GOLDEN_NEW_ROOT_SEED_HEX = (
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fc"
)

# Old-root seed (RFC 8032 test 1 seed, same as Go goldenOldRootSeedHex).
_GOLDEN_OLD_ROOT_SEED_HEX = (
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)


def _pubkey_from_seed_hex(seed_hex: str) -> bytes:
    """Derive the Ed25519 public key from a hex-encoded 32-byte seed."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    seed = bytes.fromhex(seed_hex)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return priv.public_key().public_bytes_raw()


def smoke_test_recovery_authorization(fixture_path: str) -> int:
    """Verify a recovery_authorization golden fixture from the signing package."""
    pubkey = _pubkey_from_seed_hex(_GOLDEN_RECOVERY_ROOT_SEED_HEX)
    fp = fingerprint(pubkey)
    data = Path(fixture_path).read_bytes()
    try:
        body = verify_recovery_authorization(
            data, pubkey, fp, "2026-04-26T13:10:00Z"
        )
        print(
            f"OK recovery_authorization: reason={body['reason']!r}, "
            f"fingerprint={fp}"
        )
        return 0
    except ValueError as e:
        print(f"FAIL recovery_authorization: {e}")
        return 1


def smoke_test_root_transition(fixture_path: str) -> int:
    """Verify a root_transition golden fixture from the signing package."""
    old_pubkey = _pubkey_from_seed_hex(_GOLDEN_OLD_ROOT_SEED_HEX)
    new_pubkey = _pubkey_from_seed_hex(_GOLDEN_NEW_ROOT_SEED_HEX)
    old_fp = fingerprint(old_pubkey)
    data = Path(fixture_path).read_bytes()
    try:
        body = verify_root_transition(data, old_pubkey, new_pubkey, old_fp)
        print(
            f"OK root_transition: reason={body['reason']!r}, "
            f"old_fingerprint={body['old_fingerprint']}, "
            f"new_fingerprint={body['new_fingerprint']}"
        )
        return 0
    except ValueError as e:
        print(f"FAIL root_transition: {e}")
        return 1


def smoke_test_signing_goldens() -> int:
    """Auto-locate and verify both signing-package golden fixtures.

    Looks relative to this script's location:
      ../../internal/signing/testdata/golden/
    """
    script_dir = Path(__file__).resolve().parent
    signing_golden = script_dir.parent.parent / "internal" / "signing" / "testdata" / "golden"

    failures = 0

    recovery_path = signing_golden / "valid_recovery_authorization.json"
    if recovery_path.exists():
        failures += smoke_test_recovery_authorization(str(recovery_path))
    else:
        print(f"FAIL recovery_authorization: file missing at {recovery_path}")
        failures += 1

    transition_path = signing_golden / "valid_root_transition.json"
    if transition_path.exists():
        failures += smoke_test_root_transition(str(transition_path))
    else:
        print(f"FAIL root_transition: file missing at {transition_path}")
        failures += 1

    return failures


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--fingerprint":
        sys.exit(smoke_test_fingerprint())
    if len(sys.argv) == 3 and sys.argv[1] == "--recovery-authorization":
        sys.exit(smoke_test_recovery_authorization(sys.argv[2]))
    if len(sys.argv) == 3 and sys.argv[1] == "--root-transition":
        sys.exit(smoke_test_root_transition(sys.argv[2]))
    if len(sys.argv) == 2 and sys.argv[1] == "--signing-goldens":
        sys.exit(smoke_test_signing_goldens())

    # Default: verify contract-package golden-dir.
    # Also verify signing-package goldens if the directory exists.
    exit_code = main(sys.argv)
    if exit_code == 0:
        signing_result = smoke_test_signing_goldens()
        if signing_result > 0:
            exit_code = 1
    sys.exit(exit_code)
