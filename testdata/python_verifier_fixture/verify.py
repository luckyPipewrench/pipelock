#!/usr/bin/env python3
"""Cross-implementation verifier for v2.4 learn-and-lock golden vectors.

Loads each Go-emitted golden fixture, independently recomputes the JCS
preimage in Python, and verifies the Ed25519 PureEdDSA signature against
the RFC 8032 test public key. Proves byte-identical canonicalization
between the Go and Python implementations.

Usage:
    python3 verify.py <golden-dir>

Exits 0 on success, 1 on any verification failure.
"""

import json
import os
import sys
from pathlib import Path

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SIG_PREFIX = "ed25519:"


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
        for i, sig_obj in enumerate(envelope["signatures"]):
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


if __name__ == "__main__":
    sys.exit(main(sys.argv))
