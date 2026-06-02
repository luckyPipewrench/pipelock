# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Protected signature suite, ported from ``internal/aarp/suite.go``.

A protected header is covered by its own signature's bytes, so a verifier can
never be tricked into matching bytes produced under a different algorithm,
canonicalization, or profile version. Agility lives inside the signed envelope,
fail-closed: an unknown suite or an unknown critical extension is rejected with
no fallback verification.
"""

from __future__ import annotations

# AARP profile + canonicalization identifiers carried by every envelope and every
# protected signature header. A mismatch is fatal.
PROFILE = "aarp/v0.1"
CANON_ID = "jcs-rfc8785-nfc"

ALG_ED25519 = "ed25519"
ALG_MLDSA65 = "ml-dsa-65"

# Each recognized algorithm's required key type. A header whose key_type disagrees
# with its alg is malformed.
KEY_TYPE_FOR_ALG = {
    ALG_ED25519: "ed25519",
    ALG_MLDSA65: "ml-dsa",
}

# Algorithms whose verification is built. A recognized-but-unimplemented alg is a
# typed stub that fails closed, never a fallback verify.
IMPLEMENTED_ALGS = {ALG_ED25519}

# Closed set of signer roles a protected header may claim.
KNOWN_SIGNER_ROLES = {"mediator", "issuer", "countersig"}

# Registry of understood critical-extension names. Empty in v0.1: any name flagged
# critical fails the envelope closed.
KNOWN_CRITICAL_EXTENSIONS: set[str] = set()


class UnknownSuiteError(Exception):
    """The header names a profile, canon, or alg this verifier does not know."""


class UnimplementedSuiteError(Exception):
    """A recognized but unbuilt suite (the post-quantum slot)."""


class MalformedSuiteError(Exception):
    """The header is structurally invalid (missing key id, bad role, type mismatch)."""


class UnknownCriticalExtensionError(Exception):
    """A critical extension this verifier does not understand; fail closed."""


def check_critical_extensions(crit: list[str]) -> None:
    """Reject empty, duplicate, or unknown critical-extension names.

    Structural validity (no empty, no duplicate) is checked first, then
    known-ness, so a duplicated unknown name is reported as the duplicate it is.
    """
    seen: set[str] = set()
    for name in crit:
        if name == "":
            raise MalformedSuiteError("empty critical extension name")
        if name in seen:
            raise MalformedSuiteError(f"duplicate critical extension {name!r}")
        seen.add(name)
    for name in seen:
        if name not in KNOWN_CRITICAL_EXTENSIONS:
            raise UnknownCriticalExtensionError(f"{name!r}")
