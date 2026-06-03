# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""AARP v0.1 assurance-envelope verifier (Python reference implementation).

This package is one of the four reference AARP verifiers (Go, TypeScript, Rust,
Python). It ports the Go reference in ``internal/aarp/`` and
``internal/contract/canonicalize.go`` so that, given the same envelope and trust
file, it emits byte-identical comparable output to the other three. Any
cross-language divergence is the bug class the conformance corpus exists to kill.
"""

from __future__ import annotations

from .appraise import (
    Appraisal,
    SignatureResult,
    TrustEntry,
    VerifyOptions,
    comparable_appraisal,
    verify,
)
from .chain import comparable_chain, is_chain_linked, verify_chain
from .envelope import Envelope, unmarshal

__version__ = "0.1.0"

__all__ = [
    "Appraisal",
    "Envelope",
    "SignatureResult",
    "TrustEntry",
    "VerifyOptions",
    "comparable_appraisal",
    "comparable_chain",
    "is_chain_linked",
    "unmarshal",
    "verify",
    "verify_chain",
    "__version__",
]
