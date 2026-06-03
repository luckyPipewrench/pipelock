# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Rung-1 chain linkage verification, ported from ``internal/aarp/chain.py``.

VerifyChain checks that a slice of envelopes forms a contiguous, hash-linked
stream from a single issuer: every envelope carries a chain link, all links share
one issuer, the sequence increments by exactly 1, and each link's prior_hash
equals the previous envelope's payload digest. It does NOT check signatures — it
checks only the linkage that makes backdating, insertion, and reordering within a
stream detectable. The slice must be in ascending stream order.
"""

from __future__ import annotations

from .canonical import canonicalize
from .envelope import Envelope, parse_seq_value


class ChainBrokenError(Exception):
    """A sequence of links does not form a contiguous, single-issuer stream."""


def verify_chain(envs: list[Envelope]) -> None:
    """Raise ChainBrokenError (or a chain-schema error) if envs are not linked."""
    if len(envs) == 0:
        raise ChainBrokenError("empty chain")
    issuer = ""
    prev_seq = 0
    prev_hash = ""
    for i, e in enumerate(envs):
        if e.chain is None:
            raise ChainBrokenError(f"envelope[{i}] has no chain link")
        e.chain.validate()
        seq = parse_seq_value(e.chain.seq)
        if i == 0:
            issuer = e.chain.issuer_id
        else:
            if e.chain.issuer_id != issuer:
                raise ChainBrokenError(
                    f"envelope[{i}] issuer {e.chain.issuer_id!r} != stream issuer "
                    f"{issuer!r}"
                )
            if seq != prev_seq + 1:
                raise ChainBrokenError(
                    f"envelope[{i}] seq {seq}, expected {prev_seq + 1}"
                )
            # Both sides are lowercase hex (prior_hash passed the grammar check;
            # prev_hash is a hexdigest). Compare exactly.
            if e.chain.prior_hash != prev_hash:
                raise ChainBrokenError(
                    f"envelope[{i}] prior_hash does not match previous payload digest"
                )
        digest = e.payload_digest()
        prev_seq = seq
        prev_hash = digest


def is_chain_linked(envs: list[Envelope]) -> bool:
    """Whether the stream verifies (True) or breaks (False)."""
    try:
        verify_chain(envs)
    except Exception:  # noqa: BLE001 - any linkage/schema break means not linked
        return False
    return True


def comparable_chain(envs: list[Envelope]) -> bytes:
    """Project a VerifyChain outcome onto the comparison surface (JCS bytes)."""
    obj = {
        "chain_linked": is_chain_linked(envs),
        "length": len(envs),
    }
    return canonicalize(obj)
