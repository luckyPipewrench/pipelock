# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""SPIFFE trust-domain syntax check, ported from ``internal/aarp/trustdomain.go``.

SPIFFE-ID §2 requires a trust domain to be a DNS name. go-spiffe's parser accepts
the lowercased host portion of a SPIFFE ID and also accepts IP literals, so a
numeric host could otherwise impersonate a domain; this module rejects IP
literals as the Go reference does.

No AARP corpus fixture carries ``trust_domain``, so this path is exercised only
by future fixtures; it is implemented faithfully so those hold without a code
change. Core only checks syntax — the authoritative SVID-bound trust-domain match
happens in the attestation layer.
"""

from __future__ import annotations

import ipaddress

# Characters go-spiffe permits in a trust-domain name: lowercase letters, digits,
# and the separators '.', '-', '_'. Uppercase and other characters are rejected.
_ALLOWED = set("abcdefghijklmnopqrstuvwxyz0123456789.-_")


class TrustDomainError(Exception):
    """The trust domain is not a syntactically valid SPIFFE DNS name."""


def validate_trust_domain_name(s: str) -> None:
    """Validate ``s`` as a SPIFFE trust domain that is a DNS name, not an IP."""
    if s == "":
        raise TrustDomainError("trust domain is empty")
    # go-spiffe accepts an optional spiffe:// scheme prefix; strip it for the host.
    host = s
    if host.startswith("spiffe://"):
        host = host[len("spiffe://") :]
    if host == "":
        raise TrustDomainError(f"invalid trust domain {s!r}")
    for c in host:
        if c not in _ALLOWED:
            raise TrustDomainError(f"invalid trust domain {s!r}: bad character {c!r}")
    # Reject IP literals: a trust domain must be a DNS name.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise TrustDomainError(
            f"trust domain must be a DNS name, not an IP address: {s!r}"
        )
