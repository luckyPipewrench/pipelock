# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Protected-suite critical-extension checks and trust-domain syntax checks."""

from __future__ import annotations

import pytest

from pipelock_aarp_verify.suite import (
    MalformedSuiteError,
    UnknownCriticalExtensionError,
    check_critical_extensions,
)
from pipelock_aarp_verify.trustdomain import (
    TrustDomainError,
    validate_trust_domain_name,
)


def test_empty_crit_list_ok():
    check_critical_extensions([])


def test_empty_crit_name_rejected():
    with pytest.raises(MalformedSuiteError):
        check_critical_extensions([""])


def test_duplicate_crit_name_rejected():
    with pytest.raises(MalformedSuiteError):
        check_critical_extensions(["x-foo", "x-foo"])


def test_unknown_crit_name_rejected():
    with pytest.raises(UnknownCriticalExtensionError):
        check_critical_extensions(["x-unknown-critical"])


def test_trust_domain_valid_dns_name():
    validate_trust_domain_name("example.org")


def test_trust_domain_empty_rejected():
    with pytest.raises(TrustDomainError):
        validate_trust_domain_name("")


def test_trust_domain_ip_literal_rejected():
    with pytest.raises(TrustDomainError):
        validate_trust_domain_name("10.0.0.1")


def test_trust_domain_uppercase_rejected():
    with pytest.raises(TrustDomainError):
        validate_trust_domain_name("Example.org")


def test_trust_domain_bad_char_rejected():
    with pytest.raises(TrustDomainError):
        validate_trust_domain_name("bad domain")


def test_trust_domain_strips_spiffe_scheme():
    validate_trust_domain_name("spiffe://example.org")


def test_trust_domain_scheme_only_rejected():
    with pytest.raises(TrustDomainError):
        validate_trust_domain_name("spiffe://")
