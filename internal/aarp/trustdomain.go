// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"fmt"
	"net"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// validateTrustDomainName checks that s is a syntactically valid SPIFFE trust
// domain name and not an IP literal. SPIFFE-ID §2 requires a DNS name;
// go-spiffe's parser accepts IP literals, so a numeric host could otherwise be
// used to impersonate a domain. This mirrors internal/svid.parseTrustDomain.
//
// Core only checks syntax here; the authoritative SVID-bound trust-domain match
// happens in the attestation layer against pinned bundle history.
func validateTrustDomainName(s string) error {
	td, err := spiffeid.TrustDomainFromString(s)
	if err != nil {
		return fmt.Errorf("invalid trust domain %q: %w", s, err)
	}
	if net.ParseIP(td.String()) != nil {
		return fmt.Errorf("trust domain must be a DNS name, not an IP address: %q", s)
	}
	return nil
}
