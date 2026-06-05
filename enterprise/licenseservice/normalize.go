//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"fmt"
	"net/mail"
	"strings"
)

// NormalizeEmail returns the canonical form of an email address used as the
// identity key across the eval funnel (Polar order email comparison, eval-order
// records, and the deferred preflight seams). It must be the SINGLE source of
// canonicalization so the same human always maps to the same key.
//
// Canonicalization: trim surrounding whitespace, parse exactly one RFC 5322
// address (rejecting display-name-only or multi-address inputs), then lowercase
// the full address. Plus-tags and dots in the local part are PRESERVED.
//
// We deliberately do NOT apply provider-specific alias rules (Gmail dot/plus
// collapsing): those rules are false security (other providers treat dots and
// plus tags as significant) and would silently merge or break corporate
// mailboxes. Two Gmail aliases therefore normalize to distinct canonical forms.
func NormalizeEmail(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("email is empty")
	}

	addr, err := mail.ParseAddress(trimmed)
	if err != nil {
		return "", fmt.Errorf("parse email %q: %w", raw, err)
	}

	// mail.ParseAddress accepts a single address; an input with a comma-separated
	// list is rejected by ParseAddressList, not ParseAddress, so guard explicitly.
	if strings.Contains(trimmed, ",") {
		return "", fmt.Errorf("multiple email addresses not allowed: %q", raw)
	}

	return strings.ToLower(addr.Address), nil
}
