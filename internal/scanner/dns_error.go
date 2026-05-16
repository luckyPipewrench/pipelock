// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"errors"
	"fmt"
	"net"
)

// classifyDNSError maps a resolver failure into a DNSErrorKind plus a
// resolver-led reason string. The caller still produces a fail-closed Result;
// the kind only drives audit display labels and metric subdivision.
//
// Classification order matters. Timeout is checked first because a *net.DNSError
// with both Timeout()=true and IsNotFound=false occurs on resolver stalls,
// and the timeout reading is the more useful signal for operator alerting.
// NXDOMAIN ("no such host") is checked next via IsNotFound. Anything else falls
// through to the generic resolver_error kind so SIEM consumers can still
// distinguish a resolver-layer failure from threat evidence.
func classifyDNSError(hostname string, err error) (DNSErrorKind, string) {
	if err == nil {
		// Defensive: this function is only called from the err != nil branch
		// of LookupHost. A nil err here would be a programming error. Still
		// fail closed with a generic kind so the audit stream never sees an
		// empty DNSErrorKind on an infra-error path.
		return DNSErrorResolver, fmt.Sprintf("DNS lookup for %s failed", hostname)
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsTimeout || dnsErr.Timeout():
			return DNSErrorTimeout, fmt.Sprintf("DNS lookup for %s timed out", hostname)
		case dnsErr.IsNotFound:
			return DNSErrorNoSuchHost, fmt.Sprintf("DNS lookup for %s returned no such host", hostname)
		case dnsErr.IsTemporary || dnsErr.Temporary():
			return DNSErrorResolver, fmt.Sprintf("DNS lookup for %s failed (temporary resolver error): %s", hostname, dnsErr.Err)
		default:
			return DNSErrorResolver, fmt.Sprintf("DNS lookup for %s failed: %s", hostname, dnsErr.Err)
		}
	}

	// Not a *net.DNSError. Could be a wrapped resolver error or a transport
	// error surfaced from the resolver. Treat as resolver_error so the audit
	// stream still tags the kind correctly.
	return DNSErrorResolver, fmt.Sprintf("DNS lookup for %s failed: %v", hostname, err)
}
