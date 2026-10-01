// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"
)

// The reverse listener has no server-wide write timeout, so the upstream
// transport must bound a silent upstream itself.
func TestNewReverseProxyTransport_BoundsSilentUpstream(t *testing.T) {
	rt := newReverseProxyTransport(&ReverseProxyHandler{}, nil)
	signing, ok := rt.(*reverseSigningRoundTripper)
	if !ok {
		t.Fatalf("transport type = %T, want *reverseSigningRoundTripper", rt)
	}
	base, ok := innerReverseTransport(signing.base)
	if !ok {
		t.Fatalf("base type = %T, want *http.Transport", signing.base)
	}
	if base.ResponseHeaderTimeout != reverseUpstreamHeaderTimeout || base.ResponseHeaderTimeout <= 0 {
		t.Fatalf("ResponseHeaderTimeout = %v, want %v", base.ResponseHeaderTimeout, reverseUpstreamHeaderTimeout)
	}
}
