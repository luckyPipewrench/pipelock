// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import "testing"

// TestMCPBaselineAgentKeyResolution covers the identity-key resolution branches:
// address-protection agent wins, else the capture profile, else empty.
func TestMCPBaselineAgentKeyResolution(t *testing.T) {
	if got := mcpBaselineAgentKey(MCPProxyOpts{AddressProtectionAgent: "ident", Profile: "cap-p"}); got != "ident" {
		t.Fatalf("agent key = %q, want ident", got)
	}
	if got := mcpBaselineAgentKey(MCPProxyOpts{AddressProtectionAgent: "  ", Profile: "cap-p"}); got != "cap-p" {
		t.Fatalf("agent key = %q, want cap-p (profile fallback)", got)
	}
	if got := mcpBaselineAgentKey(MCPProxyOpts{}); got != "" {
		t.Fatalf("agent key = %q, want empty", got)
	}
}

// TestRecordMCPBaselineSampleGuards covers the fail-safe no-op guards: a nil
// recorder and no baseline checker configured must both be safe no-ops.
func TestRecordMCPBaselineSampleGuards(t *testing.T) {
	recordMCPBaselineSample(MCPProxyOpts{}, nil)                     // nil recorder -> no-op
	recordMCPBaselineSample(MCPProxyOpts{}, &baselineTestRecorder{}) // no checker -> no-op
}
