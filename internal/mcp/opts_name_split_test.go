// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	nameSplitIdentity = "vendor-indexer"
	nameSplitRevision = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	nameSplitTarget   = "mcp://vendor-indexer/response"
)

func TestMCPProxyOpts_NameSplitTargets(t *testing.T) {
	tests := []struct {
		name      string
		opts      MCPProxyOpts
		wantArm   string
		wantAudit string
	}{
		{"unnamed", MCPProxyOpts{}, "", ""},
		{"legacy explicit name", MCPProxyOpts{ServerName: "code-assistant", PolicyServerName: "code-assistant"}, "mcp://code-assistant/response", "mcp://code-assistant/response"},
		{"verified identity arms by its name", MCPProxyOpts{ServerName: nameSplitIdentity, PolicyServerName: nameSplitIdentity, ServerBindingMode: config.MCPAckBindingModeVerifiedLocalSession}, nameSplitTarget, nameSplitTarget},
		{"name without an arming name labels but does not arm", MCPProxyOpts{ServerName: nameSplitIdentity}, "", nameSplitTarget},
		{"arming name without a label arms but does not label", MCPProxyOpts{PolicyServerName: nameSplitIdentity}, nameSplitTarget, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opts.responseTarget(); got != tt.wantArm {
				t.Fatalf("responseTarget = %q, want %q", got, tt.wantArm)
			}
			if got := tt.opts.auditTarget(); got != tt.wantAudit {
				t.Fatalf("auditTarget = %q, want %q", got, tt.wantAudit)
			}
			if got := tt.opts.responseScanOptions().Target; got != tt.wantArm {
				t.Fatalf("responseScanOptions().Target = %q, want %q", got, tt.wantArm)
			}
		})
	}
}

func TestMCPProxyOpts_AdaptiveSessionKey(t *testing.T) {
	tests := []struct {
		name string
		opts MCPProxyOpts
		want string
	}{
		{"unnamed", MCPProxyOpts{}, "default"},
		{"legacy name is unchanged", MCPProxyOpts{ServerName: "code-assistant"}, "code-assistant"},
		{"registered identity carries the short revision", MCPProxyOpts{ServerName: nameSplitIdentity, ServerRevision: nameSplitRevision}, "vendor-indexer@0123456789ab"},
		{"short revision is kept whole", MCPProxyOpts{ServerName: nameSplitIdentity, ServerRevision: "abc"}, "vendor-indexer@abc"},
		{"exactly twelve characters", MCPProxyOpts{ServerName: nameSplitIdentity, ServerRevision: "0123456789ab"}, "vendor-indexer@0123456789ab"},
		{"revision without a name", MCPProxyOpts{ServerRevision: nameSplitRevision}, "default@0123456789ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opts.adaptiveSessionKey(); got != tt.want {
				t.Fatalf("adaptiveSessionKey = %q, want %q", got, tt.want)
			}
		})
	}
}

// A suppress entry written for a registered identity's name takes effect only
// once the launch's arming name is set; a label alone never arms it.
func TestScanResponseOpts_ArmingNameGatesSuppress(t *testing.T) {
	sc := testScanner(t)
	line := suppressResponse(1)
	base := ScanResponse(line, sc)
	if base.Clean {
		t.Fatal("baseline must trip a response pattern")
	}
	suppress := []config.SuppressEntry{{Rule: base.Matches[0].PatternName, Path: nameSplitTarget, Reason: "reviewed"}}

	tests := []struct {
		name      string
		opts      MCPProxyOpts
		wantClean bool
	}{
		{"label only does not arm", MCPProxyOpts{ServerName: nameSplitIdentity, Suppress: suppress}, false},
		{"arming name arms", MCPProxyOpts{ServerName: nameSplitIdentity, PolicyServerName: nameSplitIdentity, Suppress: suppress}, true},
		{"another arming name does not match", MCPProxyOpts{ServerName: nameSplitIdentity, PolicyServerName: "other", Suppress: suppress}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := ScanResponseOpts(line, sc, tt.opts.responseScanOptions())
			if v.Clean != tt.wantClean {
				t.Fatalf("clean = %v, want %v (matches=%v)", v.Clean, tt.wantClean, v.Matches)
			}
		})
	}
}
