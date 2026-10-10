// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/identity"
)

// TestApplyMCPResponseSuppressOpts_ClampsTrustToSectionAction pins the startup
// banner and the proxy override to the same clamped action. The banner is read
// by an operator as the effective policy, so reporting warn while the proxy
// blocks is the same class of divergence as an explain mismatch.
func TestApplyMCPResponseSuppressOpts_ClampsTrustToSectionAction(t *testing.T) {
	tests := []struct {
		name          string
		trust         string
		sectionAction string
		want          string
	}{
		{"reasoning under block blocks", config.ResponseTrustReasoning, config.ActionBlock, config.ActionBlock},
		{"reasoning under warn warns", config.ResponseTrustReasoning, config.ActionWarn, config.ActionWarn},
		{"untrusted under warn blocks", config.ResponseTrustUntrusted, config.ActionWarn, config.ActionBlock},
		{"unknown trust under warn blocks", "totally-bogus", config.ActionWarn, config.ActionBlock},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.ResponseScanning.Action = tc.sectionAction
			cfg.ResponseScanning.MCPServers = []config.MCPResponseServerTrust{
				{Server: "code-assistant", Trust: tc.trust},
			}

			var opts mcp.MCPProxyOpts
			applyMCPResponseSuppressOpts(&opts, cfg, identity.Legacy("code-assistant"))

			if opts.ResponseActionOverride != tc.want {
				t.Fatalf("override = %q, want %q", opts.ResponseActionOverride, tc.want)
			}
			action, trust, server := mcpResponseLogFields(opts)
			if action != tc.want {
				t.Fatalf("banner action = %q, want %q", action, tc.want)
			}
			if trust != tc.trust {
				t.Fatalf("banner trust = %q, want %q", trust, tc.trust)
			}
			if server != "code-assistant" {
				t.Fatalf("banner server = %q, want code-assistant", server)
			}
		})
	}
}
