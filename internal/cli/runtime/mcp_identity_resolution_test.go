// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/identity"
	"github.com/luckyPipewrench/pipelock/internal/mcp/localservice"
)

const (
	resolutionIdentity = "vendor-indexer"
	resolutionRevision = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	resolutionURL      = "http://127.0.0.1:41873/rpc/v1"
	resolutionTarget   = "mcp://vendor-indexer/response"
)

// verifiedResolution is a resolved registry entry for a Python-style HTTP
// indexer, built directly so the test does not depend on the host platform.
func verifiedResolution() identity.Resolution {
	uid := uint32(1001)
	entry := config.MCPIdentity{
		Name: resolutionIdentity,
		VerifiedLocalService: &config.MCPVerifiedLocalService{
			Scheme:           config.MCPIdentitySchemeHTTP,
			Host:             config.MCPIdentityHostIPv4Loopback,
			Path:             "/rpc/v1",
			PrincipalUID:     &uid,
			ExecutableSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	return identity.Resolution{
		Name:        resolutionIdentity,
		ArmingName:  resolutionIdentity,
		Source:      identity.SourceVerifiedLocalService,
		Revision:    resolutionRevision,
		BindingMode: config.MCPAckBindingModeVerifiedLocalSession,
		Pin:         &localservice.Pin{PrincipalUID: uid, ExecutableSHA256: entry.VerifiedLocalService.ExecutableSHA256},
		Entry:       &entry,
	}
}

func TestVerifiedBindingDiffersFromTransportV2(t *testing.T) {
	r := verifiedResolution()
	launch := identity.Transport{Kind: identity.KindHTTP, UpstreamURL: resolutionURL, ChildEnv: []string{"VENDOR_MODE=fast"}}
	verified, err := identity.SessionBinding(r, launch)
	if err != nil {
		t.Fatal(err)
	}
	legacy := mcpServerBinding(mcpBindingInputs{UpstreamURL: resolutionURL, Headers: http.Header{}, ChildEnv: launch.ChildEnv})
	if verified == "" || legacy == "" || verified == legacy {
		t.Fatalf("verified=%q legacy=%q: the two binding families must never share a digest", verified, legacy)
	}

	// A transport-v2 digest of any upstream over the same inputs is different
	// again, so an entry minted in one family cannot match the other.
	other := mcpServerBinding(mcpBindingInputs{UpstreamURL: "http://127.0.0.1:50000/rpc/v1", Headers: http.Header{}, ChildEnv: launch.ChildEnv})
	if other == legacy {
		t.Fatal("transport-v2 must still distinguish ports")
	}
	moved := launch
	moved.UpstreamURL = "http://127.0.0.1:50000/rpc/v1"
	again, err := identity.SessionBinding(r, moved)
	if err != nil {
		t.Fatal(err)
	}
	if again != verified {
		t.Fatal("the verified binding must survive an ephemeral port change")
	}
}

func TestApplyMCPResponseSuppressOpts_NameSplit(t *testing.T) {
	newCfg := func() *config.Config {
		cfg := config.Defaults()
		cfg.Suppress = []config.SuppressEntry{{Rule: "New Instructions", Path: resolutionTarget, Reason: "reviewed"}}
		cfg.ResponseScanning.MCPServers = []config.MCPResponseServerTrust{{Server: resolutionIdentity, Trust: config.ResponseTrustReasoning}}
		cfg.Taint.TrustedMCPServers = []string{resolutionIdentity}
		return cfg
	}

	tests := []struct {
		name       string
		res        identity.Resolution
		wantTrust  string
		wantAction string
		wantTaint  bool
		wantName   string
		wantArm    string
		wantMode   string
		wantRev    string
	}{
		{
			name:       "verified identity arms every policy by its name",
			res:        verifiedResolution(),
			wantTrust:  config.ResponseTrustReasoning,
			wantAction: config.ActionWarn,
			wantTaint:  true,
			wantName:   resolutionIdentity,
			wantArm:    resolutionIdentity,
			wantMode:   config.MCPAckBindingModeVerifiedLocalSession,
			wantRev:    resolutionRevision,
		},
		{
			name:       "legacy explicit name behaves as before",
			res:        identity.Legacy(resolutionIdentity),
			wantTrust:  config.ResponseTrustReasoning,
			wantAction: config.ActionWarn,
			wantTaint:  true,
			wantName:   resolutionIdentity,
			wantArm:    resolutionIdentity,
			wantMode:   config.MCPAckBindingModeTransportV2,
		},
		{
			name:       "unnamed launch arms nothing",
			res:        identity.Legacy(""),
			wantTrust:  config.ResponseTrustUntrusted,
			wantAction: config.ActionBlock,
			wantMode:   config.MCPAckBindingModeTransportV2,
		},
		{
			name:       "a label without an arming name arms nothing",
			res:        identity.Resolution{Name: resolutionIdentity, BindingMode: config.MCPAckBindingModeTransportV2},
			wantTrust:  config.ResponseTrustUntrusted,
			wantAction: config.ActionBlock,
			wantName:   resolutionIdentity,
			wantMode:   config.MCPAckBindingModeTransportV2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts mcp.MCPProxyOpts
			applyMCPResponseSuppressOpts(&opts, newCfg(), tt.res)
			if opts.ResponseTrustClass != tt.wantTrust || opts.ResponseActionOverride != tt.wantAction {
				t.Fatalf("trust/action = %q/%q, want %q/%q", opts.ResponseTrustClass, opts.ResponseActionOverride, tt.wantTrust, tt.wantAction)
			}
			if opts.TaintTrustedSource != tt.wantTaint {
				t.Fatalf("TaintTrustedSource = %v, want %v", opts.TaintTrustedSource, tt.wantTaint)
			}
			if opts.ServerName != tt.wantName || opts.PolicyServerName != tt.wantArm {
				t.Fatalf("names = %q/%q, want %q/%q", opts.ServerName, opts.PolicyServerName, tt.wantName, tt.wantArm)
			}
			legacyMode := tt.wantMode == config.MCPAckBindingModeTransportV2 && opts.ServerBindingMode == ""
			if opts.ServerBindingMode != tt.wantMode && !legacyMode {
				t.Fatalf("ServerBindingMode = %q, want %q", opts.ServerBindingMode, tt.wantMode)
			}
			if opts.ServerRevision != tt.wantRev {
				t.Fatalf("ServerRevision = %q, want %q", opts.ServerRevision, tt.wantRev)
			}
			if len(opts.Suppress) != 1 {
				t.Fatalf("suppress entries = %d, want 1: the rules are copied whatever the name", len(opts.Suppress))
			}
		})
	}
}

// The suppress target an armed launch uses is the one an operator's rule
// names; a label alone yields no target.
func TestApplyMCPResponseSuppressOpts_ArmedTarget(t *testing.T) {
	cfg := config.Defaults()
	var armed, labelled mcp.MCPProxyOpts
	applyMCPResponseSuppressOpts(&armed, cfg, verifiedResolution())
	applyMCPResponseSuppressOpts(&labelled, cfg, identity.Resolution{Name: resolutionIdentity})
	if _, _, server := mcpResponseLogFields(armed); server != resolutionIdentity {
		t.Fatalf("banner server = %q", server)
	}
	if _, _, server := mcpResponseLogFields(labelled); server != resolutionIdentity {
		t.Fatalf("a label must still be shown in the banner, got %q", server)
	}
}
