// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

// TestValidateExpiryAuthorizations pins the expiry-only validation that the
// hot-reload path runs before admitting a reloaded config. Startup goes
// through Validate, but direct Reload callers bypass Load, so this method is
// the activation boundary for every temporary-expiry authorization on
// reload. Each row asserts one field's own horizon, the exact field path a
// refusal names, and how the boundary treats an unset expiry: the fetch-proxy
// entropy exclusions are optional, while the passthrough and request-body
// route expiries are required exactly as they are at startup.
func TestValidateExpiryAuthorizations(t *testing.T) {
	now := time.Now().UTC()
	// The 48-hour margin keeps the date past the horizon even if UTC
	// midnight passes between building the fixture and the validator's own
	// todayUTC() read.
	pastHorizonDate := func(maximum time.Duration) string {
		return todayUTC().Add(maximum + 48*time.Hour).Format("2006-01-02")
	}
	pastHorizonStamp := func(maximum time.Duration) string {
		return now.Add(maximum + 24*time.Hour).Format(time.RFC3339)
	}
	// The best-effort authorizations take RFC3339 timestamps rather than
	// dates; midday on the shared helper's in-horizon date stays inside the
	// horizon.
	withinHorizonStamp := func(maximum time.Duration) string {
		return temporaryExpiryDate(maximum) + "T12:00:00Z"
	}

	withSandboxBestEffort := func(expiry string) *Config {
		cfg := Defaults()
		cfg.Sandbox.BestEffort = true
		cfg.Sandbox.BestEffortReason = "temporary namespace failure"
		cfg.Sandbox.BestEffortExpiry = expiry
		return cfg
	}
	withAgentBestEffort := func(expiry string) *Config {
		cfg := Defaults()
		cfg.Agents = map[string]AgentProfile{
			"researcher": {Sandbox: &AgentSandboxOverride{
				BestEffort:       ptrBool(true),
				BestEffortReason: "temporary namespace failure",
				BestEffortExpiry: expiry,
			}},
		}
		return cfg
	}
	withUnscannablePassthrough := func(expires string) *Config {
		cfg := Defaults()
		cfg.ResponseScanning.UnscannablePassthrough = []UnscannablePassthroughEntry{{Expires: expires}}
		return cfg
	}
	withPathEntropyExclusion := func(expires string) *Config {
		cfg := Defaults()
		cfg.FetchProxy.Monitoring.PathEntropyExclusions = []PathEntropyExclusion{{Expires: expires}}
		return cfg
	}
	withQueryEntropyParamExclusion := func(expires string) *Config {
		cfg := Defaults()
		cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []QueryEntropyParamExclusion{{Expires: expires}}
		return cfg
	}
	withContentEntropyWarnRoute := func(expires string) *Config {
		cfg := Defaults()
		cfg.RequestBodyScanning.ContentEntropyWarnRoutes = []RequestBodyEntropyWarnRoute{{Expires: expires}}
		return cfg
	}
	withSigV4CredentialRoute := func(expires string) *Config {
		cfg := Defaults()
		cfg.RequestBodyScanning.SigV4CredentialRoutes = []RequestBodySigV4CredentialRoute{{Expires: expires}}
		return cfg
	}

	tests := []struct {
		name string
		// field is the exact path a refusal must name, so a copy-paste
		// mistake that validates the wrong field cannot pass.
		field         string
		withinHorizon func() *Config
		pastHorizon   func() *Config
		unset         func() *Config
		// unsetRefused marks fields whose expiry this boundary requires,
		// matching startup validation; optional fields accept an unset
		// expiry.
		unsetRefused bool
	}{
		{
			name:  "sandbox best effort expiry",
			field: "sandbox: best_effort_expiry",
			withinHorizon: func() *Config {
				return withSandboxBestEffort(withinHorizonStamp(MaxBestEffortConfigHorizon))
			},
			pastHorizon: func() *Config {
				return withSandboxBestEffort(pastHorizonStamp(MaxBestEffortConfigHorizon))
			},
			unset: func() *Config { return Defaults() },
		},
		{
			name:  "agent sandbox override best effort expiry",
			field: "agents.researcher.sandbox: best_effort_expiry",
			withinHorizon: func() *Config {
				return withAgentBestEffort(withinHorizonStamp(MaxBestEffortConfigHorizon))
			},
			pastHorizon: func() *Config {
				return withAgentBestEffort(pastHorizonStamp(MaxBestEffortConfigHorizon))
			},
			// A profile override that does not enable best_effort carries
			// no authorization to check and must stay valid.
			unset: func() *Config {
				cfg := Defaults()
				cfg.Agents = map[string]AgentProfile{"researcher": {Sandbox: &AgentSandboxOverride{}}}
				return cfg
			},
		},
		{
			name:  "unscannable passthrough expiry",
			field: "response_scanning.unscannable_passthrough[0].expires",
			withinHorizon: func() *Config {
				return withUnscannablePassthrough(temporaryExpiryDate(MaxUnscannablePassthroughHorizon))
			},
			pastHorizon: func() *Config {
				return withUnscannablePassthrough(pastHorizonDate(MaxUnscannablePassthroughHorizon))
			},
			unset:        func() *Config { return withUnscannablePassthrough("") },
			unsetRefused: true,
		},
		{
			name:  "path entropy exclusion expiry",
			field: "fetch_proxy.monitoring.path_entropy_exclusions[0].expires",
			withinHorizon: func() *Config {
				return withPathEntropyExclusion(temporaryExpiryDate(MaxPathEntropyExclusionHorizon))
			},
			pastHorizon: func() *Config {
				return withPathEntropyExclusion(pastHorizonDate(MaxPathEntropyExclusionHorizon))
			},
			unset: func() *Config { return withPathEntropyExclusion("") },
		},
		{
			name:  "query entropy parameter exclusion expiry",
			field: "fetch_proxy.monitoring.query_entropy_param_exclusions[0].expires",
			withinHorizon: func() *Config {
				return withQueryEntropyParamExclusion(temporaryExpiryDate(MaxQueryEntropyParamExclusionHorizon))
			},
			pastHorizon: func() *Config {
				return withQueryEntropyParamExclusion(pastHorizonDate(MaxQueryEntropyParamExclusionHorizon))
			},
			unset: func() *Config { return withQueryEntropyParamExclusion("") },
		},
		{
			name:  "content entropy warn route expiry",
			field: "request_body_scanning.content_entropy_warn_routes[0].expires",
			withinHorizon: func() *Config {
				return withContentEntropyWarnRoute(temporaryExpiryDate(MaxRequestBodyEntropyWarnRouteHorizon))
			},
			pastHorizon: func() *Config {
				return withContentEntropyWarnRoute(pastHorizonDate(MaxRequestBodyEntropyWarnRouteHorizon))
			},
			unset:        func() *Config { return withContentEntropyWarnRoute("") },
			unsetRefused: true,
		},
		{
			name:  "sigv4 credential route expiry",
			field: "request_body_scanning.sigv4_credential_routes[0].expires",
			withinHorizon: func() *Config {
				return withSigV4CredentialRoute(temporaryExpiryDate(MaxRequestBodySigV4CredentialRouteHorizon))
			},
			pastHorizon: func() *Config {
				return withSigV4CredentialRoute(pastHorizonDate(MaxRequestBodySigV4CredentialRouteHorizon))
			},
			unset:        func() *Config { return withSigV4CredentialRoute("") },
			unsetRefused: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("within horizon", func(t *testing.T) {
				if err := tt.withinHorizon().ValidateExpiryAuthorizations(); err != nil {
					t.Fatalf("ValidateExpiryAuthorizations rejected an in-horizon expiry: %v", err)
				}
			})
			t.Run("past horizon", func(t *testing.T) {
				err := tt.pastHorizon().ValidateExpiryAuthorizations()
				if err == nil {
					t.Fatal("ValidateExpiryAuthorizations accepted an expiry past its horizon")
				}
				if !strings.Contains(err.Error(), tt.field) {
					t.Fatalf("error = %q, want field %q", err, tt.field)
				}
			})
			t.Run("unset", func(t *testing.T) {
				err := tt.unset().ValidateExpiryAuthorizations()
				if tt.unsetRefused {
					if err == nil {
						t.Fatal("ValidateExpiryAuthorizations accepted an unset required expiry")
					}
					if !strings.Contains(err.Error(), tt.field) {
						t.Fatalf("error = %q, want field %q", err, tt.field)
					}
					return
				}
				if err != nil {
					t.Fatalf("ValidateExpiryAuthorizations refused an unset optional expiry: %v", err)
				}
			})
		})
	}
}
