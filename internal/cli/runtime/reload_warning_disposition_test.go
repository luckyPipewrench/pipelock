// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReloadWarningDisposition_Rejectability(t *testing.T) {
	t.Parallel()

	advisory := config.ReloadWarning{Disposition: config.ReloadWarningDispositionAdvisory}
	unknown := config.ReloadWarning{Field: "new.warning", Message: "unclassified warning"}
	if hasRejectableDowngradeWarning([]config.ReloadWarning{advisory}) {
		t.Fatal("pure advisory warning was rejectable")
	}
	if !hasRejectableDowngradeWarning([]config.ReloadWarning{unknown}) {
		t.Fatal("zero-value warning was not rejectable")
	}
	if !hasRejectableDowngradeWarning([]config.ReloadWarning{advisory, unknown}) {
		t.Fatal("mixed advisory and rejectable warnings were not rejectable")
	}
	required := config.Defaults()
	required.FlightRecorder.RequireReceipts = true
	if reason := reloadDowngradeRejectReason(required, required, []config.ReloadWarning{unknown}); !strings.Contains(reason, "flight_recorder.require_receipts") {
		t.Fatalf("unknown zero-value warning rejection = %q, want required contract", reason)
	}
}

func TestReloadDowngradeRejectReason_StrictRejectsAdvisoryEntropyRemoval(t *testing.T) {
	t.Parallel()

	old := config.Defaults()
	old.Mode = config.ModeStrict
	old.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{
		Scheme: "https", Host: "docs.vendor.example", PathPrefix: "/document/d/",
	}}
	updated := old.Clone()
	updated.FetchProxy.Monitoring.PathEntropyExclusions = nil
	warnings := config.ValidateReload(old, updated)
	if reason := reloadDowngradeRejectReason(old, updated, warnings); reason != "strict mode" {
		t.Fatalf("strict advisory removal rejection = %q, want strict mode", reason)
	}
}

func TestReloadDowngradeRejectReason_RequiredContractsHonorWarningDisposition(t *testing.T) {
	t.Parallel()

	path := config.PathEntropyExclusion{Scheme: "https", Host: "docs.vendor.example", PathPrefix: "/document/d/"}
	query := config.QueryEntropyParamExclusion{Scheme: "https", Host: "api.vendor.example", Path: "/v1/search/recent", Param: "query"}
	for _, tc := range []struct {
		name           string
		old            func(*config.Config)
		updated        func(*config.Config)
		wantRejected   bool
		wantWarningFor string
	}{
		{
			name: "path removal is accepted",
			old: func(c *config.Config) {
				c.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{path}
			},
			updated:        func(c *config.Config) { c.FetchProxy.Monitoring.PathEntropyExclusions = nil },
			wantWarningFor: "fetch_proxy.monitoring.path_entropy_exclusions",
		},
		{
			name: "query parameter removal is accepted",
			old: func(c *config.Config) {
				c.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{query}
			},
			updated:        func(c *config.Config) { c.FetchProxy.Monitoring.QueryEntropyParamExclusions = nil },
			wantWarningFor: "fetch_proxy.monitoring.query_entropy_param_exclusions",
		},
		{
			name: "path addition is rejected",
			updated: func(c *config.Config) {
				c.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{path}
			},
			wantRejected:   true,
			wantWarningFor: "fetch_proxy.monitoring.path_entropy_exclusions",
		},
		{
			name: "query parameter addition is rejected",
			updated: func(c *config.Config) {
				c.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{query}
			},
			wantRejected:   true,
			wantWarningFor: "fetch_proxy.monitoring.query_entropy_param_exclusions",
		},
		{
			name: "path swap is rejected",
			old: func(c *config.Config) {
				c.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{path}
			},
			updated: func(c *config.Config) {
				c.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{
					Scheme: "https", Host: "drive.vendor.example", PathPrefix: "/file/d/",
				}}
			},
			wantRejected:   true,
			wantWarningFor: "fetch_proxy.monitoring.path_entropy_exclusions",
		},
		{
			name: "secret file replacement is rejected",
			old: func(c *config.Config) {
				c.DLP.SecretsFile = "old-secrets.txt"
			},
			updated: func(c *config.Config) {
				c.DLP.SecretsFile = "new-secrets.txt"
			},
			wantRejected:   true,
			wantWarningFor: "dlp.secrets_file",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{config.ModeBalanced, config.ModeAudit} {
				t.Run(mode, func(t *testing.T) {
					old := config.Defaults()
					old.Mode = mode
					old.FlightRecorder.RequireReceipts = true
					if tc.old != nil {
						tc.old(old)
					}
					updated := old.Clone()
					if tc.updated != nil {
						tc.updated(updated)
					}
					warnings := config.ValidateReload(old, updated)
					found := false
					for _, warning := range warnings {
						found = found || warning.Field == tc.wantWarningFor
					}
					if !found {
						t.Fatalf("ValidateReload() did not produce warning %q: %#v", tc.wantWarningFor, warnings)
					}
					reason := reloadDowngradeRejectReason(old, updated, warnings)
					if tc.wantRejected && !strings.Contains(reason, "flight_recorder.require_receipts") {
						t.Fatalf("required-contract rejection = %q, want receipt contract", reason)
					}
					if !tc.wantRejected && reason != "" {
						t.Fatalf("pure advisory required-contract rejection = %q, want accepted", reason)
					}
				})
			}
		})
	}
}

func TestServerReload_EntropyExclusionWarningDisposition(t *testing.T) {
	path := config.PathEntropyExclusion{
		Scheme:     "https",
		Host:       "docs.vendor.example",
		PathPrefix: "/document/d/",
	}
	for _, tc := range []struct {
		name           string
		mode           string
		baseline       func(*config.Config)
		change         func(*config.Config)
		wantRejected   bool
		wantDiagnostic string
	}{
		{
			name: "path removal preserves balanced diagnostic",
			mode: config.ModeBalanced,
			baseline: func(c *config.Config) {
				c.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{path}
			},
			change:         func(c *config.Config) { c.FetchProxy.Monitoring.PathEntropyExclusions = nil },
			wantDiagnostic: "path entropy exclusions removed",
		},
		{
			name: "path removal preserves audit diagnostic",
			mode: config.ModeAudit,
			baseline: func(c *config.Config) {
				c.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{path}
			},
			change:         func(c *config.Config) { c.FetchProxy.Monitoring.PathEntropyExclusions = nil },
			wantDiagnostic: "path entropy exclusions removed",
		},
		{
			name: "path addition rejects under required receipts",
			mode: config.ModeBalanced,
			change: func(c *config.Config) {
				c.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{path}
			},
			wantRejected:   true,
			wantDiagnostic: "config reload rejected",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s *Server
			var stderr *syncBuffer
			if tc.wantRejected {
				s, stderr, _ = newRequireReceiptsReloadServerWithAudit(t, true)
			} else {
				s, stderr = newTestServer(t, func(o *ServerOpts) {
					o.Mode = tc.mode
					o.ModeChanged = true
				})
			}
			baseline := s.proxy.CurrentConfig().Clone()
			if tc.wantRejected {
				baseline.FlightRecorder.RequireReceipts = true
			}
			if tc.baseline != nil {
				tc.baseline(baseline)
			}
			if err := s.Reload(baseline); err != nil {
				t.Fatalf("initial reload to establish baseline: %v", err)
			}
			oldCfg := s.proxy.CurrentConfig()
			candidate := oldCfg.Clone()
			if tc.change != nil {
				tc.change(candidate)
			}
			err := s.Reload(candidate)
			if tc.wantRejected {
				if err == nil || !strings.Contains(err.Error(), "security downgrade") {
					t.Fatalf("Reload() error = %v, want security downgrade rejection; stderr: %s", err, stderr.String())
				}
				if s.proxy.CurrentConfig() != oldCfg {
					t.Fatal("rejected reload changed the live config")
				}
			} else if err != nil {
				t.Fatalf("Reload() error = %v, want advisory reload accepted", err)
			}
			if !stderr.contains(tc.wantDiagnostic) {
				t.Fatalf("reload diagnostic missing %q:\n%s", tc.wantDiagnostic, stderr.String())
			}
			if !tc.wantRejected && stderr.contains("config reload rejected") {
				t.Fatalf("advisory reload reported rejection:\n%s", stderr.String())
			}
		})
	}
}
