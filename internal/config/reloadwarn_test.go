// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// TestValidateReload_AgentTrustedDomainsAdded covers the per-agent
// trusted_domains expansion path: any agent profile whose trusted_domains
// gains entries on reload should produce a deterministic ReloadWarning
// per profile (mirrors the global trusted_domains warning shape).
func TestValidateReload_AgentTrustedDomainsAdded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		oldAgents   map[string]AgentProfile
		newAgents   map[string]AgentProfile
		wantFields  []string // exact ReloadWarning.Field values, in order
		wantInMsgs  []string // substrings that must appear across the matched warnings
		dontWantMsg string   // substring that must not appear anywhere
	}{
		{
			name:      "added_domain_on_existing_profile",
			oldAgents: map[string]AgentProfile{"alice": {TrustedDomains: []string{"a.example"}}},
			newAgents: map[string]AgentProfile{"alice": {TrustedDomains: []string{"a.example", "b.example"}}},
			wantFields: []string{
				"agents.alice.trusted_domains",
			},
			wantInMsgs: []string{`agent "alice" trusted domains added: b.example`},
		},
		{
			name:      "new_profile_entirely",
			oldAgents: map[string]AgentProfile{},
			newAgents: map[string]AgentProfile{"bob": {TrustedDomains: []string{"x.example"}}},
			wantFields: []string{
				"agents.bob.trusted_domains",
			},
			wantInMsgs: []string{`agent "bob" trusted domains added: x.example`},
		},
		{
			name: "profile_removed_no_warning",
			oldAgents: map[string]AgentProfile{
				"charlie": {TrustedDomains: []string{"x.example"}},
			},
			newAgents:   map[string]AgentProfile{},
			wantFields:  nil,
			dontWantMsg: `agents.charlie`,
		},
		{
			name: "shrunk_list_no_warning",
			oldAgents: map[string]AgentProfile{
				"dana": {TrustedDomains: []string{"x.example", "y.example"}},
			},
			newAgents: map[string]AgentProfile{
				"dana": {TrustedDomains: []string{"x.example"}},
			},
			wantFields:  nil,
			dontWantMsg: `agents.dana`,
		},
		{
			name: "multi_profile_added_deterministic_order",
			oldAgents: map[string]AgentProfile{
				"alpha": {},
				"beta":  {},
			},
			newAgents: map[string]AgentProfile{
				"alpha": {TrustedDomains: []string{"a.example"}},
				"beta":  {TrustedDomains: []string{"b.example"}},
			},
			wantFields: []string{
				"agents.alpha.trusted_domains",
				"agents.beta.trusted_domains",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			old := Defaults()
			old.Agents = tt.oldAgents
			updated := Defaults()
			updated.Agents = tt.newAgents

			warnings := ValidateReload(old, updated)

			gotFields := make([]string, 0, len(warnings))
			gotMsgs := make([]string, 0, len(warnings))
			for _, w := range warnings {
				if !strings.HasPrefix(w.Field, "agents.") || !strings.HasSuffix(w.Field, ".trusted_domains") {
					continue
				}
				gotFields = append(gotFields, w.Field)
				gotMsgs = append(gotMsgs, w.Message)
			}

			if len(gotFields) != len(tt.wantFields) {
				t.Fatalf("agent trusted_domains warnings: got %d, want %d (got=%v)", len(gotFields), len(tt.wantFields), gotFields)
			}
			for i, want := range tt.wantFields {
				if gotFields[i] != want {
					t.Errorf("warning[%d].Field = %q, want %q", i, gotFields[i], want)
				}
			}
			for _, sub := range tt.wantInMsgs {
				found := false
				for _, msg := range gotMsgs {
					if strings.Contains(msg, sub) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("no warning message contained %q; got=%v", sub, gotMsgs)
				}
			}
			if tt.dontWantMsg != "" {
				for _, msg := range gotMsgs {
					if strings.Contains(msg, tt.dontWantMsg) {
						t.Errorf("warning message %q should not contain %q", msg, tt.dontWantMsg)
					}
				}
			}
		})
	}
}

func TestValidateReload_ReverseProxyProfileChanged(t *testing.T) {
	old := Defaults()
	updated := Defaults()
	updated.ReverseProxy.Profile = ReverseProxyProfileSubmit

	warnings := ValidateReload(old, updated)
	found := false
	for _, w := range warnings {
		if w.Field == "reverse_proxy" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected reload warning for reverse_proxy.profile change (restart-only)")
	}
}

func TestValidateReload_ReverseProxyProfileUnchanged_NoWarning(t *testing.T) {
	old := Defaults()
	updated := Defaults()

	for _, w := range ValidateReload(old, updated) {
		if w.Field == "reverse_proxy" {
			t.Fatalf("unexpected reverse_proxy warning when profile unchanged: %+v", w)
		}
	}
}

func TestValidateReload_DashboardSnapshotChanged(t *testing.T) {
	t.Parallel()

	old := Defaults()
	updated := Defaults()
	updated.DashboardSnapshot.Path = "/tmp/other-runtime-snapshot.json"

	warnings := ValidateReload(old, updated)
	for _, w := range warnings {
		if w.Field == "dashboard_snapshot" {
			return
		}
	}
	t.Fatal("expected dashboard_snapshot restart-only warning")
}

func TestValidateReload_DashboardSnapshotUnchanged_NoWarning(t *testing.T) {
	t.Parallel()

	old := Defaults()
	updated := Defaults()

	for _, w := range ValidateReload(old, updated) {
		if w.Field == "dashboard_snapshot" {
			t.Fatalf("unexpected dashboard_snapshot warning when config unchanged: %+v", w)
		}
	}
}

func TestValidateReload_QueryEntropyParamExclusionsAdded(t *testing.T) {
	old := Defaults()
	updated := Defaults()
	updated.FetchProxy.Monitoring.QueryEntropyParamExclusions = []QueryEntropyParamExclusion{{
		Scheme: "https",
		Host:   "api.vendor.example",
		Path:   "/v1/search/recent",
		Param:  "query",
	}}

	warnings := ValidateReload(old, updated)
	var found bool
	for _, w := range warnings {
		if w.Field != "fetch_proxy.monitoring.query_entropy_param_exclusions" {
			continue
		}
		found = true
		if !strings.Contains(w.Message, "https://api.vendor.example/v1/search/recent?query") {
			t.Fatalf("reload warning message = %q, want normalized tuple", w.Message)
		}
		if !strings.Contains(w.Message, "only query-value entropy coverage is reduced") {
			t.Fatalf("reload warning message = %q, want query-value-only warning", w.Message)
		}
	}
	if !found {
		t.Fatal("expected query entropy param exclusion reload warning")
	}
}

func TestValidateReload_QueryEntropyParamExclusionsMetadataOnlyNoWarning(t *testing.T) {
	old := Defaults()
	old.FetchProxy.Monitoring.QueryEntropyParamExclusions = []QueryEntropyParamExclusion{{
		Scheme:  "https",
		Host:    "api.vendor.example",
		Path:    "/v1/search/recent",
		Param:   "query",
		Reason:  "initial reason",
		Owner:   "platform-security",
		Expires: "2026-12-31",
	}}
	updated := Defaults()
	updated.FetchProxy.Monitoring.QueryEntropyParamExclusions = []QueryEntropyParamExclusion{{
		Scheme:  "https",
		Host:    "api.vendor.example",
		Path:    "/v1/search/recent",
		Param:   "query",
		Reason:  "updated reason",
		Owner:   "platform-security",
		Expires: "2027-12-31",
	}}

	for _, w := range ValidateReload(old, updated) {
		if w.Field == "fetch_proxy.monitoring.query_entropy_param_exclusions" {
			t.Fatalf("metadata-only query entropy param change should not warn, got %+v", w)
		}
	}
}

func TestValidateReload_QueryEntropyParamExclusionsRemoved(t *testing.T) {
	old := Defaults()
	old.FetchProxy.Monitoring.QueryEntropyParamExclusions = []QueryEntropyParamExclusion{{
		Scheme: "https",
		Host:   "api.vendor.example",
		Path:   "/v1/search/recent",
		Param:  "query",
	}}
	updated := Defaults()

	warnings := ValidateReload(old, updated)
	var found bool
	for _, w := range warnings {
		if w.Field != "fetch_proxy.monitoring.query_entropy_param_exclusions" {
			continue
		}
		found = true
		if !strings.Contains(w.Message, "removed: https://api.vendor.example/v1/search/recent?query") {
			t.Fatalf("reload warning message = %q, want removed tuple", w.Message)
		}
		if !strings.Contains(w.Message, "again be subject to query-value entropy blocks") {
			t.Fatalf("reload warning message = %q, want restored entropy-block warning", w.Message)
		}
	}
	if !found {
		t.Fatal("expected query entropy param exclusion removal reload warning")
	}
}

func TestValidateReload_QueryEntropyParamExclusionsMalformedOrDuplicateNoPanic(t *testing.T) {
	old := Defaults()
	old.FetchProxy.Monitoring.QueryEntropyParamExclusions = []QueryEntropyParamExclusion{
		{Scheme: "https", Host: "API.VENDOR.EXAMPLE.", Path: "/v1/search/recent", Param: "query"},
		{Scheme: "https", Host: "api.vendor.example", Path: "/v1/search/recent", Param: "query"},
		{Scheme: "https", Host: "", Path: "", Param: ""},
	}
	updated := Defaults()
	updated.FetchProxy.Monitoring.QueryEntropyParamExclusions = []QueryEntropyParamExclusion{
		{Scheme: "https", Host: "api.vendor.example", Path: "/v1/search/recent", Param: "query"},
		{Scheme: "https", Host: "", Path: "", Param: ""},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ValidateReload panicked on malformed or duplicate query entropy param exclusions: %v", r)
		}
	}()
	_ = ValidateReload(old, updated)
}
