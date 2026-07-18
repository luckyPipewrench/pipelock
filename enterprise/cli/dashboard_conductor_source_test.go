//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	conductorcli "github.com/luckyPipewrench/pipelock/enterprise/cli/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
)

type fakeDashboardConductorClient struct {
	body       []byte
	err        error
	gotOrg     string
	gotFleet   string
	gotLimit   int
	calledList bool
}

func (f *fakeDashboardConductorClient) ListFollowers(_ context.Context, orgID, fleetID string, limit int) ([]byte, error) {
	f.calledList = true
	f.gotOrg = orgID
	f.gotFleet = fleetID
	f.gotLimit = limit
	if f.err != nil {
		return nil, f.err
	}
	return f.body, nil
}

func TestDashboardConductorSourceListFleetFollowersMapsFollowers(t *testing.T) {
	now := time.Date(2026, 7, 12, 14, 0, 0, 0, time.UTC)
	resp := dashboardConductorFollowersResponse{
		Followers: []controlplane.FollowerFleetStatus{
			{
				FollowerSummary: controlplane.FollowerSummary{
					OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1", Environment: "prod",
					AuditKeyID: "audit-key-1", EnrolledAt: now.Add(-time.Hour), Active: true,
				},
				RuntimeStatus: &controlplane.FollowerRuntimeStatus{
					LastSeenAt: now, ActiveBundleID: "bundle-v2", ActiveBundleVersion: 2,
					ActiveBundleHash: strings.Repeat("a", 64), ActiveBundleMinPipelockVersion: "1.2.3",
					PipelockVersion: "1.2.4", GitCommit: "abc123", BuildDate: "2026-07-12",
					LastPolicyPollAt: now.Add(-time.Minute), LastSuccessfulApplyAt: now.Add(-2 * time.Minute),
				},
				SignedAppliedState: &controlplane.VerifiedAppliedState{
					SignerKeyID: "signer-1", BatchID: "batch-1", EnvelopeHash: "env-hash",
					ObservedAt: now.Add(-30 * time.Second), VerifiedAt: now,
					Verified: true,
					AppliedState: conductor.FollowerAppliedState{
						ActiveBundleID: "bundle-v2", ActiveBundleVersion: 2, ActiveBundleHash: strings.Repeat("b", 64),
						ActiveBundleMinPipelockVersion: "1.2.3", PipelockVersion: "1.2.5",
						LastApplyErrorCode: "apply_failed", LastApplyErrorMessage: "synthetic failure",
					},
				},
				Health:         controlplane.FleetHealthApplyFailed,
				Drift:          "drift",
				ExpectedBundle: controlplane.ExpectedBundle{BundleID: "bundle-v2", Version: 2, BundleHash: strings.Repeat("c", 64), MinPipelockVersion: "1.2.3"},
			},
		},
		Count:   1,
		HasMore: boolPtr(false),
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	client := &fakeDashboardConductorClient{body: body}
	source := &dashboardConductorSource{client: client, orgID: "org-main", fleet: "prod"}

	page, err := source.ListFleetFollowers(context.Background(), "org-main", "prod", 1)
	if err != nil {
		t.Fatalf("ListFleetFollowers: %v", err)
	}
	if !client.calledList || client.gotOrg != "org-main" || client.gotFleet != "prod" || client.gotLimit != 1 {
		t.Fatalf("client call = called:%t org:%q fleet:%q limit:%d", client.calledList, client.gotOrg, client.gotFleet, client.gotLimit)
	}
	if !page.CompletenessKnown || page.HasMore {
		t.Fatalf("page completeness known=%t hasMore=%t, want known complete", page.CompletenessKnown, page.HasMore)
	}
	if len(page.Followers) != 1 {
		t.Fatalf("followers len = %d, want 1", len(page.Followers))
	}
	got := page.Followers[0]
	if got.InstanceID != "pl-prod-1" || got.FleetHealth != "apply_failed" || got.Drift != "drift" {
		t.Fatalf("mapped basic follower = %+v", got)
	}
	if !got.RuntimeReported || !got.SignedStatePresent || !got.Verified {
		t.Fatalf("runtime/signed flags = runtime:%t signed:%t verified:%t", got.RuntimeReported, got.SignedStatePresent, got.Verified)
	}
	if got.ActiveBundleHash != strings.Repeat("b", 64) || got.SignerKeyID != "signer-1" || got.LastApplyErrorCode != "apply_failed" {
		t.Fatalf("signed state did not take precedence: %+v", got)
	}
}

func TestDashboardFollowerViewDoesNotTrustUnverifiedSignedAppliedState(t *testing.T) {
	now := time.Date(2026, 7, 12, 15, 0, 0, 0, time.UTC)
	view := dashboardFollowerView(controlplane.FollowerFleetStatus{
		FollowerSummary: controlplane.FollowerSummary{
			OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1",
		},
		RuntimeStatus: &controlplane.FollowerRuntimeStatus{
			LastSeenAt: now, ActiveBundleID: "runtime-bundle", ActiveBundleVersion: 7,
			ActiveBundleHash: strings.Repeat("a", 64), ActiveBundleMinPipelockVersion: "1.2.3",
			PipelockVersion: "1.2.4", GitCommit: "runtime-commit", BuildDate: "2026-07-12",
			LastPolicyPollAt: now.Add(-time.Minute), LastSuccessfulApplyAt: now.Add(-2 * time.Minute),
		},
		SignedAppliedState: &controlplane.VerifiedAppliedState{
			SignerKeyID: "signer-1", BatchID: "batch-1", EnvelopeHash: "env-hash",
			ObservedAt: now.Add(-30 * time.Second), VerifiedAt: now,
			Verified: false,
			AppliedState: conductor.FollowerAppliedState{
				ActiveBundleID: "unverified-bundle", ActiveBundleVersion: 99, ActiveBundleHash: strings.Repeat("b", 64),
				ActiveBundleMinPipelockVersion: "9.9.9", PipelockVersion: "9.9.9",
				LastApplyErrorCode: "unverified_error", LastApplyErrorMessage: "do not display as runtime state",
			},
		},
	})
	if !view.RuntimeReported || !view.SignedStatePresent || view.Verified {
		t.Fatalf("flags = runtime:%t signed:%t verified:%t", view.RuntimeReported, view.SignedStatePresent, view.Verified)
	}
	if view.SignerKeyID != "signer-1" || view.BatchID != "batch-1" || view.EnvelopeHash != "env-hash" {
		t.Fatalf("signed metadata missing: %+v", view)
	}
	if view.ActiveBundleID != "runtime-bundle" || view.ActiveBundleVersion != 7 || view.ActiveBundleHash != strings.Repeat("a", 64) ||
		view.PipelockVersion != "1.2.4" || view.GitCommit != "runtime-commit" || view.LastApplyErrorCode != "" {
		t.Fatalf("unverified signed state overrode runtime fields: %+v", view)
	}
}

func TestDashboardConductorSourceCompletenessSignals(t *testing.T) {
	tests := []struct {
		name      string
		resp      dashboardConductorFollowersResponse
		limit     int
		wantKnown bool
		wantMore  bool
		wantErr   string
	}{
		{
			name: "explicit exactly limit complete",
			resp: dashboardConductorFollowersResponse{
				Followers: []controlplane.FollowerFleetStatus{testConductorFollower("org-main", "prod", "pl-prod-1")},
				Count:     1,
				Complete:  boolPtr(true),
			},
			limit:     1,
			wantKnown: true,
		},
		{
			name: "explicit truncated",
			resp: dashboardConductorFollowersResponse{
				Followers: []controlplane.FollowerFleetStatus{testConductorFollower("org-main", "prod", "pl-prod-1")},
				Count:     1,
				HasMore:   boolPtr(true),
			},
			limit:     1,
			wantKnown: true,
			wantMore:  true,
		},
		{
			name: "legacy exact limit unknown",
			resp: dashboardConductorFollowersResponse{
				Followers: []controlplane.FollowerFleetStatus{testConductorFollower("org-main", "prod", "pl-prod-1")},
				Count:     1,
			},
			limit: 1,
		},
		{
			name: "conflicting explicit fields",
			resp: dashboardConductorFollowersResponse{
				Followers: []controlplane.FollowerFleetStatus{},
				HasMore:   boolPtr(false),
				Complete:  boolPtr(true),
			},
			limit:   1,
			wantErr: "conflicting",
		},
		{
			name: "unknown completeness with explicit has more",
			resp: dashboardConductorFollowersResponse{
				Followers:         []controlplane.FollowerFleetStatus{},
				Count:             0,
				CompletenessKnown: boolPtr(false),
				HasMore:           boolPtr(true),
			},
			limit:   1,
			wantErr: "unknown completeness",
		},
		{
			name: "unknown completeness with explicit complete",
			resp: dashboardConductorFollowersResponse{
				Followers:         []controlplane.FollowerFleetStatus{},
				Count:             0,
				CompletenessKnown: boolPtr(false),
				Complete:          boolPtr(true),
			},
			limit:   1,
			wantErr: "unknown completeness",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.resp)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			source := &dashboardConductorSource{
				client: &fakeDashboardConductorClient{body: body},
				orgID:  "org-main",
				fleet:  "prod",
			}
			page, err := source.ListFleetFollowers(context.Background(), "org-main", "prod", tc.limit)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ListFleetFollowers: %v", err)
			}
			if page.CompletenessKnown != tc.wantKnown || page.HasMore != tc.wantMore {
				t.Fatalf("known=%t more=%t, want known=%t more=%t", page.CompletenessKnown, page.HasMore, tc.wantKnown, tc.wantMore)
			}
		})
	}
}

func TestDashboardConductorSourceFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		client  *fakeDashboardConductorClient
		org     string
		fleet   string
		limit   int
		wantErr string
	}{
		{"scope mismatch", &fakeDashboardConductorClient{body: []byte(`{"followers":[],"count":0}`)}, "other", "prod", 1, "not configured"},
		{"non positive limit", &fakeDashboardConductorClient{body: []byte(`{"followers":[],"count":0}`)}, "org-main", "prod", 0, "limit"},
		{"limit too high", &fakeDashboardConductorClient{body: []byte(`{"followers":[],"count":0}`)}, "org-main", "prod", conductorcli.ReadClientFollowerLimitMax + 1, "exceeds maximum"},
		{"client error", &fakeDashboardConductorClient{err: errors.New("status 500")}, "org-main", "prod", 1, "status 500"},
		{"malformed json", &fakeDashboardConductorClient{body: []byte(`{"followers":[`)}, "org-main", "prod", 1, "decode"},
		{"trailing json", &fakeDashboardConductorClient{body: []byte(`{"followers":[],"count":0}{}`)}, "org-main", "prod", 1, "trailing"},
		{"count mismatch", &fakeDashboardConductorClient{body: []byte(`{"followers":[],"count":1}`)}, "org-main", "prod", 1, "count=1 len=0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source := &dashboardConductorSource{client: tc.client, orgID: "org-main", fleet: "prod"}
			_, err := source.ListFleetFollowers(context.Background(), tc.org, tc.fleet, tc.limit)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
			if strings.Contains(tc.wantErr, "not configured") && tc.client.calledList {
				t.Fatal("scope mismatch reached conductor client")
			}
		})
	}
}

func TestDashboardConductorSourceRejectsInvalidReturnedFollowers(t *testing.T) {
	tests := []struct {
		name      string
		followers []controlplane.FollowerFleetStatus
		wantErr   string
	}{
		{
			name:      "cross org",
			followers: []controlplane.FollowerFleetStatus{testConductorFollower("org-other", "prod", "pl-prod-1")},
			wantErr:   "outside configured scope",
		},
		{
			name:      "cross fleet",
			followers: []controlplane.FollowerFleetStatus{testConductorFollower("org-main", "staging", "pl-prod-1")},
			wantErr:   "outside configured scope",
		},
		{
			name:      "scope with whitespace",
			followers: []controlplane.FollowerFleetStatus{testConductorFollower(" org-main", "prod", "pl-prod-1")},
			wantErr:   "outside configured scope",
		},
		{
			name:      "empty instance",
			followers: []controlplane.FollowerFleetStatus{testConductorFollower("org-main", "prod", "")},
			wantErr:   "invalid follower identity",
		},
		{
			name:      "control character instance",
			followers: []controlplane.FollowerFleetStatus{testConductorFollower("org-main", "prod", "pl-prod-\n1")},
			wantErr:   "invalid follower identity",
		},
		{
			name: "duplicate instance",
			followers: []controlplane.FollowerFleetStatus{
				testConductorFollower("org-main", "prod", "pl-prod-1"),
				testConductorFollower("org-main", "prod", "pl-prod-1"),
			},
			wantErr: "duplicate follower identity",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := dashboardConductorFollowersResponse{Followers: tc.followers, Count: len(tc.followers)}
			body, err := json.Marshal(resp)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			source := &dashboardConductorSource{
				client: &fakeDashboardConductorClient{body: body},
				orgID:  "org-main",
				fleet:  "prod",
			}
			_, err = source.ListFleetFollowers(context.Background(), "org-main", "prod", 10)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateDashboardConductorConfig(t *testing.T) {
	base := dashboardServeOptions{
		conductorURL:       "https://127.0.0.1:8895",
		conductorTokenFile: "token",
		conductorTLSCert:   "client.pem",
		conductorTLSKey:    "client.key",
		conductorServerCA:  "ca.pem",
		conductorOrg:       "org-main",
		conductorFleet:     "prod",
	}
	tests := []struct {
		name    string
		mut     func(*dashboardServeOptions)
		wantErr string
	}{
		{"unset ok", func(o *dashboardServeOptions) { *o = dashboardServeOptions{} }, ""},
		{"complete ok", func(*dashboardServeOptions) {}, ""},
		{"option without url", func(o *dashboardServeOptions) { o.conductorURL = "" }, "--conductor-url"},
		{"missing token", func(o *dashboardServeOptions) { o.conductorTokenFile = "" }, "--conductor-token-file"},
		{"missing cert", func(o *dashboardServeOptions) { o.conductorTLSCert = "" }, "--conductor-tls-cert"},
		{"missing key", func(o *dashboardServeOptions) { o.conductorTLSKey = "" }, "--conductor-tls-key"},
		{"missing ca", func(o *dashboardServeOptions) { o.conductorServerCA = "" }, "--conductor-server-ca"},
		{"missing org", func(o *dashboardServeOptions) { o.conductorOrg = "" }, "--conductor-org"},
		{"missing fleet", func(o *dashboardServeOptions) { o.conductorFleet = "" }, "--conductor-fleet"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := base
			tc.mut(&opts)
			err := validateDashboardConductorConfig(opts)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("validateDashboardConductorConfig: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewDashboardConductorSourceConstructsWithoutNetwork(t *testing.T) {
	certFile, keyFile, caFile := writeConductorSourceClientMaterial(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("conductor-read-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(token): %v", err)
	}
	source, err := newDashboardConductorSource(dashboardServeOptions{
		conductorURL:       "https://127.0.0.1:8895",
		conductorTokenFile: tokenFile,
		conductorTLSCert:   certFile,
		conductorTLSKey:    keyFile,
		conductorServerCA:  caFile,
		conductorOrg:       "org-main",
		conductorFleet:     "prod",
	})
	if err != nil {
		t.Fatalf("newDashboardConductorSource: %v", err)
	}
	if source == nil || source.orgID != "org-main" || source.fleet != "prod" {
		t.Fatalf("source = %+v", source)
	}
}

func TestDashboardConductorFleetScopeAuthorizer(t *testing.T) {
	authorize := dashboardConductorFleetScopeAuthorizer("org-main", "prod")
	if err := authorize(nil, dashboard.DecisionScope{OrgID: "org-main", FleetID: "prod"}, false); err != nil {
		t.Fatalf("authorized scope rejected: %v", err)
	}
	if err := authorize(nil, dashboard.DecisionScope{OrgID: "org-other", FleetID: "prod"}, false); err == nil {
		t.Fatal("cross-org scope allowed")
	}
	if err := authorize(nil, dashboard.DecisionScope{OrgID: "org-main", FleetID: "staging"}, false); err == nil {
		t.Fatal("cross-fleet scope allowed")
	}
}

func writeConductorSourceClientMaterial(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()
	certFile, keyFile, _ = writeDashTLSCert(t)
	return certFile, keyFile, certFile
}

func testConductorFollower(orgID, fleetID, instanceID string) controlplane.FollowerFleetStatus {
	return controlplane.FollowerFleetStatus{
		FollowerSummary: controlplane.FollowerSummary{
			OrgID:      orgID,
			FleetID:    fleetID,
			InstanceID: instanceID,
		},
	}
}

func boolPtr(v bool) *bool {
	return &v
}
