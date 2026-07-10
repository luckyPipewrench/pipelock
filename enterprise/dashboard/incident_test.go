//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func incidentTarget() string {
	return "/incident?org_id=" + wbTestOrgID + "&fleet_id=" + wbTestFleetID + "&artifact_hash=" + wbTestArtifactHash
}

func TestIncident_ScopePromptWhenEmpty(t *testing.T) {
	t.Parallel()

	handler := New(Options{ReceiptDir: t.TempDir(), HasFeature: allowFleetFeature})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/incident", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{incidentClaim, incidentNonClaim, "Supply", "never kills an agent"} {
		if !strings.Contains(body, want) {
			t.Fatalf("incident body missing %q: %s", want, body)
		}
	}
}

func TestIncident_UnconfiguredSourcesRenderAbsence(t *testing.T) {
	t.Parallel()

	handler := New(Options{ReceiptDir: t.TempDir(), HasFeature: allowFleetFeature})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, incidentTarget(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"No conductor decision source configured", "No conductor fleet source configured"} {
		if !strings.Contains(body, want) {
			t.Fatalf("incident body missing %q: %s", want, body)
		}
	}
}

func TestIncident_CorrelatesDecisionAndAppliedSummary(t *testing.T) {
	t.Parallel()

	source := &fakeConductorSource{view: testReplayView(), found: true}
	fleet := &fakeFleetSource{followers: testFleetFollowers()}
	handler := New(Options{
		ReceiptDir:          t.TempDir(),
		HasFeature:          allowFleetFeature,
		ConductorSource:     source,
		FleetSource:         fleet,
		AuthorizeRaw:        allowRawAccess,
		AuthorizeFleetScope: allowFleetScope,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, incidentTarget(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if fleet.gotOrgID != wbTestOrgID || fleet.gotFleet != wbTestFleetID {
		t.Fatalf("fleet scope = (%q,%q), want (%q,%q)", fleet.gotOrgID, fleet.gotFleet, wbTestOrgID, wbTestFleetID)
	}
	if fleet.gotLimit != fleetOverviewFollowerLimit+1 {
		t.Fatalf("fleet limit = %d, want %d", fleet.gotLimit, fleetOverviewFollowerLimit+1)
	}
	body := rec.Body.String()
	// testFleetFollowers(): 1 verified, 1 signed-unverified, 1 unsigned.
	for _, want := range []string{
		"Rollback", "Divergence",
		"verified applied", "signed, unverified", "unsigned/self-reported",
		"followers",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("incident body missing %q: %s", want, body)
		}
	}
}

func TestIncident_AppliedSummaryCountsAreCorrect(t *testing.T) {
	t.Parallel()

	model := NewReadModel(Options{ReceiptDir: t.TempDir(), FleetSource: &fakeFleetSource{followers: testFleetFollowers()}})
	summary, err := model.fleetAppliedSummary(context.Background(), wbTestOrgID, wbTestFleetID)
	if err != nil {
		t.Fatalf("fleetAppliedSummary: %v", err)
	}
	if summary.Total != 3 {
		t.Fatalf("Total = %d, want 3", summary.Total)
	}
	if summary.Verified != 1 || summary.SignedUnverified != 1 || summary.Unsigned != 1 {
		t.Fatalf("counts = verified %d / signed-unverified %d / unsigned %d, want 1/1/1",
			summary.Verified, summary.SignedUnverified, summary.Unsigned)
	}
	if summary.NoReport != 0 {
		t.Fatalf("NoReport = %d, want 0", summary.NoReport)
	}
	if summary.Drift != 0 {
		t.Fatalf("Drift = %d, want 0", summary.Drift)
	}
	if summary.ApplyFailed != 0 {
		t.Fatalf("ApplyFailed = %d, want 0", summary.ApplyFailed)
	}
}

func TestIncident_MetadataViewRedactsDecision(t *testing.T) {
	t.Parallel()

	view := testReplayView()
	view.Valid = false
	view.Conflict = "source error for " + wbSensitiveHash
	source := &fakeConductorSource{view: view, found: true}
	handler := New(Options{
		ReceiptDir:      t.TempDir(),
		HasFeature:      allowFleetFeature,
		ConductorSource: source,
		FleetSource:     &fakeFleetSource{followers: testFleetFollowers()},
		// No AuthorizeRaw: fail closed.
		AuthorizeFleetScope: allowFleetScope,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, incidentTarget(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, secret := range []string{wbSensitiveHash, wbSensitiveResult, wbSensitiveReason, wbTestOrgID, wbTestFleetID, "source error"} {
		if strings.Contains(body, secret) {
			t.Fatalf("metadata incident leaked %q: %s", secret, body)
		}
	}
	if !strings.Contains(body, "org <span class=\"mono\">"+fleetRedacted+"</span>") ||
		!strings.Contains(body, "fleet <span class=\"mono\">"+fleetRedacted+"</span>") {
		t.Fatalf("metadata incident missing redacted scope: %s", body)
	}
	if !strings.Contains(body, "Would be rejected: unknown") {
		t.Fatalf("metadata incident missing bounded conflict code: %s", body)
	}
	// Applied-state counts (non-identifying) are still shown in the metadata view.
	if !strings.Contains(body, "verified applied") {
		t.Fatalf("metadata incident missing applied counts: %s", body)
	}
}

func TestIncident_DecisionMissingRendersEmpty(t *testing.T) {
	t.Parallel()

	source := &fakeConductorSource{found: false}
	handler := New(Options{ReceiptDir: t.TempDir(), HasFeature: allowFleetFeature, ConductorSource: source, AuthorizeFleetScope: allowFleetScope})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, incidentTarget(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "No recorded decision matched") {
		t.Fatalf("body missing decision-missing state: %s", rec.Body.String())
	}
}

func TestIncident_FleetSourceErrorReturnsServerError(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		ReceiptDir:          t.TempDir(),
		HasFeature:          allowFleetFeature,
		ConductorSource:     &fakeConductorSource{found: false},
		FleetSource:         &fakeFleetSource{err: errors.New("fleet unavailable")},
		AuthorizeFleetScope: allowFleetScope,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, incidentTarget(), nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

func TestIncident_DecisionSourceErrorReturnsServerError(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		ReceiptDir:          t.TempDir(),
		HasFeature:          allowFleetFeature,
		ConductorSource:     &fakeConductorSource{err: errors.New("replay unavailable")},
		AuthorizeFleetScope: allowFleetScope,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, incidentTarget(), nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}
