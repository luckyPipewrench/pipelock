//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

func TestEvaluateControlMappingFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		control ControlDefinition
		signals map[string]EvidenceSignal
		want    CoverageStatus
	}{
		{
			name:    "no evidence is not covered",
			control: ControlDefinition{Evidence: []EvidenceRequirement{{Key: "receipt.chain"}}},
			want:    CoverageNotCovered,
		},
		{
			name: "partial evidence is partial",
			control: ControlDefinition{Evidence: []EvidenceRequirement{
				{Key: "receipt.chain"},
				{Key: "config.require_receipts"},
			}},
			signals: map[string]EvidenceSignal{
				"receipt.chain": {Present: true, Detail: "verified chain"},
			},
			want: CoveragePartial,
		},
		{
			name: "all declared evidence is covered",
			control: ControlDefinition{Evidence: []EvidenceRequirement{
				{Key: "receipt.chain"},
				{Key: "config.require_receipts"},
			}},
			signals: map[string]EvidenceSignal{
				"receipt.chain":           {Present: true, Detail: "verified chain"},
				"config.require_receipts": {Present: true, Detail: "enabled"},
			},
			want: CoverageCovered,
		},
		{
			name: "unknown and hostile evidence cannot overclaim",
			control: ControlDefinition{Evidence: []EvidenceRequirement{
				{Key: "receipt.chain"},
				{Key: "config.require_receipts"},
			}},
			signals: map[string]EvidenceSignal{
				"unknown":       {Present: true, Detail: hostileScript},
				"receipt.chain": {Present: false, Detail: hostileImage},
			},
			want: CoverageNotCovered,
		},
		{
			name:    "empty requirement set cannot be green by default",
			control: ControlDefinition{},
			signals: map[string]EvidenceSignal{"unknown": {Present: true}},
			want:    CoverageNotCovered,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := evaluateControlMapping(tc.control, tc.signals)
			if got.Status != tc.want {
				t.Fatalf("status = %q, want %q; mapping=%+v", got.Status, tc.want, got)
			}
		})
	}
}

func TestFrameworkDefinitionsIncludeAARMAndGenericSOC2(t *testing.T) {
	t.Parallel()

	frameworks := frameworkDefinitions()
	counts := map[string]int{}
	for _, framework := range frameworks {
		counts[framework.ID] = len(framework.Controls)
	}
	if counts["aarm-v1"] != 9 {
		t.Fatalf("AARM controls = %d, want 9", counts["aarm-v1"])
	}
	if counts["soc2-style"] == 0 {
		t.Fatal("generic SOC 2-style mapping is missing")
	}
}

func TestFrameworkMappingsDoNotSubstituteConfigurationForRuntimeEvidence(t *testing.T) {
	t.Parallel()

	signals := map[string]EvidenceSignal{
		"receipt.action":            {Present: true},
		"receipt.trusted_signature": {Present: true},
		"config.bound_identity":     {Present: true},
		"config.otlp":               {Present: true},
		"legal_hold.active":         {Present: true},
	}
	frameworks := evaluateFrameworks(signals)
	for _, tc := range []struct {
		frameworkID string
		controlID   string
	}{
		{frameworkID: "aarm-v1", controlID: "R6"},
		{frameworkID: "aarm-v1", controlID: "R8"},
		{frameworkID: "soc2-style", controlID: "CC7.2-style"},
		{frameworkID: "soc2-style", controlID: "CC8.1-style"},
	} {
		var status CoverageStatus
		for _, framework := range frameworks {
			if framework.ID != tc.frameworkID {
				continue
			}
			for _, control := range framework.Controls {
				if control.ID == tc.controlID {
					status = control.Status
				}
			}
		}
		if status == CoverageCovered {
			t.Errorf("%s/%s is covered without required runtime evidence", tc.frameworkID, tc.controlID)
		}
	}
}

func TestComplianceTemplateEscapesHostileEvidence(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := complianceTemplate.Execute(&out, CompliancePage{
		Limitation: hostileScript,
		Frameworks: []FrameworkMapping{{Controls: []ControlMapping{{
			ID: hostileImage, Status: CoverageNotCovered,
			Evidence: []MappedEvidence{{Detail: hostileJSON}},
		}}}},
		LegalHolds: []LegalHold{{ID: hostileScript, Scope: hostileImage, Reason: hostileJSON}},
		Fleet: FleetCoverageRollup{SourceConfigured: true, Agents: []FleetAgentCoverageRow{{
			AgentID: hostileScript, Status: CoverageNotCovered,
		}}},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, hostile := range []string{hostileScript, hostileImage, hostileJSON} {
		if strings.Contains(out.String(), hostile) {
			t.Fatalf("template emitted hostile input %q without escaping", hostile)
		}
	}
}

func TestComplianceReadPrincipalReachesOnlyComplianceRoutes(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       func(string) bool { return true },
		Authorize:        func(*http.Request) error { return nil },
		AuthorizeRaw: func(*http.Request) error {
			return errors.New("raw denied")
		},
		AuthorizePermission: func(_ *http.Request, permission Permission) error {
			if permission == PermissionComplianceRead {
				return nil
			}
			return errors.New("permission denied")
		},
	})

	paths := map[string]bool{
		"/":                               false,
		"/exemptions":                     false,
		"/session/session-a":              false,
		"/session/session-a/receipt/0":    false,
		"/agents":                         false,
		"/agent/agent-a":                  false,
		"/budgets":                        false,
		"/fleet":                          false,
		"/workbench":                      false,
		"/incident":                       false,
		"/compliance":                     true,
		"/compliance?org_id=o&fleet_id=f": true,
	}
	for path, allowed := range paths {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
			handler.ServeHTTP(rec, req)
			if allowed && rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			if !allowed && rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "Signed Action Workbench") {
				t.Fatal("compliance-only principal reached signed-action content")
			}
		})
	}
}

func TestComplianceHTTPHasNoLegalHoldMutationAuthority(t *testing.T) {
	t.Parallel()

	store, err := OpenLegalHoldStore(filepath.Join(t.TempDir(), "holds.json"))
	if err != nil {
		t.Fatalf("OpenLegalHoldStore: %v", err)
	}
	if err := store.Add(LegalHold{
		ID: "hold-a", Scope: "agent-a", Reason: "review", Created: time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(), LegalHoldStore: store,
		HasFeature:          func(string) bool { return true },
		Authorize:           func(*http.Request) error { return nil },
		AuthorizePermission: func(*http.Request, Permission) error { return nil },
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/compliance", strings.NewReader(`{"release":"hold-a"}`))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /compliance status = %d, want 405", rec.Code)
	}
	holds, err := store.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(holds) != 1 || holds[0].Released != nil {
		t.Fatalf("holds = %+v, HTTP request mutated legal-hold authority", holds)
	}
}

func TestRouteGateRejectsUnknownPermissionBeforeHandler(t *testing.T) {
	t.Parallel()

	d := &dashboardHandler{
		hasFeature: func(string) bool { return true },
		authorizePermission: func(*http.Request, Permission) error {
			return nil
		},
	}
	for _, permission := range []Permission{"", "dashboard:unknown"} {
		t.Run(string(permission), func(t *testing.T) {
			called := false
			h := d.routeGate(routeSpec{
				feature:          license.FeatureAgents,
				forbiddenMessage: agentsFeatureForbidden,
				permission:       permission,
			}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
			if rec.Code != http.StatusForbidden || called {
				t.Fatalf("permission %q status=%d called=%t, want 403/false", permission, rec.Code, called)
			}
		})
	}
}

func TestComplianceFleetRollupHonestEmptyAndAggregation(t *testing.T) {
	t.Parallel()

	t.Run("nil source", func(t *testing.T) {
		model := NewReadModel(Options{ReceiptDir: t.TempDir()})
		page, err := model.Compliance(context.Background(), "", "")
		if err != nil {
			t.Fatalf("Compliance: %v", err)
		}
		if page.Fleet.SourceConfigured || len(page.Fleet.Agents) != 0 {
			t.Fatalf("fleet = %+v, want honest unconfigured empty state", page.Fleet)
		}
	})

	t.Run("typed nil source", func(t *testing.T) {
		var source *complianceFleetFake
		model := NewReadModel(Options{ReceiptDir: t.TempDir(), FleetSource: source})
		page, err := model.Compliance(context.Background(), "", "")
		if err != nil {
			t.Fatalf("Compliance: %v", err)
		}
		if page.Fleet.SourceConfigured || len(page.Fleet.Agents) != 0 {
			t.Fatalf("fleet = %+v, want typed nil source treated as unconfigured", page.Fleet)
		}
	})

	t.Run("per-agent rollup", func(t *testing.T) {
		source := &complianceFleetFake{coverage: []FleetAgentCoverage{
			{AgentID: "agent-a", CoverageCertificateVerified: true, SessionsCovered: 3},
			{AgentID: "agent-b", CoverageCertificateVerified: true, SessionsCovered: 2, ChainGaps: 1},
			{AgentID: "agent-c"},
		}}
		model := NewReadModel(Options{ReceiptDir: t.TempDir(), FleetSource: source})
		page, err := model.Compliance(context.Background(), "org-a", "fleet-a")
		if err != nil {
			t.Fatalf("Compliance: %v", err)
		}
		if !page.Fleet.SourceConfigured || page.Fleet.Covered != 1 || page.Fleet.Partial != 1 || page.Fleet.NotCovered != 1 {
			t.Fatalf("fleet rollup = %+v, want 1 covered/1 partial/1 not-covered", page.Fleet)
		}
		if !strings.Contains(page.Fleet.Limitation, "mediated egress") || !strings.Contains(page.Fleet.Limitation, "LIMITED") {
			t.Fatalf("limitation = %q, want mediated-egress LIMITED wording", page.Fleet.Limitation)
		}
	})

	t.Run("exact display limit is conservatively truncated", func(t *testing.T) {
		coverage := make([]FleetAgentCoverage, complianceFleetAgentLimit)
		for i := range coverage {
			coverage[i] = FleetAgentCoverage{
				AgentID: fmt.Sprintf("agent-%03d", i), CoverageCertificateVerified: true, SessionsCovered: 1,
			}
		}
		model := NewReadModel(Options{ReceiptDir: t.TempDir(), FleetSource: &complianceFleetFake{coverage: coverage}})
		page, err := model.Compliance(context.Background(), "org-a", "fleet-a")
		if err != nil {
			t.Fatalf("Compliance: %v", err)
		}
		if !page.Fleet.Truncated {
			t.Fatal("a full display-limit response was presented as a complete fleet rollup")
		}
	})
}

func TestComplianceFleetRollupFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		orgID   string
		fleetID string
		source  *complianceFleetFake
	}{
		{name: "missing scope", source: &complianceFleetFake{}},
		{name: "hostile scope", orgID: "<script>", fleetID: "fleet-a", source: &complianceFleetFake{}},
		{name: "source error", orgID: "org-a", fleetID: "fleet-a", source: &complianceFleetFake{err: errors.New("source unavailable")}},
		{
			name: "duplicate agent identity", orgID: "org-a", fleetID: "fleet-a",
			source: &complianceFleetFake{coverage: []FleetAgentCoverage{
				{AgentID: "agent-a", CoverageCertificateVerified: true, SessionsCovered: 1},
				{AgentID: " agent-a ", CoverageCertificateVerified: true, SessionsCovered: 1},
			}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			model := NewReadModel(Options{ReceiptDir: t.TempDir(), FleetSource: tc.source})
			if _, err := model.Compliance(context.Background(), tc.orgID, tc.fleetID); err == nil {
				t.Fatal("Compliance accepted invalid or unavailable fleet input")
			}
		})
	}
}

func TestNormalizeFleetAgentCoverageRejectsMalformedCounts(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		agentID string
		count   int
	}{
		{name: "negative count", agentID: "agent-a", count: -1},
		{name: "missing identity", count: 1},
		{name: "control character", agentID: "agent-a\x1b[2J", count: 1},
		{name: "oversized identity", agentID: strings.Repeat("a", 4097), count: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := normalizeFleetAgentCoverage(FleetAgentCoverage{
				AgentID: tc.agentID, CoverageCertificateVerified: true, SessionsCovered: tc.count,
			})
			if row.Status != CoverageNotCovered || row.Certificate != "invalid coverage record" {
				t.Fatalf("row = %+v, want fail-closed malformed record", row)
			}
		})
	}
}

func TestComplianceSignalsRequireOneAuthenticAndIntactPipPerSession(t *testing.T) {
	t.Parallel()

	signals := complianceSignals(nil, []SessionSummary{
		{ReceiptCount: 1, Pips: []SummaryPip{
			{Label: "A", State: StateVerify},
			{Label: "A", State: StateVerify},
			{Label: "U", State: StateVerify},
			{Label: "U", State: StateVerify},
		}},
		{ReceiptCount: 1},
	}, FleetCoverageRollup{}, nil)
	if signals["receipt.trusted_signature"].Present {
		t.Fatal("duplicate authentic pips falsely claimed every session was verified")
	}
	if signals["receipt.chain"].Present {
		t.Fatal("duplicate chain pips falsely claimed every session was intact")
	}
}

type complianceFleetFake struct {
	coverage []FleetAgentCoverage
	err      error
}

func (f *complianceFleetFake) ListFleetFollowers(context.Context, string, string, int) (FleetFollowerPage, error) {
	return FleetFollowerPage{CompletenessKnown: true}, nil
}

func (f *complianceFleetFake) ListFleetAgentCoverage(context.Context, string, string, int) ([]FleetAgentCoverage, error) {
	return f.coverage, f.err
}
