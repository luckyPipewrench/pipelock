// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	explainIdentityKey = "explain-agent|10.0.0.7"
	explainAuthHeader  = "Bearer " + testSessionAPIToken
	explainEvidence    = "injection payload detected in response body"
	explainManual      = "manual"
)

func explainURLFor(key string) string {
	return "/api/v1/sessions/" + url.PathEscape(key) + "/explain"
}

func setAirlockConfigForTest(sm *SessionManager, airlockCfg *config.Airlock) {
	sm.UpdateConfig(
		&config.SessionProfiling{
			MaxSessions:            100,
			SessionTTLMinutes:      30,
			CleanupIntervalSeconds: 300,
			DomainBurst:            10,
			WindowMinutes:          5,
		},
		nil,
		airlockCfg,
	)
}

func TestSessionAPI_HandleExplain_HardTierWithEvidence(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	airlockCfg := &config.Airlock{
		Enabled: true,
		Triggers: config.AirlockTriggers{
			OnElevated: config.AirlockTierNone,
			OnHigh:     config.AirlockTierSoft,
			OnCritical: config.AirlockTierHard,
		},
		Timers: config.AirlockTimers{
			SoftMinutes: 5,
			HardMinutes: 10,
		},
	}
	setAirlockConfigForTest(sm, airlockCfg)

	sess := sm.GetOrCreate(explainIdentityKey)
	sess.RecordEvent(SessionEvent{
		Kind: actionBlock, Target: "evil.example.com", Detail: explainEvidence,
		Severity: "critical", Score: 0.95,
	})
	_, _, _ = sess.Airlock().SetTierWithProvenance(config.AirlockTierHard, airlockTriggerOnCritical, airlockSourceTriggers)

	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodGet, explainURLFor(explainIdentityKey), nil)
	req.Header.Set("Authorization", explainAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleExplain(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var exp SessionExplanation
	if err := json.Unmarshal(w.Body.Bytes(), &exp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if exp.Tier != config.AirlockTierHard {
		t.Errorf("Tier: got %q, want %q", exp.Tier, config.AirlockTierHard)
	}
	if exp.Trigger != "on_critical" {
		t.Errorf("Trigger: got %q, want on_critical", exp.Trigger)
	}
	if exp.TriggerSource != airlockSourceTriggers {
		t.Errorf("TriggerSource: got %q, want %q", exp.TriggerSource, airlockSourceTriggers)
	}
	if exp.EvidenceKind != actionBlock {
		t.Errorf("EvidenceKind: got %q, want block", exp.EvidenceKind)
	}
	if exp.EvidenceDetail != explainEvidence {
		t.Errorf("EvidenceDetail: got %q, want %q", exp.EvidenceDetail, explainEvidence)
	}
	if exp.NextDeescalationTier != config.AirlockTierSoft {
		t.Errorf("NextDeescalationTier: got %q, want %q", exp.NextDeescalationTier, config.AirlockTierSoft)
	}
	if exp.NextDeescalationAt.IsZero() {
		t.Error("NextDeescalationAt should be non-zero when HardMinutes>0 and EnteredAt is set")
	}
	// ElapsedInTier is measured from EnteredAt; allow any non-negative value.
	if exp.ElapsedInTier < 0 {
		t.Errorf("ElapsedInTier: got %v, want >= 0", exp.ElapsedInTier)
	}
}

func TestSessionAPI_HandleExplain_NoneTierReturns200(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	// Not quarantined.
	sm.GetOrCreate(explainIdentityKey)

	handler := newTestSessionAPIHandler(t, sm)
	req := httptest.NewRequest(http.MethodGet, explainURLFor(explainIdentityKey), nil)
	req.Header.Set("Authorization", explainAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleExplain(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 for non-quarantined; body=%s", w.Code, w.Body.String())
	}

	var exp SessionExplanation
	if err := json.Unmarshal(w.Body.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	if exp.Tier != config.AirlockTierNone {
		t.Errorf("Tier: got %q, want %q", exp.Tier, config.AirlockTierNone)
	}
	if exp.Reason == "" {
		t.Error("Reason should be non-empty for none tier")
	}
}

func TestSessionAPI_HandleExplain_NotFound(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodGet, explainURLFor("ghost|1.2.3.4"), nil)
	req.Header.Set("Authorization", explainAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleExplain(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", w.Code)
	}
}

func TestSessionAPI_HandleExplain_Unauthorized(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodGet, explainURLFor(explainIdentityKey), nil)
	w := httptest.NewRecorder()
	handler.HandleExplain(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", w.Code)
	}
}

func TestSessionAPI_HandleExplain_MethodNotAllowed(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodPost, explainURLFor(explainIdentityKey), nil)
	req.Header.Set("Authorization", explainAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleExplain(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status: got %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodGet {
		t.Errorf("Allow: got %q, want %q", allow, http.MethodGet)
	}
}

func TestSessionAPI_HandleExplain_BadPath(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions//explain", nil)
	req.Header.Set("Authorization", explainAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleExplain(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
}

func TestSessionAPI_HandleExplain_RateLimited(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	sm.GetOrCreate(explainIdentityKey)
	handler := newTestSessionAPIHandler(t, sm)

	for i := 0; i < sessionAPIRateLimitMax; i++ {
		req := httptest.NewRequest(http.MethodGet, explainURLFor(explainIdentityKey), nil)
		req.Header.Set("Authorization", explainAuthHeader)
		w := httptest.NewRecorder()
		handler.HandleExplain(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: got %d", i, w.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, explainURLFor(explainIdentityKey), nil)
	req.Header.Set("Authorization", explainAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleExplain(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status: got %d, want 429", w.Code)
	}
}

func TestSessionAPI_HandleExplain_ManualTrigger(t *testing.T) {
	// Operator-forced transitions (no trigger config match) surface as explainManual.
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	// No airlock config set at all.

	sess := sm.GetOrCreate(explainIdentityKey)
	_, _, _ = sess.Airlock().ForceSetTier(config.AirlockTierDrain)

	handler := newTestSessionAPIHandler(t, sm)
	req := httptest.NewRequest(http.MethodGet, explainURLFor(explainIdentityKey), nil)
	req.Header.Set("Authorization", explainAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleExplain(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	var exp SessionExplanation
	if err := json.Unmarshal(w.Body.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	if exp.Tier != config.AirlockTierDrain {
		t.Errorf("Tier: got %q, want drain", exp.Tier)
	}
	if exp.Trigger != explainManual {
		t.Errorf("Trigger: got %q, want manual (no airlock config)", exp.Trigger)
	}
	if exp.TriggerSource != airlockSourceAdminAPI {
		t.Errorf("TriggerSource: got %q, want %q", exp.TriggerSource, airlockSourceAdminAPI)
	}
	// Manual path has no config, so NextDeescalationAt should be zero.
	if !exp.NextDeescalationAt.IsZero() {
		t.Errorf("NextDeescalationAt: got %v, want zero", exp.NextDeescalationAt)
	}
}

func TestSessionAPI_HandleExplain_PrefersNonTransitionEvidence(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sess := sm.GetOrCreate(explainIdentityKey)
	sess.RecordEvent(SessionEvent{Kind: actionBlock, Target: "evil.example.com", Detail: explainEvidence, Severity: "critical", Score: 0.95})
	sess.RecordEvent(SessionEvent{Kind: "airlock_enter", Target: config.AirlockTierHard, Detail: "none->hard", Severity: "warn"})
	_, _, _ = sess.Airlock().SetTierWithProvenance(config.AirlockTierHard, airlockTriggerOnCritical, airlockSourceTriggers)

	handler := newTestSessionAPIHandler(t, sm)
	req := httptest.NewRequest(http.MethodGet, explainURLFor(explainIdentityKey), nil)
	req.Header.Set("Authorization", explainAuthHeader)
	w := httptest.NewRecorder()
	handler.HandleExplain(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	var exp SessionExplanation
	if err := json.Unmarshal(w.Body.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	if exp.EvidenceKind != actionBlock {
		t.Errorf("EvidenceKind: got %q, want block", exp.EvidenceKind)
	}
	if exp.EvidenceDetail != explainEvidence {
		t.Errorf("EvidenceDetail: got %q, want %q", exp.EvidenceDetail, explainEvidence)
	}
}

func TestDeescalationDuration_Behavior(t *testing.T) {
	timers := &config.AirlockTimers{
		SoftMinutes:         5,
		HardMinutes:         10,
		DrainMinutes:        15,
		DrainTimeoutSeconds: 30,
	}

	tests := []struct {
		name string
		tier string
		want time.Duration
	}{
		{"soft", config.AirlockTierSoft, 5 * time.Minute},
		{"hard", config.AirlockTierHard, 10 * time.Minute},
		{"drain capped at seconds", config.AirlockTierDrain, 30 * time.Second},
		{"unknown", "fuzz", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deescalationDuration(tt.tier, timers)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeescalationDuration_ZeroTimerDisables(t *testing.T) {
	tests := []struct {
		name   string
		tier   string
		timers *config.AirlockTimers
	}{
		{"nil timers", config.AirlockTierSoft, nil},
		{"soft zero", config.AirlockTierSoft, &config.AirlockTimers{SoftMinutes: 0}},
		{"hard zero", config.AirlockTierHard, &config.AirlockTimers{HardMinutes: 0}},
		{"drain zero both", config.AirlockTierDrain, &config.AirlockTimers{DrainMinutes: 0, DrainTimeoutSeconds: 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deescalationDuration(tt.tier, tt.timers)
			if got != 0 {
				t.Errorf("got %v, want 0", got)
			}
		})
	}
}

func TestNextDeescalationTier(t *testing.T) {
	tests := []struct {
		current string
		want    string
	}{
		{config.AirlockTierSoft, config.AirlockTierNone},
		{config.AirlockTierHard, config.AirlockTierSoft},
		{config.AirlockTierDrain, config.AirlockTierHard},
		{config.AirlockTierNone, ""},
		{"unknown", ""},
	}
	for _, tt := range tests {
		t.Run(tt.current, func(t *testing.T) {
			got := nextDeescalationTier(tt.current)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAirlockCfgFromManager_NilManager(t *testing.T) {
	h := newTestSessionAPIHandler(t, nil)
	if cfg := h.airlockCfgFromManager(nil); cfg != nil {
		t.Errorf("nil manager should yield nil config, got %+v", cfg)
	}
}

func TestBuildExplanation_NoneTierAttachesEvidence(t *testing.T) {
	// Even normal sessions get evidence from their event log so explain is
	// useful outside of incident response.
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()

	sess := sm.GetOrCreate(explainIdentityKey)
	sess.RecordEvent(SessionEvent{
		Kind: "anomaly", Target: "new.example.com", Detail: "domain burst",
		Severity: "warn", Score: 2.0,
	})
	// Do NOT escalate — stay at none.

	snap, found := sm.AdminSnapshotByKey(explainIdentityKey)
	if !found {
		t.Fatal("expected session")
	}
	exp := buildExplanation(snap, nil)

	if exp.Tier != config.AirlockTierNone {
		t.Errorf("Tier: got %q, want none", exp.Tier)
	}
	if exp.Reason != tierNotQuarantinedReason {
		t.Errorf("Reason: got %q, want %q", exp.Reason, tierNotQuarantinedReason)
	}
	if exp.EvidenceKind != "anomaly" {
		t.Errorf("EvidenceKind: got %q, want anomaly", exp.EvidenceKind)
	}
}

// TestBuildExplanation_NoneTierOmitsTriggerMetadata guards against the
// self-contradictory output where a normal-tier session returned a
// "not quarantined" reason alongside stale trigger metadata from a prior
// airlock entry. The explain contract is: tier=none means no active
// quarantine cause, so Trigger and TriggerSource must be empty.
func TestBuildExplanation_NoneTierOmitsTriggerMetadata(t *testing.T) {
	snap := sessionAdminSnapshot{
		SessionSnapshot: SessionSnapshot{
			Key:         "agent|10.0.0.1",
			AirlockTier: config.AirlockTierNone,
		},
		AirlockTrigger:       "stale_trigger_from_prior_entry",
		AirlockTriggerSource: "prior_source",
	}
	exp := buildExplanation(snap, nil)
	if exp.Reason != tierNotQuarantinedReason {
		t.Errorf("Reason: got %q, want %q", exp.Reason, tierNotQuarantinedReason)
	}
	if exp.Trigger != "" {
		t.Errorf("Trigger: got %q, want empty for tier=none", exp.Trigger)
	}
	if exp.TriggerSource != "" {
		t.Errorf("TriggerSource: got %q, want empty for tier=none", exp.TriggerSource)
	}
}
