// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy/baseline"
)

const baselineAPIAgent = "agent-baseline"

func setupBaselineAPITestManager(t *testing.T) (*SessionManager, string, func()) {
	t.Helper()
	sm, cleanup := setupSessionAPITestManager(t)
	profileDir := t.TempDir()
	bbCfg := &config.BehavioralBaseline{
		Enabled:          true,
		LearningWindow:   3,
		DeviationAction:  config.ActionBlock,
		ProfileDir:       profileDir,
		SensitivitySigma: 2.0,
		SeasonalityMode:  config.SeasonalityModeNone,
	}
	if err := sm.EnableBaseline(bbCfg); err != nil {
		t.Fatalf("EnableBaseline: %v", err)
	}
	return sm, profileDir, cleanup
}

func seedRatifyProfile(t *testing.T, mgr *baseline.Manager, agent string) {
	t.Helper()
	for range 3 {
		mgr.RecordSession(agent, baseline.SessionMetrics{
			ToolCalls:   4,
			UniqueTools: 2,
			Domains:     2,
			BytesTotal:  1000,
			DurationSec: 60,
			Requests:    5,
		})
	}
	if got := mgr.GetState(agent); got != baseline.StateRatify {
		t.Fatalf("state after seed = %q, want %q", got, baseline.StateRatify)
	}
}

func baselineAdminRequest(method, path string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), method, path, nil)
	req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
	return req
}

func TestSessionAPI_BaselineRoundTrip_ListShowRatifyForget(t *testing.T) {
	sm, profileDir, cleanup := setupBaselineAPITestManager(t)
	defer cleanup()
	mgr := sm.BaselineManager()
	seedRatifyProfile(t, mgr, baselineAPIAgent)

	handler := newTestSessionAPIHandler(t, sm)

	listReq := baselineAdminRequest(http.MethodGet, "/api/v1/baseline")
	listW := httptest.NewRecorder()
	handler.HandleBaselineList(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", listW.Code, listW.Body.String())
	}
	var listResp BaselineListResponse
	if err := json.NewDecoder(listW.Body).Decode(&listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if listResp.Count != 1 || listResp.PendingRatify != 1 || listResp.Profiles[0].AgentKey != baselineAPIAgent {
		t.Fatalf("unexpected list response: %+v", listResp)
	}
	if listResp.Profiles[0].ObservedSessionCount != 3 {
		t.Fatalf("list observed sessions = %d, want 3", listResp.Profiles[0].ObservedSessionCount)
	}

	showReq := baselineAdminRequest(http.MethodGet, "/api/v1/baseline/"+url.PathEscape(baselineAPIAgent))
	showW := httptest.NewRecorder()
	handler.HandleBaselineProfile(showW, showReq)
	if showW.Code != http.StatusOK {
		t.Fatalf("show status = %d body=%s", showW.Code, showW.Body.String())
	}
	var profile BaselineProfile
	if err := json.NewDecoder(showW.Body).Decode(&profile); err != nil {
		t.Fatalf("decode show: %v", err)
	}
	if profile.Metrics.ToolCallsPerSession.Mean != 4 || profile.SessionCount != 3 {
		t.Fatalf("profile is not approval-grade enough: %+v", profile)
	}

	deviant := baseline.SessionMetrics{ToolCalls: 100, UniqueTools: 2, Domains: 2, BytesTotal: 1000, DurationSec: 60, Requests: 5}
	if devs := mgr.Check(baselineAPIAgent, deviant); len(devs) != 0 {
		t.Fatalf("unratified profile enforced before ratify: %+v", devs)
	}

	ratifyReq := baselineAdminRequest(http.MethodPost, "/api/v1/baseline/"+url.PathEscape(baselineAPIAgent)+"/ratify")
	ratifyW := httptest.NewRecorder()
	handler.HandleBaselineProfile(ratifyW, ratifyReq)
	if ratifyW.Code != http.StatusOK {
		t.Fatalf("ratify status = %d body=%s", ratifyW.Code, ratifyW.Body.String())
	}
	var ratifyResp BaselineRatifyResult
	if err := json.NewDecoder(ratifyW.Body).Decode(&ratifyResp); err != nil {
		t.Fatalf("decode ratify: %v", err)
	}
	if ratifyResp.PreviousState != baseline.StateRatify || ratifyResp.NewState != baseline.StateLocked || !ratifyResp.Ratified {
		t.Fatalf("unexpected ratify response: %+v", ratifyResp)
	}
	if devs := mgr.Check(baselineAPIAgent, deviant); len(devs) == 0 {
		t.Fatal("locked profile did not enforce after ratify")
	}

	profilePath := filepath.Clean(filepath.Join(profileDir, baselineAPIAgent+".json"))
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("read persisted profile: %v", err)
	}
	if !strings.Contains(string(raw), `"state": "locked"`) {
		t.Fatalf("persisted profile was not locked: %s", raw)
	}

	forgetReq := baselineAdminRequest(http.MethodPost, "/api/v1/baseline/"+url.PathEscape(baselineAPIAgent)+"/forget")
	forgetW := httptest.NewRecorder()
	handler.HandleBaselineProfile(forgetW, forgetReq)
	if forgetW.Code != http.StatusOK {
		t.Fatalf("forget status = %d body=%s", forgetW.Code, forgetW.Body.String())
	}
	var forgetResp BaselineForgetResult
	if err := json.NewDecoder(forgetW.Body).Decode(&forgetResp); err != nil {
		t.Fatalf("decode forget: %v", err)
	}
	if forgetResp.PreviousState != baseline.StateLocked || forgetResp.NewState != baseline.StateObserve || !forgetResp.Forgotten {
		t.Fatalf("unexpected forget response: %+v", forgetResp)
	}
	if devs := mgr.Check(baselineAPIAgent, deviant); len(devs) != 0 {
		t.Fatalf("forgotten profile still enforced: %+v", devs)
	}
	if _, err := os.Stat(profilePath); !os.IsNotExist(err) {
		t.Fatalf("profile file should be deleted after forget, err=%v", err)
	}
}

func TestSessionAPI_BaselineRatifyRejectsUnknownAndWrongState(t *testing.T) {
	sm, _, cleanup := setupBaselineAPITestManager(t)
	defer cleanup()
	mgr := sm.BaselineManager()
	seedRatifyProfile(t, mgr, baselineAPIAgent)
	if err := mgr.Ratify(baselineAPIAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	handler := newTestSessionAPIHandler(t, sm)

	unknownReq := baselineAdminRequest(http.MethodPost, "/api/v1/baseline/missing-agent/ratify")
	unknownW := httptest.NewRecorder()
	handler.HandleBaselineProfile(unknownW, unknownReq)
	if unknownW.Code != http.StatusNotFound {
		t.Fatalf("unknown ratify status = %d body=%s", unknownW.Code, unknownW.Body.String())
	}

	wrongStateReq := baselineAdminRequest(http.MethodPost, "/api/v1/baseline/"+url.PathEscape(baselineAPIAgent)+"/ratify")
	wrongStateW := httptest.NewRecorder()
	handler.HandleBaselineProfile(wrongStateW, wrongStateReq)
	if wrongStateW.Code != http.StatusConflict {
		t.Fatalf("wrong-state ratify status = %d body=%s", wrongStateW.Code, wrongStateW.Body.String())
	}
}

func TestSessionAPI_BaselineForgetFailsClosedWhenProfileRemovalFails(t *testing.T) {
	sm, profileDir, cleanup := setupBaselineAPITestManager(t)
	defer cleanup()
	mgr := sm.BaselineManager()
	seedRatifyProfile(t, mgr, baselineAPIAgent)
	if err := mgr.Ratify(baselineAPIAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	profilePath := filepath.Clean(filepath.Join(profileDir, baselineAPIAgent+".json"))
	if err := os.Remove(profilePath); err != nil {
		t.Fatalf("remove seeded profile: %v", err)
	}
	if err := os.Mkdir(profilePath, 0o750); err != nil {
		t.Fatalf("mkdir blocker dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(profilePath, "blocker"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}

	handler := newTestSessionAPIHandler(t, sm)
	forgetReq := baselineAdminRequest(http.MethodPost, "/api/v1/baseline/"+url.PathEscape(baselineAPIAgent)+"/forget")
	forgetW := httptest.NewRecorder()
	handler.HandleBaselineProfile(forgetW, forgetReq)
	if forgetW.Code != http.StatusInternalServerError {
		t.Fatalf("forget status = %d, want 500 body=%s", forgetW.Code, forgetW.Body.String())
	}
	if state := mgr.GetState(baselineAPIAgent); state != baseline.StateLocked {
		t.Fatalf("profile must stay locked after failed API forget, got %q", state)
	}
	if devs := mgr.Check(baselineAPIAgent, baseline.SessionMetrics{ToolCalls: 9999}); len(devs) == 0 {
		t.Fatal("enforcement must remain active after failed API forget")
	}
}

func TestSessionAPI_BaselineAuthAndDisabledGuards(t *testing.T) {
	sm, cleanup := setupSessionAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	noAuthReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/baseline", nil)
	noAuthW := httptest.NewRecorder()
	handler.HandleBaselineList(noAuthW, noAuthReq)
	if noAuthW.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth status = %d", noAuthW.Code)
	}

	disabledReq := baselineAdminRequest(http.MethodGet, "/api/v1/baseline")
	disabledW := httptest.NewRecorder()
	handler.HandleBaselineList(disabledW, disabledReq)
	if disabledW.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled status = %d body=%s", disabledW.Code, disabledW.Body.String())
	}
}

func TestProxy_MainMuxDoesNotExposeBaselineAdminAPI(t *testing.T) {
	sm, _, cleanup := setupBaselineAPITestManager(t)
	defer cleanup()
	handler := newTestSessionAPIHandler(t, sm)

	cfg := config.Defaults()
	cfg.KillSwitch.APIListen = ""
	p := &Proxy{
		sessionAPI: handler,
		metrics:    metrics.New(),
	}
	p.cfgPtr.Store(cfg)

	req := baselineAdminRequest(http.MethodGet, "/api/v1/baseline")
	w := httptest.NewRecorder()
	p.buildMux().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("baseline admin API exposed on main proxy mux: status=%d body=%s", w.Code, w.Body.String())
	}
}
