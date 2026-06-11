// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/proxy/baseline"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const baselineCLIAgent = "agent-cli"

func makeBaselineProfile() proxy.BaselineProfile {
	now := testFixedTime()
	return proxy.BaselineProfile{
		AgentKey:             baselineCLIAgent,
		State:                baseline.StateRatify,
		LearnedAt:            now,
		SessionCount:         3,
		ObservedSessionCount: 4,
		TrimmedSessionCount:  1,
		Ratified:             false,
		Metrics: baseline.ProfileMetrics{
			ToolCallsPerSession:   baseline.Range{Min: 3, Max: 5, Mean: 4, StdDev: 1},
			UniqueToolsPerSession: baseline.Range{Min: 2, Max: 2, Mean: 2, StdDev: 0},
			DomainsPerSession:     baseline.Range{Min: 1, Max: 2, Mean: 1.5, StdDev: 0.5},
			BytesPerSession:       baseline.Range{Min: 1000, Max: 1200, Mean: 1100, StdDev: 100},
			SessionDurationSec:    baseline.Range{Min: 50, Max: 70, Mean: 60, StdDev: 10},
			RequestsPerSession:    baseline.Range{Min: 4, Max: 6, Mean: 5, StdDev: 1},
		},
	}
}

func TestBaselineCmd_RegistersSubcommands(t *testing.T) {
	cmd := BaselineCmd()
	want := []string{"list", "show", "ratify", "forget"}
	for _, name := range want {
		if _, _, err := cmd.Find([]string{name}); err != nil {
			t.Errorf("subcommand %q not registered: %v", name, err)
		}
	}
	if !strings.Contains(cmd.Long, "admin API") {
		t.Errorf("long help should mention admin API: %q", cmd.Long)
	}
}

func TestClient_BaselineMethods(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		paths = append(paths, r.Method+" "+r.URL.EscapedPath())
		switch r.URL.EscapedPath() {
		case "/api/v1/baseline":
			writeJSONResponse(w, http.StatusOK, proxy.BaselineListResponse{Profiles: []proxy.BaselineProfile{makeBaselineProfile()}, Count: 1, PendingRatify: 1})
		case "/api/v1/baseline/" + url.PathEscape(baselineCLIAgent):
			writeJSONResponse(w, http.StatusOK, makeBaselineProfile())
		case "/api/v1/baseline/" + url.PathEscape(baselineCLIAgent) + "/ratify":
			writeJSONResponse(w, http.StatusOK, proxy.BaselineRatifyResult{AgentKey: baselineCLIAgent, PreviousState: baseline.StateRatify, NewState: baseline.StateLocked, Ratified: true})
		case "/api/v1/baseline/" + url.PathEscape(baselineCLIAgent) + "/forget":
			writeJSONResponse(w, http.StatusOK, proxy.BaselineForgetResult{AgentKey: baselineCLIAgent, PreviousState: baseline.StateLocked, NewState: baseline.StateObserve, Forgotten: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := newClient(endpoint{URL: srv.URL, Token: testToken})
	if _, err := c.BaselineList(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BaselineShow(context.Background(), baselineCLIAgent); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BaselineRatify(context.Background(), baselineCLIAgent); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BaselineForget(context.Background(), baselineCLIAgent); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"GET /api/v1/baseline",
		"GET /api/v1/baseline/" + url.PathEscape(baselineCLIAgent),
		"POST /api/v1/baseline/" + url.PathEscape(baselineCLIAgent) + "/ratify",
		"POST /api/v1/baseline/" + url.PathEscape(baselineCLIAgent) + "/forget",
	}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("paths:\ngot:\n%s\nwant:\n%s", strings.Join(paths, "\n"), strings.Join(want, "\n"))
	}
}

func TestBaselineRenderers(t *testing.T) {
	profile := makeBaselineProfile()
	listOut := &strings.Builder{}
	if err := renderBaselineList(listOut, proxy.BaselineListResponse{Profiles: []proxy.BaselineProfile{profile}, Count: 1, PendingRatify: 1}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{baselineCLIAgent, "ratify", "TRIMMED", "pending_ratify=1"} {
		if !strings.Contains(listOut.String(), want) {
			t.Errorf("list output missing %q: %s", want, listOut.String())
		}
	}

	showOut := &strings.Builder{}
	if err := renderBaselineProfile(showOut, profile); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"retained_sessions: 3", "observed_sessions: 4", "trimmed_sessions:  1", "tool_calls_per_session"} {
		if !strings.Contains(showOut.String(), want) {
			t.Errorf("show output missing %q: %s", want, showOut.String())
		}
	}
}

func TestBaselineCLI_Integration_ListShowRatifyForget(t *testing.T) {
	sessProfiling := &config.SessionProfiling{
		MaxSessions:            50,
		SessionTTLMinutes:      30,
		CleanupIntervalSeconds: 300,
		DomainBurst:            10,
		WindowMinutes:          5,
	}
	sm := proxy.NewSessionManager(sessProfiling, nil, metrics.New(), proxy.SessionManagerOptions{
		Logger: audit.NewNop(),
	})
	defer sm.Close()
	if err := sm.EnableBaseline(&config.BehavioralBaseline{
		Enabled:          true,
		LearningWindow:   3,
		DeviationAction:  config.ActionBlock,
		ProfileDir:       t.TempDir(),
		SensitivitySigma: 2.0,
		SeasonalityMode:  config.SeasonalityModeNone,
	}); err != nil {
		t.Fatalf("EnableBaseline: %v", err)
	}
	mgr := sm.BaselineManager()
	for range 3 {
		mgr.RecordSession(baselineCLIAgent, baseline.SessionMetrics{
			ToolCalls: 4, UniqueTools: 2, Domains: 1,
			BytesTotal: 1000, DurationSec: 60, Requests: 5,
		})
	}

	var smPtr atomic.Pointer[proxy.SessionManager]
	smPtr.Store(sm)
	var etPtr atomic.Pointer[scanner.EntropyTracker]
	var fbPtr atomic.Pointer[scanner.FragmentBuffer]
	handler := proxy.NewSessionAPIHandler(proxy.SessionAPIOptions{
		SessionMgrPtr: &smPtr,
		EntropyPtr:    &etPtr,
		FragmentPtr:   &fbPtr,
		Logger:        audit.NewNop(),
		APIToken:      integToken,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/baseline", handler.HandleBaselineList)
	mux.HandleFunc("/api/v1/baseline/", handler.HandleBaselineProfile)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	flags := &rootFlags{apiURL: srv.URL, apiToken: integToken}
	overrideClientFactory(t, flags)

	out, err := runCommand(baselineListCmd(&rootFlags{}))
	if err != nil {
		t.Fatalf("baseline list: %v; out=%s", err, out)
	}
	if !strings.Contains(out, baselineCLIAgent) || !strings.Contains(out, "ratify") {
		t.Fatalf("baseline list output: %s", out)
	}

	out, err = runCommand(baselineShowCmd(&rootFlags{}), baselineCLIAgent)
	if err != nil {
		t.Fatalf("baseline show: %v; out=%s", err, out)
	}
	if !strings.Contains(out, "tool_calls_per_session") || !strings.Contains(out, "observed_sessions") {
		t.Fatalf("baseline show output: %s", out)
	}

	deviant := baseline.SessionMetrics{ToolCalls: 100, UniqueTools: 2, Domains: 1, BytesTotal: 1000, DurationSec: 60, Requests: 5}
	if devs := mgr.Check(baselineCLIAgent, deviant); len(devs) != 0 {
		t.Fatalf("baseline enforced before CLI ratify: %+v", devs)
	}

	out, err = runCommand(baselineRatifyCmd(&rootFlags{}), baselineCLIAgent)
	if err != nil {
		t.Fatalf("baseline ratify: %v; out=%s", err, out)
	}
	if !strings.Contains(out, "ratified baseline") {
		t.Fatalf("baseline ratify output: %s", out)
	}
	if devs := mgr.Check(baselineCLIAgent, deviant); len(devs) == 0 {
		t.Fatal("baseline did not enforce after CLI ratify")
	}

	out, err = runCommand(baselineForgetCmd(&rootFlags{}), baselineCLIAgent)
	if err != nil {
		t.Fatalf("baseline forget: %v; out=%s", err, out)
	}
	if !strings.Contains(out, "forgot baseline") {
		t.Fatalf("baseline forget output: %s", out)
	}
	if devs := mgr.Check(baselineCLIAgent, deviant); len(devs) != 0 {
		t.Fatalf("baseline still enforced after CLI forget: %+v", devs)
	}
}
