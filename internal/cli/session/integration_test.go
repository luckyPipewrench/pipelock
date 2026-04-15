// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	integSessionKey = "integration-agent|10.0.0.50"
	integToken      = "integration-token"
)

// TestSessionCLI_Integration_ListInspectRelease stands up a full
// admin-API HTTP server wired to a real proxy.SessionManager with a
// seeded hard-tier session, then runs list → inspect → release through
// the CLI commands against the live endpoint. Asserts the end state:
// the session is still in the manager, its tier is none, and the
// release response reflects the transition.
//
// Uses net.ListenConfig{}.Listen(ctx, ...) for noctx compliance and a
// closed-channel handshake instead of time.Sleep for the shutdown path.
func TestSessionCLI_Integration_ListInspectRelease(t *testing.T) {
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

	sess := sm.GetOrCreate(integSessionKey)
	sess.RecordEvent(proxy.SessionEvent{
		Kind:     "block",
		Target:   "evil.example.com",
		Detail:   "dlp block (integration)",
		Severity: "critical",
		Score:    0.95,
	})
	_, _, _ = sess.Airlock().SetTierWithProvenance(config.AirlockTierHard, "on_critical", "airlock_triggers")

	// Wire the admin API handler using the options struct. Pointers are
	// atomic so the handler reads through them the way runtime/run.go does.
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
	mux.HandleFunc("/api/v1/sessions", handler.HandleList)
	mux.HandleFunc("/api/v1/sessions/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		switch {
		case killswitch.IsSessionActionPath(path, "airlock"):
			handler.HandleAirlock(w, r)
		case killswitch.IsSessionActionPath(path, "explain"):
			handler.HandleExplain(w, r)
		case killswitch.IsSessionActionPath(path, "terminate"):
			handler.HandleTerminate(w, r)
		case killswitch.IsSessionKeyPath(path):
			handler.HandleInspect(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		shutdownCtx, cancelShut := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelShut()
		_ = srv.Shutdown(shutdownCtx)
		<-serverDone
	})

	base := "http://" + ln.Addr().String()
	flags := &rootFlags{apiURL: base, apiToken: integToken}
	overrideClientFactory(t, flags)

	// Step 1: list --tier hard should return exactly our seeded session.
	out, err := runCommand(listCmd(&rootFlags{}), "--tier", "hard")
	if err != nil {
		t.Fatalf("list: %v; out=%s", err, out)
	}
	if !strings.Contains(out, integSessionKey) {
		t.Errorf("list output missing key: %s", out)
	}

	// Step 2: inspect shows the full detail including the event.
	out, err = runCommand(inspectCmd(&rootFlags{}), integSessionKey)
	if err != nil {
		t.Fatalf("inspect: %v; out=%s", err, out)
	}
	if !strings.Contains(out, "dlp block (integration)") {
		t.Errorf("inspect output missing event detail: %s", out)
	}

	// Step 3: release to none — wraps HandleAirlock with ForceSetTier.
	out, err = runCommand(releaseCmd(&rootFlags{}), integSessionKey, "--to", "none")
	if err != nil {
		t.Fatalf("release: %v; out=%s", err, out)
	}
	if !strings.Contains(out, "released") {
		t.Errorf("release output: %s", out)
	}

	// Assert end state: the session is still in the manager, but its
	// airlock tier is now none.
	if !sm.SessionExists(integSessionKey) {
		t.Error("session should still exist after release")
	}
	if got := sess.Airlock().Tier(); got != config.AirlockTierNone {
		t.Errorf("tier after release: got %q, want %q", got, config.AirlockTierNone)
	}
}

func TestSessionCLI_Integration_Explain(t *testing.T) {
	sessProfiling := &config.SessionProfiling{
		MaxSessions:            50,
		SessionTTLMinutes:      30,
		CleanupIntervalSeconds: 300,
		DomainBurst:            10,
		WindowMinutes:          5,
	}
	airlockCfg := &config.Airlock{
		Enabled: true,
		Triggers: config.AirlockTriggers{
			OnElevated: config.AirlockTierNone,
			OnHigh:     config.AirlockTierSoft,
			OnCritical: config.AirlockTierHard,
		},
		Timers: config.AirlockTimers{SoftMinutes: 5, HardMinutes: 10},
	}
	sm := proxy.NewSessionManager(sessProfiling, nil, metrics.New(), proxy.SessionManagerOptions{
		AirlockCfg: airlockCfg,
		Logger:     audit.NewNop(),
	})
	defer sm.Close()

	sess := sm.GetOrCreate(integSessionKey)
	sess.RecordEvent(proxy.SessionEvent{
		Kind:     "block",
		Target:   "evil.example.com",
		Detail:   "triggered explain",
		Severity: "critical",
		Score:    0.9,
	})
	_, _, _ = sess.Airlock().SetTierWithProvenance(config.AirlockTierHard, "on_critical", "airlock_triggers")

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
	mux.HandleFunc("/api/v1/sessions/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		switch {
		case killswitch.IsSessionActionPath(path, "explain"):
			handler.HandleExplain(w, r)
		case killswitch.IsSessionKeyPath(path):
			handler.HandleInspect(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	// httptest server for simplicity in this test.
	srv := httptest.NewServer(mux)
	defer srv.Close()

	flags := &rootFlags{apiURL: srv.URL, apiToken: integToken}
	overrideClientFactory(t, flags)

	out, err := runCommand(explainCmd(&rootFlags{}), integSessionKey)
	if err != nil {
		t.Fatalf("explain: %v; out=%s", err, out)
	}
	wantContains := []string{"on_critical", "triggered explain", "next_deescalation"}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("explain output missing %q: %s", w, out)
		}
	}
}
