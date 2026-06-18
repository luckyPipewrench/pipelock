// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type blockingContainmentVerifier struct {
	entered chan struct{}
	release chan struct{}
}

func (v *blockingContainmentVerifier) Verify(ctx context.Context) error {
	close(v.entered)
	select {
	case <-v.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newKillTestServer(t *testing.T) (*Server, string, *Gate) {
	t.Helper()
	g, err := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good", MaxSessions: 5}}, TokenTTL: time.Minute})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	srv, err := NewServer(ServerConfig{
		Gate:          g,
		MaxConcurrent: 4,
		IPRate:        RateConfig{RefillPerSec: 1000, Burst: 1000},
		CodeRate:      RateConfig{RefillPerSec: 1000, Burst: 1000},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return srv, ts.URL, g
}

func TestServer_KillSwitch_RefusesAndReportsKilled(t *testing.T) {
	t.Parallel()
	srv, url, g := newKillTestServer(t)

	if srv.Killed() {
		t.Fatal("a new server must not be killed")
	}
	srv.Kill()
	if !srv.Killed() {
		t.Fatal("Kill did not engage the switch")
	}

	// New sessions are refused while killed.
	resp := postJSON(t, url+RouteSession, createReq{Code: "good"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("session while killed = %d, want 503", resp.StatusCode)
	}

	// Messages are refused while killed (the kill check fires before any session
	// lookup, so even a freshly minted valid token is turned away).
	tok, _, err := g.Redeem("good", "sid-x")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	mr := postJSON(t, url+RouteMessage, messageReq{Token: tok, Message: "hi"})
	_ = mr.Body.Close()
	if mr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("message while killed = %d, want 503", mr.StatusCode)
	}

	// Health reports the switch and is not ok.
	hr := getRaw(t, url+RouteHealth)
	var health struct {
		OK     bool `json:"ok"`
		Killed bool `json:"killed"`
	}
	if err := json.NewDecoder(hr.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	_ = hr.Body.Close()
	if health.OK || !health.Killed {
		t.Errorf("health ok=%v killed=%v, want ok=false killed=true", health.OK, health.Killed)
	}

	// Resume reopens the door.
	srv.Resume()
	if srv.Killed() {
		t.Fatal("Resume did not clear the switch")
	}
}

func TestServer_KillSwitch_TerminatesActiveSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real session")
	}
	t.Parallel()
	srv, url, _ := newKillTestServer(t)

	resp := postJSON(t, url+RouteSession, createReq{Code: "good"})
	var cr createResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	_ = resp.Body.Close()
	if cr.SessionID == "" {
		t.Fatalf("empty session id: %+v", cr)
	}
	if srv.lookup(cr.SessionID) == nil {
		t.Fatal("session was not registered")
	}

	// Kill must TERMINATE the active session, not merely block new ones.
	srv.Kill()
	if srv.lookup(cr.SessionID) != nil {
		t.Error("Kill did not terminate the active session")
	}
}

func TestServer_KillSwitch_RejectsSessionStartedDuringKill(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real session")
	}
	t.Parallel()

	g, err := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good", MaxSessions: 1}}, TokenTTL: time.Minute})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	verifier := &blockingContainmentVerifier{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	srv, err := NewServer(ServerConfig{
		Gate:               g,
		MaxConcurrent:      4,
		IPRate:             RateConfig{RefillPerSec: 1000, Burst: 1000},
		CodeRate:           RateConfig{RefillPerSec: 1000, Burst: 1000},
		RequireContainment: true,
		Containment:        verifier,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })

	statusC := make(chan int, 1)
	errC := make(chan error, 1)
	go func() {
		body, _ := json.Marshal(createReq{Code: "good"})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+RouteSession, bytes.NewReader(body))
		if err != nil {
			errC <- err
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			errC <- err
			return
		}
		_ = resp.Body.Close()
		statusC <- resp.StatusCode
	}()

	select {
	case <-verifier.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not reach containment verifier")
	}
	srv.Kill()
	close(verifier.release)

	select {
	case err := <-errC:
		t.Fatalf("session request failed: %v", err)
	case status := <-statusC:
		if status != http.StatusServiceUnavailable {
			t.Fatalf("session status during kill = %d, want 503", status)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("session request did not finish after kill release")
	}

	if srv.conc.InUse() != 0 {
		t.Fatalf("concurrency slot leaked after killed start: %d", srv.conc.InUse())
	}
	if _, _, err := g.Redeem("good", "after-kill-race"); err != nil {
		t.Fatalf("invite budget was not refunded after killed start: %v", err)
	}
}
