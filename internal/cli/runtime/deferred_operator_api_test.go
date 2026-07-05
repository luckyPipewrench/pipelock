// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func deferredOpTestManager(t *testing.T) *deferred.Manager {
	t.Helper()
	m := deferred.NewManager(deferred.Config{
		Enabled:              true,
		Timeout:              time.Hour,
		MaxPending:           8,
		MaxPendingPerSession: 8,
		MaxPendingBytes:      1 << 20,
		MaxCascadeDepth:      4,
	})
	if err := m.Hold(deferred.HeldAction{
		DeferID:   "0193defer00000000000000000001",
		ActionID:  "0193defer00000000000000000001",
		Surface:   deferred.SurfaceMCPStdio,
		Method:    "tools/call",
		Target:    "shell.exec",
		Reason:    "tool policy: defer",
		Authority: deferred.AuthoritySnapshot{SessionID: "sess-1"},
		Resolve:   func(deferred.Resolution) {},
	}); err != nil {
		t.Fatalf("seed hold: %v", err)
	}
	return m
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestStartDeferredOperatorAPI_NoListenerWhenUnset proves the surface is not
// exposed (no listener started) when api_listen is unset, defer is disabled, or
// no live manager exists - and that the returned stop is a safe no-op.
func TestStartDeferredOperatorAPI_NoListenerWhenUnset(t *testing.T) {
	logger := audit.NewNop()
	cases := []struct {
		name string
		cfg  *config.Config
		mgr  *deferred.Manager
	}{
		{"api_listen unset", &config.Config{}, deferredOpTestManager(t)},
		{"nil manager", func() *config.Config {
			c := &config.Config{}
			c.KillSwitch.APIListen = "127.0.0.1:0"
			c.KillSwitch.APIToken = "t"
			return c
		}(), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stop, err := startDeferredOperatorAPI(context.Background(), tc.cfg, tc.mgr, logger, io.Discard)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if stop == nil {
				t.Fatal("stop must be non-nil")
			}
			stop() // must not panic
		})
	}
}

// TestStartDeferredOperatorAPI_ServesDeferredRoutes proves the listener exposes
// the deferred list/approve/deny surface, wired to the live manager, and gates
// it behind the admin bearer token.
func TestStartDeferredOperatorAPI_ServesDeferredRoutes(t *testing.T) {
	const token = "op-token"
	addr := freeAddr(t)
	cfg := &config.Config{}
	cfg.KillSwitch.APIListen = addr
	cfg.KillSwitch.APIToken = token
	mgr := deferredOpTestManager(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop, err := startDeferredOperatorAPI(ctx, cfg, mgr, audit.NewNop(), io.Discard)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer stop()

	client := &http.Client{Timeout: 5 * time.Second}
	base := "http://" + addr
	get := func(t *testing.T, url string, auth bool) *http.Response {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, reqErr := client.Do(req)
		if reqErr != nil {
			t.Fatalf("GET %s: %v", url, reqErr)
		}
		return resp
	}

	// Wait until the listener is serving.
	testwait.For(t, 3*time.Second, func() bool {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/deferred", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, reqErr := client.Do(req)
		if reqErr != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "deferred operator API on %s", addr)

	// GET /api/v1/deferred returns the held action.
	resp := get(t, base+"/api/v1/deferred", true)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status=%d body=%s", resp.StatusCode, body)
	}
	var list struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if list.Count != 1 {
		t.Fatalf("count=%d, want 1", list.Count)
	}

	// Unauthenticated list is rejected.
	resp = get(t, base+"/api/v1/deferred", false)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth list status=%d, want 401", resp.StatusCode)
	}

	// deny resolves the held action via the operator surface.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/api/v1/deferred/0193defer00000000000000000001/deny", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deny status=%d, want 200", resp.StatusCode)
	}
	if got := mgr.Snapshot(); len(got) != 0 {
		t.Fatalf("hold still held after deny: %d", len(got))
	}
}

func TestStartDeferredOperatorAPI_UsesEnvAPIToken(t *testing.T) {
	token := "op-env-" + "val"
	t.Setenv(killswitch.EnvAPIToken, token)
	addr := freeAddr(t)
	cfg := &config.Config{}
	cfg.KillSwitch.APIListen = addr
	mgr := deferredOpTestManager(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop, err := startDeferredOperatorAPI(ctx, cfg, mgr, audit.NewNop(), io.Discard)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer stop()

	client := &http.Client{Timeout: 5 * time.Second}
	base := "http://" + addr
	testwait.For(t, 3*time.Second, func() bool {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/deferred", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, reqErr := client.Do(req)
		if reqErr != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "deferred operator API with env token on %s", addr)
}

func TestStartDeferredOperatorAPI_MissingTokenFailsFast(t *testing.T) {
	t.Setenv(killswitch.EnvAPIToken, "")
	cfg := &config.Config{}
	cfg.KillSwitch.APIListen = freeAddr(t)

	stop, err := startDeferredOperatorAPI(context.Background(), cfg, deferredOpTestManager(t), audit.NewNop(), io.Discard)
	if err == nil {
		stop()
		t.Fatal("expected missing token error, got nil")
	}
	if stop == nil {
		t.Fatal("stop must be non-nil on error")
	}
	stop()
}

// TestStartDeferredOperatorAPI_BindErrorIsFatal proves a bind conflict on
// api_listen returns an error (fail-fast) rather than silently continuing
// without an operator surface.
func TestStartDeferredOperatorAPI_BindErrorIsFatal(t *testing.T) {
	// Occupy a port, then point api_listen at it.
	occupied, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy: %v", err)
	}
	defer func() { _ = occupied.Close() }()

	cfg := &config.Config{}
	cfg.KillSwitch.APIListen = occupied.Addr().String()
	cfg.KillSwitch.APIToken = "t"

	stop, err := startDeferredOperatorAPI(context.Background(), cfg, deferredOpTestManager(t), audit.NewNop(), io.Discard)
	if err == nil {
		stop()
		t.Fatal("expected bind error on occupied port, got nil")
	}
	if stop == nil {
		t.Fatal("stop must be non-nil even on error")
	}
	stop() // no-op, must not panic
}
