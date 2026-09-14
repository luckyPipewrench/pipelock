// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// runtimeStateSequenceHarness sends requests over a real TCP forward-proxy
// connection. The upstream counter is an independent delivery witness: an
// allowed request must increment it, while a refused request must not.
type runtimeStateSequenceHarness struct {
	proxy    *Proxy
	proxyURL *url.URL
	upstream *httptest.Server
	hits     atomic.Int32
	stop     func()
}

func newRuntimeStateSequenceHarness(t *testing.T) *runtimeStateSequenceHarness {
	t.Helper()

	h := &runtimeStateSequenceHarness{}
	h.upstream = newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h.hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(h.upstream.Close)

	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.CrossRequestDetection.Enabled = true
		cfg.CrossRequestDetection.Action = config.ActionBlock
		cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
		cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 65536
		cfg.CrossRequestDetection.FragmentReassembly.WindowMinutes = 5
		cfg.CrossRequestDetection.EntropyBudget.Enabled = false
	})
	h.stop = sync.OnceFunc(cleanup)
	t.Cleanup(h.stop)

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	h.proxy = p
	h.proxyURL = proxyURL
	return h
}

// forward opens a new client connection for every request. Besides keeping
// tests isolated, that makes sequence tests exercise reconnect admission,
// rather than a handler call in one synthetic request context.
func (h *runtimeStateSequenceHarness) forward(t *testing.T, path string) int {
	t.Helper()

	status, err := h.forwardStatus(t.Context(), path)
	if err != nil {
		t.Fatalf("forward %q: %v", path, err)
	}
	return status
}

func (h *runtimeStateSequenceHarness) forwardStatus(ctx context.Context, path string) (int, error) {
	transport := &http.Transport{Proxy: http.ProxyURL(h.proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.upstream.URL+path, nil)
	if err != nil {
		return 0, fmt.Errorf("new request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func (h *runtimeStateSequenceHarness) requireAllowed(t *testing.T, path string) {
	t.Helper()
	before := h.hits.Load()
	if got := h.forward(t, path); got != http.StatusOK {
		t.Fatalf("%q status = %d, want allowed 200", path, got)
	}
	if got := h.hits.Load(); got != before+1 {
		t.Fatalf("%q upstream hits = %d, want %d after allowed request", path, got, before+1)
	}
}

func (h *runtimeStateSequenceHarness) requireDenied(t *testing.T, path string) {
	t.Helper()
	before := h.hits.Load()
	if got := h.forward(t, path); got != http.StatusForbidden {
		t.Fatalf("%q status = %d, want refused 403", path, got)
	}
	if got := h.hits.Load(); got != before {
		t.Fatalf("%q reached upstream: hits = %d, want %d after refusal", path, got, before)
	}
}

func (h *runtimeStateSequenceHarness) reload(t *testing.T, update func(*config.Config)) {
	t.Helper()
	cfg := h.proxy.cfgPtr.Load().Clone()
	update(cfg)
	if ok := h.proxy.Reload(cfg, scanner.MustNew(cfg)); !ok {
		t.Fatal("reload failed")
	}
}

func TestForwardProxyRuntimeStateSequences(t *testing.T) {
	half1, half2 := pathSecretHalves()
	first := "/upload/" + half1
	second := "/upload/" + half2

	t.Run("fresh state with benign history permits useful traffic then refuses split secret", func(t *testing.T) {
		h := newRuntimeStateSequenceHarness(t)
		h.requireAllowed(t, "/health-check")
		h.requireAllowed(t, first)
		h.requireDenied(t, second)
	})

	t.Run("unrelated reload retains enforcement state", func(t *testing.T) {
		h := newRuntimeStateSequenceHarness(t)
		h.requireAllowed(t, first)
		h.reload(t, func(cfg *config.Config) { cfg.KillSwitch.Message = "unrelated reload" })
		h.requireAllowed(t, "/still-useful")
		h.requireDenied(t, second)
	})

	t.Run("relevant reload applies tightened action to retained detector history", func(t *testing.T) {
		h := newRuntimeStateSequenceHarness(t)
		h.reload(t, func(cfg *config.Config) { cfg.CrossRequestDetection.Action = config.ActionWarn })
		h.requireAllowed(t, first)
		h.requireAllowed(t, second)
		h.reload(t, func(cfg *config.Config) { cfg.CrossRequestDetection.Action = config.ActionBlock })
		h.requireDenied(t, "/after-policy-tightening")
	})

	t.Run("reconnect retains state for the same caller", func(t *testing.T) {
		h := newRuntimeStateSequenceHarness(t)
		// forward creates a fresh TCP client connection for each half.
		h.requireAllowed(t, first)
		h.requireDenied(t, second)
	})

	t.Run("restart starts a new state epoch and can enforce a new sequence", func(t *testing.T) {
		firstEpoch := newRuntimeStateSequenceHarness(t)
		firstEpoch.requireAllowed(t, first)
		firstEpoch.stop()

		// Reconstruct the runtime after shutdown. This exercises in-process
		// lifecycle recreation, not persistence across OS processes.
		secondEpoch := newRuntimeStateSequenceHarness(t)
		secondEpoch.requireAllowed(t, second)
		secondEpoch.requireAllowed(t, first)
		secondEpoch.requireDenied(t, second)
	})

	t.Run("concurrent completing callers are all refused without delivery", func(t *testing.T) {
		h := newRuntimeStateSequenceHarness(t)
		h.requireAllowed(t, first)
		before := h.hits.Load()

		const callers = 8
		var wg sync.WaitGroup
		errs := make(chan error, callers)
		for range callers {
			wg.Go(func() {
				got, err := h.forwardStatus(t.Context(), second)
				if err != nil {
					errs <- err
				} else if got != http.StatusForbidden {
					errs <- fmt.Errorf("completing caller status = %d, want 403", got)
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		if got := h.hits.Load(); got != before {
			t.Fatalf("concurrent refused callers reached upstream: hits = %d, want %d", got, before)
		}
	})
}
