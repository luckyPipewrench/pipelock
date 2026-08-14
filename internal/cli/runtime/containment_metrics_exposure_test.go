// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// TestServer_ContainmentDeletedMetricsKeyDoesNotExposeMetricsOnTheProxyPort
// covers the state an operator actually reaches by following the remediation
// message: they delete metrics_listen instead of setting it.
//
// Deleting the key is not the same as setting an unsafe address. An unsafe
// address leaves the value non-empty, and the proxy only publishes /metrics and
// /stats on its own listener when the value is EMPTY. So the deleted-key case
// is the one where disabling the dedicated listener silently hands the endpoints
// to the agent-reachable proxy port, while startup still reports metrics
// disabled. That combination is worse than an unguarded host, because the
// operator has been told they are covered.
func TestServer_ContainmentDeletedMetricsKeyDoesNotExposeMetricsOnTheProxyPort(t *testing.T) {
	t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
	fetchListen := testport.ListenAddrs(t, 1)[0]
	// The empty address is the deleted key: config.Load leaves it "".
	s, _ := newContainmentMetricsTestServerWithFetch(t, "", "", fetchListen)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()

	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 500 * time.Millisecond}
	get := func(path string) (int, bool) {
		request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+fetchListen+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, requestErr := client.Do(request)
		if requestErr != nil {
			return 0, false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode, true
	}

	testwait.For(t, 3*time.Second, func() bool {
		select {
		case startErr := <-done:
			t.Fatalf("Start returned before serving the proxy: %v", startErr)
		default:
		}
		code, ok := get("/health")
		return ok && code == http.StatusOK
	}, "contained proxy to start with the metrics key deleted")

	for _, path := range []string{"/metrics", "/stats"} {
		code, ok := get(path)
		if !ok {
			t.Fatalf("%s: request failed against a proxy that is serving /health", path)
		}
		if code != http.StatusNotFound {
			t.Errorf("%s on the agent-reachable proxy port returned %d, want 404: containment reported metrics disabled, "+
				"so the contained agent must not be able to read them here", path, code)
		}
	}

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case startErr := <-done:
		if startErr != nil {
			t.Fatalf("Start: %v", startErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for contained proxy shutdown")
	}
}
