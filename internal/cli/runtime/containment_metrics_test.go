// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func newContainmentMetricsTestServer(t *testing.T, metricsListen, webhookURL string) (*Server, *syncBuffer) {
	return newContainmentMetricsTestServerWithFetch(t, metricsListen, webhookURL, "")
}

func newContainmentMetricsTestServerWithFetch(t *testing.T, metricsListen, webhookURL, fetchListen string) (*Server, *syncBuffer) {
	t.Helper()
	lines := []string{
		"mode: balanced",
		"metrics_listen: " + fmt.Sprintf("%q", metricsListen),
	}
	if webhookURL != "" {
		lines = append(lines,
			"emit:",
			"  webhook:",
			"    url: "+fmt.Sprintf("%q", webhookURL),
			"    min_severity: warn",
			"    timeout_seconds: 1",
			"    queue_size: 16",
		)
	}
	buf := &syncBuffer{}
	s, err := NewServer(ServerOpts{
		ConfigFile:                        writeServerTestConfig(t, strings.Join(lines, "\n")+"\n"),
		Listen:                            fetchListen,
		ListenChanged:                     fetchListen != "",
		Stdout:                            buf,
		Stderr:                            buf,
		allowEphemeralListenersForTesting: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })
	return s, buf
}

func TestServer_StartContainmentUnsafeMetricsSkipsBlockedListener(t *testing.T) {
	t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
	metricsBlocker, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = metricsBlocker.Close() }()
	metricsPort := metricsBlocker.Addr().(*net.TCPAddr).Port
	metricsListen := net.JoinHostPort("0.0.0.0", strconv.Itoa(metricsPort))
	fetchListen := testport.ListenAddrs(t, 1)[0]
	s, _ := newContainmentMetricsTestServerWithFetch(t, metricsListen, "", fetchListen)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()

	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 200 * time.Millisecond}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+fetchListen+"/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	testwait.For(t, 2*time.Second, func() bool {
		select {
		case startErr := <-done:
			t.Fatalf("Start returned before serving the proxy: %v", startErr)
		default:
		}
		resp, requestErr := client.Do(request)
		if requestErr != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "contained proxy to start while unsafe metrics port is blocked")

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case startErr := <-done:
		if startErr != nil {
			t.Fatalf("Start: %v", startErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for contained proxy shutdown")
	}
}

func TestNewServer_ContainmentUnsafeMetricsDisablesListenerAndReportsCritical(t *testing.T) {
	t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
	webhookURL, events := newServerTestWebhook(t)
	s, stderr := newContainmentMetricsTestServer(t, "0.0.0.0:19091", webhookURL)

	if !s.containmentManaged {
		t.Fatal("managed containment environment was not recognized")
	}
	if !s.metricsDisabled {
		t.Fatal("unsafe containment metrics listener remained enabled")
	}
	if got := s.proxy.CurrentConfig().MetricsListen; got == "" {
		t.Fatal("unsafe metrics listener was cleared, which would expose metrics on the proxy port")
	}
	if !stderr.contains("CRITICAL: containment managed config drift") {
		t.Fatalf("critical containment drift was not reported:\n%s", stderr.String())
	}

	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case event := <-events:
			if event.Type != containmentMetricsDriftEvent {
				continue
			}
			if event.Severity != "critical" {
				t.Fatalf("event severity = %q, want critical", event.Severity)
			}
			if event.Fields["outcome"] != "metrics_disabled" {
				t.Fatalf("event outcome = %v, want metrics_disabled", event.Fields["outcome"])
			}
			return
		case <-deadline.C:
			t.Fatal("timed out waiting for critical containment metrics drift event")
		}
	}
}

func TestNewServer_ContainmentLoopbackMetricsRemainEnabled(t *testing.T) {
	t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
	s, stderr := newContainmentMetricsTestServer(t, "127.0.0.1:19091", "")

	if !s.containmentManaged {
		t.Fatal("managed containment environment was not recognized")
	}
	if s.metricsDisabled {
		t.Fatal("compliant loopback metrics listener was disabled")
	}
	if stderr.contains("containment managed config drift") {
		t.Fatalf("compliant loopback metrics listener reported drift:\n%s", stderr.String())
	}
}

func TestServer_ReloadContainmentUnsafeMetricsPreservesLiveListenerAndReportsCritical(t *testing.T) {
	t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
	s, stderr := newContainmentMetricsTestServer(t, "127.0.0.1:19091", "")
	oldCfg := s.proxy.CurrentConfig()
	newCfg := oldCfg.Clone()
	newCfg.MetricsListen = "0.0.0.0:19092"

	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := s.proxy.CurrentConfig().MetricsListen; got != oldCfg.MetricsListen {
		t.Fatalf("live metrics listener = %q, want preserved %q", got, oldCfg.MetricsListen)
	}
	if !stderr.contains("CRITICAL: containment managed config drift") {
		t.Fatalf("unsafe reload did not report critical containment drift:\n%s", stderr.String())
	}
}
