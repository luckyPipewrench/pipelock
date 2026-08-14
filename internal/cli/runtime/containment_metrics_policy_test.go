// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestContainmentMetricsRequestAllowedFailureDirections(t *testing.T) {
	now := time.Date(2026, time.August, 14, 12, 0, 0, 0, time.UTC)
	validPolicy := func() *config.ContainmentMetricsExposure {
		return &config.ContainmentMetricsExposure{
			AllowFullMetrics:   true,
			AllowedSourceCIDRs: []string{"192.0.2.42/32"},
			Owner:              "observability",
			Reason:             "Prometheus scrape",
			ExpiresAt:          "2026-08-15T12:00:00Z",
		}
	}
	newConfig := func(policy *config.ContainmentMetricsExposure) *config.Config {
		cfg := config.Defaults()
		cfg.FetchProxy.Listen = "127.0.0.1:8888"
		cfg.MetricsListen = "192.0.2.20:9091"
		cfg.Containment.MetricsExposure = policy
		return cfg
	}

	tests := []struct {
		name       string
		cfg        *config.Config
		remoteAddr string
		want       bool
		wantReason string
	}{
		{name: "allowed source succeeds", cfg: newConfig(validPolicy()), remoteAddr: "192.0.2.42:49152", want: true},
		{name: "source mismatch denies", cfg: newConfig(validPolicy()), remoteAddr: "192.0.2.43:49152", wantReason: "source_cidr_mismatch"},
		{name: "absent policy denies", cfg: newConfig(nil), remoteAddr: "192.0.2.42:49152", wantReason: "malformed_live_config"},
		{name: "malformed policy denies", cfg: newConfig(&config.ContainmentMetricsExposure{AllowFullMetrics: true, AllowedSourceCIDRs: []string{"not-a-cidr"}, Owner: "observability", Reason: "Prometheus scrape", ExpiresAt: "2026-08-15T12:00:00Z"}), remoteAddr: "192.0.2.42:49152", wantReason: "malformed_live_config"},
		{name: "expired policy denies", cfg: newConfig(&config.ContainmentMetricsExposure{AllowFullMetrics: true, AllowedSourceCIDRs: []string{"192.0.2.42/32"}, Owner: "observability", Reason: "Prometheus scrape", ExpiresAt: "2026-08-14T12:00:00Z"}), remoteAddr: "192.0.2.42:49152", wantReason: "expired_policy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := containmentMetricsRequestDecision(tt.cfg, tt.remoteAddr, now)
			if got != tt.want || reason != tt.wantReason {
				t.Fatalf("containmentMetricsRequestDecision = %v, %q; want %v, %q", got, reason, tt.want, tt.wantReason)
			}
		})
	}
}

func TestContainmentMetricsHandlersEnforceSourcePolicyAndStatsLoopback(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	cfg := config.Defaults()
	cfg.FetchProxy.Listen = "127.0.0.1:8888"
	cfg.MetricsListen = "192.0.2.20:9091"
	cfg.Containment.MetricsExposure = &config.ContainmentMetricsExposure{
		AllowFullMetrics:   true,
		AllowedSourceCIDRs: []string{"192.0.2.42/32"},
		Owner:              "observability",
		Reason:             "Prometheus scrape",
		ExpiresAt:          now,
	}
	var metricsHits atomic.Int64
	var denials []string
	report := func(endpoint, _, reason string) {
		denials = append(denials, endpoint+":"+reason)
	}
	metricsHandler := containmentMetricsHandler(func() *config.Config { return cfg }, func() bool { return false }, report, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		metricsHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tt := range []struct {
		name       string
		remoteAddr string
		wantStatus int
	}{
		{name: "allowed scraper", remoteAddr: "192.0.2.42:49152", wantStatus: http.StatusNoContent},
		{name: "other source", remoteAddr: "192.0.2.43:49152", wantStatus: http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
			req.RemoteAddr = tt.remoteAddr
			rec := httptest.NewRecorder()
			metricsHandler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("metrics status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
	if got := metricsHits.Load(); got != 1 {
		t.Fatalf("metrics handler calls = %d, want 1", got)
	}

	statsHandler := containmentLoopbackHandler(report, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tt := range []struct {
		name       string
		remoteAddr string
		wantStatus int
	}{
		{name: "remote metrics source cannot read stats", remoteAddr: "192.0.2.42:49152", wantStatus: http.StatusForbidden},
		{name: "loopback can read stats", remoteAddr: "127.0.0.1:49152", wantStatus: http.StatusNoContent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stats", nil)
			req.RemoteAddr = tt.remoteAddr
			rec := httptest.NewRecorder()
			statsHandler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("stats status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
	if got, want := denials, []string{"/metrics:source_cidr_mismatch", "/stats:non_loopback_stats"}; !slices.Equal(got, want) {
		t.Fatalf("denial reports = %v, want %v", got, want)
	}
}

func TestServer_ContainmentMetricsExposureServesOnlyAllowedScraper(t *testing.T) {
	t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
	host := containmentNonLoopbackIPv4(t)
	metricsAddr := reserveTCPAddress(t, host)
	fetchListen := testport.ListenAddrs(t, 1)[0]
	configBody := fmt.Sprintf(`mode: balanced
metrics_listen: %q
containment:
  metrics_exposure:
    allow_full_metrics: true
    allowed_source_cidrs:
      - %q
    owner: observability
    reason: Prometheus scrape
    expires_at: %q
`, metricsAddr, host+"/32", time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	stderr := &syncBuffer{}
	s, err := NewServer(ServerOpts{
		ConfigFile:                        writeServerTestConfig(t, configBody),
		Listen:                            fetchListen,
		ListenChanged:                     true,
		Stdout:                            stderr,
		Stderr:                            stderr,
		allowEphemeralListenersForTesting: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.cleanup)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(host)}}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:       nil,
			DialContext: dialer.DialContext,
		},
		Timeout: time.Second,
	}
	get := func(path string) int {
		t.Helper()
		status := 0
		testwait.For(t, 3*time.Second, func() bool {
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+metricsAddr+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				return false
			}
			defer func() { _ = response.Body.Close() }()
			status = response.StatusCode
			return true
		}, "configured metrics listener to accept a scrape")
		return status
	}

	metricsStatus := get("/metrics")
	if metricsStatus != http.StatusOK {
		t.Fatalf("allowed scraper status = %d, want %d", metricsStatus, http.StatusOK)
	}
	statsStatus := get("/stats")
	if statsStatus != http.StatusForbidden {
		t.Fatalf("remote stats status = %d, want %d", statsStatus, http.StatusForbidden)
	}

	expired := s.proxy.CurrentConfig().Clone()
	expired.Containment.MetricsExposure.ExpiresAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339)
	if err := s.Reload(expired); err == nil {
		t.Fatal("Reload accepted an expired containment metrics exposure")
	}
	deniedStatus := get("/metrics")
	if deniedStatus != http.StatusForbidden {
		t.Fatalf("expired-policy scrape status = %d, want %d", deniedStatus, http.StatusForbidden)
	}
	if !s.containmentMetricsDenied.Load() {
		t.Fatal("rejected containment reload left metrics access enabled")
	}

	if err := s.Reload(s.proxy.CurrentConfig().Clone()); err != nil {
		t.Fatalf("Reload valid containment metrics policy: %v", err)
	}
	restoredStatus := get("/metrics")
	if restoredStatus != http.StatusOK {
		t.Fatalf("restored-policy scrape status = %d, want %d", restoredStatus, http.StatusOK)
	}
	if s.containmentMetricsDenied.Load() {
		t.Fatal("valid containment reload did not restore metrics access")
	}

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for containment metrics server shutdown")
	}
}

func containmentNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				return ip.String()
			}
		}
	}
	t.Skip("no non-loopback IPv4 address is available for containment metrics listener test")
	return ""
}

func reserveTCPAddress(t *testing.T, host string) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}
