// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
)

const containmentMetricsDriftEvent = "containment_managed_config_drift"

func containmentManagedRuntime() bool {
	return os.Getenv(config.ContainmentManagedEnvKey) == config.ContainmentManagedEnvValue
}

func validateContainmentMetricsConfig(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("containment runtime has no active config")
	}
	_, port, err := net.SplitHostPort(cfg.FetchProxy.Listen)
	if err != nil {
		return fmt.Errorf("parse fetch_proxy.listen %q for containment metrics policy: %w", cfg.FetchProxy.Listen, err)
	}
	proxyPort, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("parse fetch_proxy.listen port %q for containment metrics policy: %w", port, err)
	}
	if proxyPort < 1 || proxyPort > 65535 {
		return fmt.Errorf("fetch_proxy.listen port %d is out of range for containment metrics policy", proxyPort)
	}
	return config.ValidateContainmentMetricsExposure(cfg.MetricsListen, proxyPort, cfg.Containment.MetricsExposure, time.Now())
}

// containmentMetricsHandler enforces the source policy at request time. The
// policy is read from the live config for every scrape so expiry and an
// accepted hot reload take effect without rebinding the metrics listener.
func containmentMetricsHandler(currentConfig func() *config.Config, denyAll func() bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if denyAll() || !containmentMetricsRequestAllowed(currentConfig(), r.RemoteAddr, time.Now()) {
			http.Error(w, "metrics access denied", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// containmentLoopbackHandler keeps the more detailed /stats endpoint local
// even when an operator has approved remote Prometheus metrics collection.
func containmentLoopbackHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !containmentRequestSourceIP(r.RemoteAddr).IsLoopback() {
			http.Error(w, "stats access denied", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func containmentMetricsRequestAllowed(cfg *config.Config, remoteAddr string, now time.Time) bool {
	if cfg == nil {
		return false
	}
	_, port, err := net.SplitHostPort(cfg.FetchProxy.Listen)
	if err != nil {
		return false
	}
	proxyPort, err := strconv.Atoi(port)
	if err != nil || proxyPort < 1 || proxyPort > 65535 {
		return false
	}
	if err := config.ValidateContainmentMetricsExposure(cfg.MetricsListen, proxyPort, cfg.Containment.MetricsExposure, now); err != nil {
		return false
	}
	source := containmentRequestSourceIP(remoteAddr)
	if source == nil {
		return false
	}
	host, _, err := net.SplitHostPort(cfg.MetricsListen)
	if err != nil {
		return false
	}
	metricsIP := net.ParseIP(host)
	if metricsIP == nil {
		return false
	}
	if metricsIP.IsLoopback() {
		return source.IsLoopback()
	}
	return config.ContainmentMetricsExposureAllowsSource(cfg.Containment.MetricsExposure, source)
}

func containmentRequestSourceIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// reportContainmentMetricsDrift makes the degraded state visible to both the
// local audit log and configured event sinks. The explicit critical event is
// separate from the generic audit error because telemetry must not downgrade a
// containment metrics exposure to the normal warning severity for an error.
func (s *Server) reportContainmentMetricsDrift(cfg *config.Config, phase string, drift error) {
	configured := ""
	if cfg != nil {
		configured = cfg.MetricsListen
	}
	state := "disabled"
	outcome := "metrics_disabled"
	if phase == "reload" {
		state = "access denied"
		outcome = "metrics_access_denied"
	}
	detail := fmt.Sprintf("containment managed config drift: metrics listener %q %s: %v; use a numeric loopback address on a non-proxy port, or provide a current containment.metrics_exposure policy for a specific non-loopback address", configured, state, drift)
	_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: CRITICAL: %s\n", detail)
	if s.logger != nil {
		s.logger.LogError(audit.NewResourceLogContext("CONTAINMENT_MANAGED_CONFIG", s.opts.ConfigFile), errors.New(detail))
	}
	if s.emitter != nil {
		s.emitter.EmitWithSeverity(context.Background(), emit.SeverityCritical, containmentMetricsDriftEvent, map[string]any{
			"field":             "metrics_listen",
			"configured_listen": configured,
			"phase":             phase,
			"reason":            drift.Error(),
			"outcome":           outcome,
		})
	}
}
