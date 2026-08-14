// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

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
	return config.ValidateContainmentMetricsListen(cfg.MetricsListen, proxyPort)
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
	detail := fmt.Sprintf("containment managed config drift: metrics listener %q disabled: %v; set metrics_listen to a numeric loopback address on a non-proxy port and do not delete the key", configured, drift)
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
			"outcome":           "metrics_disabled",
		})
	}
}
