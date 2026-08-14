// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ContainmentManagedEnvKey and ContainmentManagedEnvValue identify a Pipelock
// process started by the managed containment service. They are deliberately
// separate from generic configuration validation: standalone Pipelock may
// expose metrics on a LAN address, while containment must not.
const (
	ContainmentManagedEnvKey   = "PIPELOCK_CONTAINMENT_MANAGED"
	ContainmentManagedEnvValue = "1"
)

// ValidateContainmentMetricsListen enforces the metrics listener invariant
// used only by the containment lifecycle: a numeric loopback address on a
// non-proxy TCP port. It does not participate in Config.Validate, because
// ordinary Pipelock deployments may intentionally expose metrics on a LAN.
func ValidateContainmentMetricsListen(listen string, proxyPort int) error {
	return ValidateContainmentMetricsExposure(listen, proxyPort, nil, time.Now())
}

// ContainmentConfig holds settings that are enforced only by the containment
// lifecycle. It is kept separate from ordinary proxy configuration because
// the containment runtime owns the kernel boundary around the agent.
type ContainmentConfig struct {
	MetricsExposure *ContainmentMetricsExposure `yaml:"metrics_exposure"`
}

// ContainmentMetricsExposure records the deliberate exception required to
// serve full Prometheus metrics beyond loopback from a contained runtime.
// Every field is required so an operator can identify who accepted the
// exposure, why, when it ends, and which scrapers may use it.
type ContainmentMetricsExposure struct {
	AllowFullMetrics   bool     `yaml:"allow_full_metrics"`
	AllowedSourceCIDRs []string `yaml:"allowed_source_cidrs"`
	Owner              string   `yaml:"owner"`
	Reason             string   `yaml:"reason"`
	ExpiresAt          string   `yaml:"expires_at"`
}

// ValidateContainmentMetricsExposure enforces the containment metrics
// listener invariant. Loopback needs no exception. Any other numeric address
// requires a complete, current metrics exposure policy.
func ValidateContainmentMetricsExposure(listen string, proxyPort int, policy *ContainmentMetricsExposure, now time.Time) error {
	if strings.TrimSpace(listen) == "" {
		return fmt.Errorf("metrics_listen is unsafe for containment: set a numeric loopback address on a dedicated port and do not delete the key")
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("metrics_listen %q is unsafe for containment: %w", listen, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("metrics_listen %q is unsafe for containment: use a numeric address, not a hostname", listen)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("metrics_listen %q is unsafe for containment: wildcard binds are not allowed", listen)
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 || int(parsedPort) == proxyPort {
		return fmt.Errorf("metrics_listen %q is unsafe for containment: use a port other than the agent-accessible proxy port %d", listen, proxyPort)
	}
	if ip.IsLoopback() {
		if policy != nil {
			return fmt.Errorf("containment.metrics_exposure requires a non-loopback metrics_listen address")
		}
		return nil
	}
	if err := validateContainmentMetricsExposurePolicy(policy, now); err != nil {
		return err
	}
	return nil
}

func validateContainmentMetricsExposurePolicy(policy *ContainmentMetricsExposure, now time.Time) error {
	if policy == nil {
		return fmt.Errorf("non-loopback metrics_listen requires containment.metrics_exposure")
	}
	if !policy.AllowFullMetrics {
		return fmt.Errorf("containment.metrics_exposure.allow_full_metrics must be true")
	}
	if strings.TrimSpace(policy.Owner) == "" {
		return fmt.Errorf("containment.metrics_exposure.owner is required")
	}
	if strings.TrimSpace(policy.Reason) == "" {
		return fmt.Errorf("containment.metrics_exposure.reason is required")
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(policy.ExpiresAt))
	if err != nil {
		return fmt.Errorf("containment.metrics_exposure.expires_at must use RFC3339: %w", err)
	}
	if !expiresAt.After(now) {
		return fmt.Errorf("containment.metrics_exposure expired at %s", expiresAt.UTC().Format(time.RFC3339))
	}
	if len(policy.AllowedSourceCIDRs) == 0 {
		return fmt.Errorf("containment.metrics_exposure.allowed_source_cidrs must name at least one source")
	}
	for i, source := range policy.AllowedSourceCIDRs {
		ip, cidr, err := net.ParseCIDR(strings.TrimSpace(source))
		if err != nil {
			return fmt.Errorf("containment.metrics_exposure.allowed_source_cidrs[%d] %q is invalid: %w", i, source, err)
		}
		if !ip.Equal(cidr.IP) {
			return fmt.Errorf("containment.metrics_exposure.allowed_source_cidrs[%d] %q must use a network address", i, source)
		}
		ones, bits := cidr.Mask.Size()
		if ones == 0 && (bits == 32 || bits == 128) {
			return fmt.Errorf("containment.metrics_exposure.allowed_source_cidrs[%d] %q must not allow every source", i, source)
		}
	}
	return nil
}

// ContainmentMetricsExposureAllowsSource reports whether an already-validated
// policy permits the connecting address. Invalid policies deny by returning
// false so callers never turn a parse failure into an open metrics endpoint.
func ContainmentMetricsExposureAllowsSource(policy *ContainmentMetricsExposure, source net.IP) bool {
	if policy == nil || source == nil {
		return false
	}
	for _, rawCIDR := range policy.AllowedSourceCIDRs {
		_, cidr, err := net.ParseCIDR(strings.TrimSpace(rawCIDR))
		if err == nil && cidr.Contains(source) {
			return true
		}
	}
	return false
}
