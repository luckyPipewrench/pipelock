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
	MetricsExposure  *ContainmentMetricsExposure  `yaml:"metrics_exposure"`
	LoopbackServices []ContainmentLoopbackService `yaml:"loopback_services"`
}

// ContainmentLoopbackService declares a second loopback destination the
// contained agent may reach beyond the mediated proxy port. This is the
// outbound sibling of ContainmentMetricsExposure: it is the sole declared
// exception format for an extra agent-reachable loopback service, carrying
// the same owner/reason/expiry lifecycle so an operator carve-out is visible
// to config validation, contain install, and contain verify instead of being
// a hand-edited nft rule that reload tolerates and verify condemns.
type ContainmentLoopbackService struct {
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	Owner     string `yaml:"owner"`
	Reason    string `yaml:"reason"`
	ExpiresAt string `yaml:"expires_at"`
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

// validateContainmentExceptionLifecycle enforces the shared owner/reason/expiry
// contract every declared containment exception carries: ContainmentMetricsExposure
// and ContainmentLoopbackService both call this instead of duplicating the
// RFC3339 parse and expiry comparison.
func validateContainmentExceptionLifecycle(field, owner, reason, expiresAt string, now time.Time) error {
	if strings.TrimSpace(owner) == "" {
		return fmt.Errorf("%s.owner is required", field)
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%s.reason is required", field)
	}
	expiresAtParsed, err := time.Parse(time.RFC3339, strings.TrimSpace(expiresAt))
	if err != nil {
		return fmt.Errorf("%s.expires_at must use RFC3339: %w", field, err)
	}
	if !expiresAtParsed.After(now) {
		return fmt.Errorf("%s expired at %s", field, expiresAtParsed.UTC().Format(time.RFC3339))
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
	if err := validateContainmentExceptionLifecycle("containment.metrics_exposure", policy.Owner, policy.Reason, policy.ExpiresAt, now); err != nil {
		return err
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

// ValidateContainmentLoopbackServices enforces the declared-exception
// lifecycle for every containment.loopback_services entry: a loopback-literal
// host, a TCP port distinct from the proxy port and from every other
// declared entry, and the same required owner/reason/expires_at contract as
// containment.metrics_exposure. An empty or nil list is valid: the contained
// agent's only implicit loopback destination remains the proxy port.
func ValidateContainmentLoopbackServices(services []ContainmentLoopbackService, proxyPort int, now time.Time) error {
	seen := make(map[string]struct{}, len(services))
	for i, svc := range services {
		field := fmt.Sprintf("containment.loopback_services[%d]", i)
		host := strings.TrimSpace(svc.Host)
		if host != "127.0.0.1" && host != "::1" {
			return fmt.Errorf("%s.host %q must be a loopback literal (127.0.0.1 or ::1), not a hostname, wildcard, or CIDR", field, svc.Host)
		}
		if svc.Port < 1 || svc.Port > 65535 {
			return fmt.Errorf("%s.port %d must be between 1 and 65535", field, svc.Port)
		}
		if svc.Port == proxyPort {
			return fmt.Errorf("%s.port %d collides with the agent-accessible proxy port; the proxy allow is implicit and does not need a declared exception", field, svc.Port)
		}
		key := host + ":" + strconv.Itoa(svc.Port)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%s duplicates an already-declared loopback service at %s", field, key)
		}
		seen[key] = struct{}{}
		if err := validateContainmentExceptionLifecycle(field, svc.Owner, svc.Reason, svc.ExpiresAt, now); err != nil {
			// Repeat the host:port and owner in the wrapped error so a caller
			// that only sees the flattened message (contain verify's FAIL
			// detail, an operator's terminal) can still tell WHICH declared
			// service is unusable without cross-referencing the index.
			return fmt.Errorf("%s:%d (owner=%s): %w", host, svc.Port, svc.Owner, err)
		}
	}
	return nil
}
