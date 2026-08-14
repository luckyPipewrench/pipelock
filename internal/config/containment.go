// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
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
	if strings.TrimSpace(listen) == "" {
		return fmt.Errorf("metrics_listen is unsafe for containment: set a numeric loopback address on a dedicated port and do not delete the key")
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("metrics_listen %q is unsafe for containment: %w", listen, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("metrics_listen %q is unsafe for containment: use a numeric loopback address on a dedicated port", listen)
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 || int(parsedPort) == proxyPort {
		return fmt.Errorf("metrics_listen %q is unsafe for containment: use a port other than the agent-accessible proxy port %d", listen, proxyPort)
	}
	return nil
}
