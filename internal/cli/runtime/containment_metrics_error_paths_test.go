// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestValidateContainmentMetricsConfigRefusals covers the branches that decide
// whether the containment metrics policy can be evaluated at all.
//
// These fail closed on purpose. If the proxy port cannot be determined there is no
// way to know whether the metrics listener collides with the surface the agent can
// reach, and guessing in that state is how a guard becomes decoration.
func TestValidateContainmentMetricsConfigRefusals(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *config.Config
		wantErr    bool
		wantDetail string
	}{
		{
			name:       "nil config",
			cfg:        nil,
			wantErr:    true,
			wantDetail: "no active config",
		},
		{
			name: "unparseable proxy listen",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.ApplyDefaults()
				c.FetchProxy.Listen = "not-a-host-port"
				c.MetricsListen = "127.0.0.1:9091"
				return c
			}(),
			wantErr:    true,
			wantDetail: "parse fetch_proxy.listen",
		},
		{
			name: "non-numeric proxy port",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.ApplyDefaults()
				c.FetchProxy.Listen = "127.0.0.1:proxy"
				c.MetricsListen = "127.0.0.1:9091"
				return c
			}(),
			wantErr:    true,
			wantDetail: "parse fetch_proxy.listen port",
		},
		{
			// Split out from the parse failure above: a port that parses but
			// cannot be listened on is a different fault and says so, rather
			// than being reported as an unparsable one.
			name: "proxy port outside the valid range",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.ApplyDefaults()
				c.FetchProxy.Listen = "127.0.0.1:70000"
				c.MetricsListen = "127.0.0.1:9091"
				return c
			}(),
			wantErr:    true,
			wantDetail: "out of range",
		},
		{
			name: "metrics on the proxy port",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.ApplyDefaults()
				c.FetchProxy.Listen = "127.0.0.1:8888"
				c.MetricsListen = "127.0.0.1:8888"
				return c
			}(),
			wantErr:    true,
			wantDetail: "agent-accessible proxy port",
		},
		{
			name: "compliant loopback metrics",
			cfg: func() *config.Config {
				c := config.Defaults()
				c.ApplyDefaults()
				c.FetchProxy.Listen = "127.0.0.1:8888"
				c.MetricsListen = "127.0.0.1:9091"
				return c
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateContainmentMetricsConfig(tt.cfg)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("validateContainmentMetricsConfig = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("validateContainmentMetricsConfig = nil, want a refusal")
			}
			if !strings.Contains(err.Error(), tt.wantDetail) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantDetail)
			}
		})
	}
}

// TestContainmentManagedRuntimeKeysOnTheExactMarker pins that the guard activates
// only under the marker the installer writes.
//
// Generic Pipelock accepts a LAN metrics address by design, so a loose check here
// would change behavior for deployments that never asked for containment.
func TestContainmentManagedRuntimeKeysOnTheExactMarker(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"the installer marker", config.ContainmentManagedEnvValue, true},
		{"unset", "", false},
		{"a different value", "0", false},
		{"a truthy-looking value that is not the marker", "true", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(config.ContainmentManagedEnvKey, tt.value)
			if got := containmentManagedRuntime(); got != tt.want {
				t.Errorf("containmentManagedRuntime() = %v with %s=%q, want %v",
					got, config.ContainmentManagedEnvKey, tt.value, tt.want)
			}
		})
	}
}
