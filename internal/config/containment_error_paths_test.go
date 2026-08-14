// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// TestValidateContainmentMetricsListenRefusals covers every refusal branch.
//
// The error paths are the point of this validator: each one is a distinct way an
// operator edit can leave the containment contract, and each returns different
// remediation text. The empty case matters most, because deleting the key does not
// disable metrics, it moves them onto the agent-accessible proxy port.
func TestValidateContainmentMetricsListenRefusals(t *testing.T) {
	const proxyPort = 8888

	tests := []struct {
		name       string
		listen     string
		wantErr    bool
		wantDetail string
	}{
		{
			name:       "empty is refused and says not to delete the key",
			listen:     "",
			wantErr:    true,
			wantDetail: "do not delete the key",
		},
		{
			name:       "whitespace only is treated as empty",
			listen:     "   ",
			wantErr:    true,
			wantDetail: "do not delete the key",
		},
		{
			name:       "unparseable address",
			listen:     "not-a-host-port",
			wantErr:    true,
			wantDetail: "unsafe for containment",
		},
		{
			name:       "LAN address",
			listen:     "10.20.0.20:9091",
			wantErr:    true,
			wantDetail: "numeric loopback address",
		},
		{
			name:       "wildcard address",
			listen:     "0.0.0.0:9091",
			wantErr:    true,
			wantDetail: "numeric loopback address",
		},
		{
			name:       "hostname rather than a numeric address",
			listen:     "localhost:9091",
			wantErr:    true,
			wantDetail: "numeric loopback address",
		},
		{
			name:       "loopback on the proxy port is refused",
			listen:     "127.0.0.1:8888",
			wantErr:    true,
			wantDetail: "other than the agent-accessible proxy port",
		},
		{
			name:       "port zero",
			listen:     "127.0.0.1:0",
			wantErr:    true,
			wantDetail: "other than the agent-accessible proxy port",
		},
		{
			name:       "non-numeric port",
			listen:     "127.0.0.1:metrics",
			wantErr:    true,
			wantDetail: "unsafe for containment",
		},
		{name: "loopback IPv4 on a dedicated port", listen: "127.0.0.1:9091"},
		{name: "loopback IPv6 on a dedicated port", listen: "[::1]:9091"},
		{name: "an alternate loopback address", listen: "127.0.0.2:9091"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContainmentMetricsListen(tt.listen, proxyPort)
			if tt.wantErr && err == nil {
				t.Fatalf("ValidateContainmentMetricsListen(%q) = nil, want a refusal", tt.listen)
			}
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("ValidateContainmentMetricsListen(%q) = %v, want nil", tt.listen, err)
				}
				return
			}
			if !strings.Contains(err.Error(), tt.wantDetail) {
				t.Errorf("error %q does not carry the remediation %q; an operator reads this to know what to change",
					err.Error(), tt.wantDetail)
			}
		})
	}
}
