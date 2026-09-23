// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateContainmentAgentListener(t *testing.T) {
	t.Parallel()
	agents := map[string]AgentProfile{
		"contained": {Listeners: []string{"127.0.0.1:8889"}},
		"other":     {Listeners: []string{"[::1]:8890"}},
	}
	for _, tc := range []struct {
		name     string
		listener string
		wantErr  string
	}{
		{name: "omitted keeps the shared listener", listener: ""},
		{name: "declared ipv4 listener", listener: "127.0.0.1:8889"},
		{name: "declared ipv6 listener", listener: "[::1]:8890"},
		{name: "undeclared listener", listener: "127.0.0.1:8891", wantErr: "not declared under any agents"},
		{name: "shared proxy port", listener: "127.0.0.1:8888", wantErr: "shared proxy port"},
		{name: "non-loopback host", listener: "10.0.0.5:8889", wantErr: "numeric loopback"},
		{name: "hostname is not numeric", listener: "localhost:8889", wantErr: "numeric loopback"},
		{name: "missing port", listener: "127.0.0.1", wantErr: "containment.agent_listener"},
		{name: "port out of range", listener: "127.0.0.1:70000", wantErr: "invalid port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateContainmentAgentListener(tc.listener, agents, 8888)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateContainmentAgentListener(%q) = %v, want nil", tc.listener, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateContainmentAgentListener(%q) = %v, want error containing %q", tc.listener, err, tc.wantErr)
			}
		})
	}
}
