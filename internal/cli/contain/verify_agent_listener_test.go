// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import "testing"

func TestAgentListenerGuardEarlierAcceptDestination(t *testing.T) {
	guard := `meta skuid != { 0, 1001 } ip daddr 127.0.0.1 tcp dport 8889 counter log prefix "pipelock_agent_listener_blocked " drop`
	for _, tc := range []struct {
		name, rule string
		want       bool
	}{
		{"different port", `meta skuid 966 ip daddr 127.0.0.1 tcp dport 9077 accept`, true},
		{"different address", `meta skuid 966 ip daddr 127.0.0.2 tcp dport 8889 accept`, true},
		{"different subnet", `meta skuid 966 ip daddr 127.0.0.128/25 tcp dport 8889 accept`, true},
		{"containing subnet", `meta skuid 966 ip daddr 127.0.0.0/24 tcp dport 8889 accept`, false},
		{"listener port", `meta skuid 966 ip daddr 127.0.0.1 tcp dport 8889 accept`, false},
		{"unbounded port", `meta skuid 966 ip daddr 127.0.0.1 accept`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := chainLinesHaveAgentListenerGuard([]string{tc.rule, guard}, "127.0.0.1:8889", 1001); got != tc.want {
				t.Fatalf("guard with earlier %q = %t, want %t", tc.rule, got, tc.want)
			}
		})
	}
}
