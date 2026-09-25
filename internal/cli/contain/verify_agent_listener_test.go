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
		// Published-service reply rules as `nft -n -a` prints them live.
		{"reply direction", `meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 8789 ct state 0x2 ct direction 1 accept`, true},
		{"established only", `meta skuid 966 ip daddr 127.0.0.1 ct state 0x2 accept`, true},
		{"established related names", `meta skuid 966 ip daddr 127.0.0.1 ct state established,related accept`, true},
		{"reply direction name", `meta skuid 966 ip daddr 127.0.0.1 ct direction reply accept`, true},
		{"state includes new", `meta skuid 966 ip daddr 127.0.0.1 ct state 0xa accept`, false},
		{"state new name", `meta skuid 966 ip daddr 127.0.0.1 ct state established,new accept`, false},
		{"state set", `meta skuid 966 ip daddr 127.0.0.1 ct state { established, related } accept`, false},
		{"state negated", `meta skuid 966 ip daddr 127.0.0.1 ct state != 0x8 accept`, false},
		{"original direction", `meta skuid 966 ip daddr 127.0.0.1 tcp sport 8789 ct direction 0 accept`, false},
		{"source port only", `meta skuid 966 ip daddr 127.0.0.1 tcp sport 8789 accept`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := chainLinesHaveAgentListenerGuard([]string{tc.rule, guard}, "127.0.0.1:8889", 1001); got != tc.want {
				t.Fatalf("guard with earlier %q = %t, want %t", tc.rule, got, tc.want)
			}
		})
	}
}

// A live managed chain with published-service reply rules and counter-only
// probe rules above the guard, as `nft -n -a list chain` prints it.
func TestAgentListenerGuardLiveChainWithPublishedReplies(t *testing.T) {
	lines := []string{
		`meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 8789 ct state 0x2 ct direction 1 accept # handle 751`,
		`meta skuid 966 oifname "lo" ip daddr 127.0.0.1 tcp sport 9119 ct state 0x2 ct direction 1 accept # handle 750`,
		`meta skuid 966 oifname "lo" counter packets 330384 bytes 81828230 comment "probe-uid-lo" # handle 536`,
		`meta skuid != { 0, 967 } ip daddr 127.0.0.1 tcp dport 8889 counter packets 0 bytes 0 log prefix "pipelock_agent_listener_blocked " drop # handle 743`,
		`meta skuid 1000 accept # handle 744`,
		`meta skuid 967 accept # handle 745`,
	}
	if !chainLinesHaveAgentListenerGuard(lines, "127.0.0.1:8889", 967) {
		t.Fatal("guard below published-service reply rules was reported missing")
	}
	bypass := append([]string{`meta skuid 966 ip daddr 127.0.0.1 tcp sport 8789 accept # handle 1`}, lines...)
	if chainLinesHaveAgentListenerGuard(bypass, "127.0.0.1:8889", 967) {
		t.Fatal("a source-port-only accept above the guard must still count as a bypass")
	}
}
