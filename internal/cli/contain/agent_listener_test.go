// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestContainedRelayTargetFollowsAgentListener proves the doorway relay
// delivers to the contained agent's own listener when the managed config names
// one, so the proxy attributes the traffic to the profile bound there, and
// keeps the shared listener otherwise.
func TestContainedRelayTargetFollowsAgentListener(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	withListener := write("with.yaml", "agents:\n  contained:\n    listeners: [\"127.0.0.1:8889\"]\ncontainment:\n  agent_listener: 127.0.0.1:8889\n")
	without := write("without.yaml", "mode: balanced\n")

	if got := containedRelayTarget(withListener, 8888); got != "127.0.0.1:8889" {
		t.Fatalf("relay target with agent_listener = %q, want 127.0.0.1:8889", got)
	}
	if got := containedRelayTarget(without, 8888); got != "127.0.0.1:8888" {
		t.Fatalf("relay target without agent_listener = %q, want the shared listener", got)
	}
	if got := containedRelayTarget(filepath.Join(dir, "absent.yaml"), 8888); got != "127.0.0.1:8888" {
		t.Fatalf("relay target with no config = %q, want the shared listener", got)
	}

	unit := renderContainedProxyForwarderUnitTo("/usr/local/bin/pipelock", "pipelock-proxy", containedRelayTarget(withListener, 8888))
	if !strings.Contains(unit, "--target-tcp 127.0.0.1:8889\n") {
		t.Fatalf("relay unit does not target the agent listener:\n%s", unit)
	}
	if strings.Contains(unit, "127.0.0.1:8888") {
		t.Fatalf("relay unit still targets the shared listener:\n%s", unit)
	}
}

func TestAgentListenerReloadReplacesGuardedAndLegacyBlocks(t *testing.T) {
	t.Parallel()
	opts := nftRuleOptions{OperatorUID: 1000, ProxyUID: 1001, AgentUID: 1002, ProxyPort: 8888, Table: defaultNFTTable, Chain: defaultNFTChain, AgentListener: "127.0.0.1:8889"}
	toLive := func(body string) string {
		var lines []string
		handle := 20
		for _, line := range managedNFTLinesFromRulesBody(body) {
			lines = append(lines, line+" # handle "+strconv.Itoa(handle))
			handle++
		}
		return strings.Join(lines, "\n")
	}
	guarded := toLive(renderNFTRulesWithServices(opts))
	if got := legacyManagedNFTRuleBlockHandles(guarded, 1000, 1001, 1002); len(got) != 7 {
		t.Fatalf("guarded block handles = %v, want seven", got)
	}
	opts.AgentListener = "127.0.0.1:8890"
	changed := renderNFTManagedChainReloadScript(guarded, renderNFTRulesWithServices(opts), opts.Table, opts.Chain, 1000, 1001, 1002, false)
	if !strings.Contains(changed, "handle 20") || !strings.Contains(changed, "tcp dport 8890") || strings.Contains(changed, "tcp dport 8889") {
		t.Fatalf("reload did not replace changed listener: %s", changed)
	}
	opts.AgentListener = ""
	removed := renderNFTManagedChainReloadScript(guarded, renderNFTRulesWithServices(opts), opts.Table, opts.Chain, 1000, 1001, 1002, false)
	if !strings.Contains(removed, "handle 20") || strings.Contains(removed, "pipelock_agent_listener_blocked") {
		t.Fatalf("reload did not remove listener guard: %s", removed)
	}
	legacy := toLive(renderNFTRulesWithServices(opts))
	if got := legacyManagedNFTRuleBlockHandles(legacy, 1000, 1001, 1002); len(got) != 6 {
		t.Fatalf("pre-change block handles = %v, want six", got)
	}
}

func TestAgentListenerManagedRule(t *testing.T) {
	t.Parallel()
	opts := nftRuleOptions{OperatorUID: 1000, ProxyUID: 1001, AgentUID: 1002, ProxyPort: 8888, Table: defaultNFTTable, Chain: defaultNFTChain}
	without := renderNFTRulesWithServices(opts)
	if strings.Contains(without, "pipelock_agent_listener_blocked") {
		t.Fatal("unset listener emitted owner guard")
	}
	opts.AgentListener = "127.0.0.1:8889"
	with := renderNFTRulesWithServices(opts)
	want := `meta skuid != { 0, 1001 } ip daddr 127.0.0.1 tcp dport 8889 counter log prefix "pipelock_agent_listener_blocked " drop`
	if !strings.Contains(with, want) {
		t.Fatalf("missing listener owner guard: %s", with)
	}
	if strings.Index(with, want) > strings.Index(with, "meta skuid 1000 accept") {
		t.Fatal("listener guard follows operator accept")
	}
	if !chainLinesHaveAgentListenerGuard(strings.Split(with, "\n"), opts.AgentListener, opts.ProxyUID) {
		t.Fatal("verifier rejected canonical listener guard")
	}
	for _, tc := range []struct{ name, change string }{
		{"wrong uid", strings.Replace(want, "1001", "1003", 1)},
		{"wrong port", strings.Replace(want, "8889", "8890", 1)},
		{"missing drop", strings.TrimSuffix(want, " drop")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := strings.Replace(with, want, tc.change, 1)
			if chainLinesHaveAgentListenerGuard(strings.Split(tampered, "\n"), opts.AgentListener, opts.ProxyUID) {
				t.Fatalf("accepted %s guard", tc.name)
			}
		})
	}
	if !lineHasAgentListenerGuardForProxy(want, opts.ProxyUID) {
		t.Fatal("reload did not recognize canonical listener guard")
	}
	if lineHasAgentListenerGuardForProxy(strings.TrimSuffix(want, " drop"), opts.ProxyUID) {
		t.Fatal("reload recognized guard without drop")
	}
}
