// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestInstallNFTRulesRejectsBadManagedListenerConfig(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		body       []byte
		readErr    error
	}{
		{"unreadable", "read managed listener config", nil, os.ErrPermission},
		{"malformed", "managed listener config", []byte("containment: ["), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			prior := env.readFile
			configReads := 0
			env.readFile = func(path string) ([]byte, error) {
				if path == managedPipelockConfigPath(env) {
					configReads++
					if configReads == 1 {
						return []byte("mode: balanced\n"), nil
					}
					return tc.body, tc.readErr
				}
				return prior(path)
			}
			applied, err := stepInstallNFTRulesApply(context.Background(), env)
			if applied || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("apply = %v, %v; want refusal containing %q", applied, err, tc.want)
			}
		})
	}
}

func TestAgentListenerConfigBytesFailures(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"empty", "", ""},
		{"no listener", "containment: {}\n", ""},
		{"valid IPv4", "containment:\n  agent_listener: 127.0.0.1:8889\n", "127.0.0.1:8889"},
		{"valid IPv6", "containment:\n  agent_listener: '[::1]:8889'\n", "[::1]:8889"},
		{"bad yaml", "containment: [\n", "error"},
		{"scalar", "hello\n", "error"},
		{"decode type", "containment:\n  agent_listener: [a]\n", "error"},
		{"missing port", "containment:\n  agent_listener: 127.0.0.1\n", "error"},
		{"nonloopback", "containment:\n  agent_listener: 192.0.2.1:8889\n", "error"},
		{"hostname", "containment:\n  agent_listener: localhost:8889\n", "error"},
		{"zero port", "containment:\n  agent_listener: 127.0.0.1:0\n", "error"},
		{"large port", "containment:\n  agent_listener: 127.0.0.1:65536\n", "error"},
		{"text port", "containment:\n  agent_listener: 127.0.0.1:http\n", "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := agentListenerFromConfigBytes([]byte(tc.body))
			if tc.want == "error" {
				if err == nil {
					t.Fatalf("accepted %q as %q", tc.body, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("listener=%q err=%v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestAgentListenerGuardRejectsMalformedRules(t *testing.T) {
	for _, tc := range []struct{ name, line, listener string }{
		{"invalid listener", "", "not-an-address"},
		{"early accept", "meta skuid 1001 accept", "127.0.0.1:8889"},
		{"short guard", "pipelock_agent_listener_blocked", "127.0.0.1:8889"},
		{"wrong family", `meta skuid != { 0, 1001 } ip6 daddr 127.0.0.1 tcp dport 8889 counter log prefix "pipelock_agent_listener_blocked " drop`, "127.0.0.1:8889"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if chainLinesHaveAgentListenerGuard([]string{tc.line}, tc.listener, 1001) {
				t.Fatalf("accepted %q", tc.line)
			}
		})
	}
	for _, line := range []string{
		"meta skuid != { 0, 1001 } ip daddr 127.0.0.1 tcp dport 0 counter log prefix \"pipelock_agent_listener_blocked \" drop",
		"meta skuid != { 0, 1001 } ip daddr 127.0.0.1 tcp dport bad counter log prefix \"pipelock_agent_listener_blocked \" drop",
		"meta skuid != { 0, 1001 } ip daddr 127.0.0.1 udp dport 8889 counter log prefix \"pipelock_agent_listener_blocked \" drop",
	} {
		if lineHasAgentListenerGuardForProxy(line, 1001) {
			t.Fatalf("recognized invalid guard %q", line)
		}
	}
	invalid := renderNFTRulesWithServices(nftRuleOptions{AgentListener: "192.0.2.1:8889"})
	if !strings.Contains(invalid, "invalid containment.agent_listener") {
		t.Fatalf("invalid listener rendered rules: %q", invalid)
	}
	if chainLinesHaveAgentListenerGuard(nil, "bad-listener", 1001) {
		t.Fatal("accepted invalid listener")
	}
	ipv6 := renderNFTRulesWithServices(nftRuleOptions{OperatorUID: 1000, ProxyUID: 1001, AgentUID: 1002, ProxyPort: 8888, Table: defaultNFTTable, Chain: defaultNFTChain, AgentListener: "[::1]:8889"})
	if !chainLinesHaveAgentListenerGuard(strings.Split(ipv6, "\n"), "[::1]:8889", 1001) {
		t.Fatal("rejected canonical IPv6 listener guard")
	}
	guard := `meta skuid != { 0, 1001 } ip daddr 127.0.0.1 tcp dport 8889 counter log prefix "pipelock_agent_listener_blocked " drop`
	if chainLinesHaveUnsafeVerdictBeforeAgentDrop([]string{guard, "meta skuid 1002 counter log prefix \"pipelock_agent_blocked \" drop"}, containmentUIDs{proxyUID: 1001, agentUID: 1002}, 8888) {
		t.Fatal("managed listener guard counted as unsafe verdict")
	}
}

func TestBrowserDefaultsRecordIOFailures(t *testing.T) {
	env, _, _, record := browserDefaultsEnv(t)
	env.writeFile = func(string, []byte, os.FileMode) error { return os.ErrPermission }
	if err := writeAgentBrowserDefaultsRecord(env, []byte("record")); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("write error: %v", err)
	}
	env.removeFile = func(string) error { return os.ErrPermission }
	if err := removeAgentBrowserDefaultsRecord(env); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("remove error: %v", err)
	}
	env.removeFile = func(path string) error {
		if path != record {
			t.Fatalf("wrong record path %q", path)
		}
		return os.ErrNotExist
	}
	if err := removeAgentBrowserDefaultsRecord(env); err != nil {
		t.Fatalf("absent record: %v", err)
	}
}
