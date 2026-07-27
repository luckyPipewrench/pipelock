// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"context"
	"errors"
	"os"
	"testing"
)

// probe helpers build the three ProbeResult shapes the start gate distinguishes.
func openProbe(target string) ProbeResult {
	return ProbeResult{Target: target, Open: true, Blocked: false, Detail: "connected"}
}

func blockedProbe(target string) ProbeResult {
	return ProbeResult{Target: target, Open: false, Blocked: true, Detail: "blocked: timeout"}
}

func refusedProbe(target string) ProbeResult {
	return ProbeResult{Target: target, Open: false, Blocked: false, Detail: "reachable: connection refused"}
}

func allBlockedDirect() []ProbeResult {
	out := make([]ProbeResult, 0, len(DirectEgressTargets()))
	for _, t := range DirectEgressTargets() {
		out = append(out, blockedProbe(t))
	}
	return out
}

func allBlockedLocal() []ProbeResult {
	out := make([]ProbeResult, 0, len(LocalEscapeTargets()))
	for _, t := range LocalEscapeTargets() {
		out = append(out, blockedProbe(t))
	}
	return out
}

func TestInVMContainmentHookLifecycle(t *testing.T) {
	hook := NewInVMContainmentHook("/nonexistent/toyagent")
	hook.OperatorUID = 1000
	hook.ProxyUID = 967
	if hook.ToyAgentBin != "/nonexistent/toyagent" {
		t.Fatalf("toy agent = %q", hook.ToyAgentBin)
	}
	if err := hook.Setup(t.Context(), DemoOpts{ProxyPort: DefaultContainedProxyPort}); err == nil {
		t.Fatal("setup without a proven boundary should fail closed")
	}
	if err := hook.Teardown(t.TempDir()); err != nil {
		t.Fatalf("teardown: %v", err)
	}
}

func TestInVMContainmentHookForwardsUIDs(t *testing.T) {
	hook := NewInVMContainmentHook("/usr/local/bin/probe")
	hook.OperatorUID = 1000
	hook.ProxyUID = 967
	hook.verify = func(_ context.Context, bin, user string, port, operatorUID, proxyUID int) error {
		if bin != hook.ToyAgentBin || user != defaultContainedAgentUser ||
			port != DefaultContainedProxyPort || operatorUID != 1000 || proxyUID != 967 {
			t.Fatalf("forwarded values: bin=%q user=%q port=%d operator=%d proxy=%d",
				bin, user, port, operatorUID, proxyUID)
		}
		return nil
	}
	if err := hook.Setup(t.Context(), DemoOpts{ProxyPort: DefaultContainedProxyPort}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
}

func TestValidateContainmentUIDRoles(t *testing.T) {
	t.Parallel()
	if err := validateContainmentUIDRoles(1000, 967, 966); err != nil {
		t.Fatalf("distinct roles rejected: %v", err)
	}
	for _, tc := range []struct {
		name            string
		operator, proxy int
		agent           int
	}{
		{name: "negative operator", operator: -1, proxy: 967, agent: 966},
		{name: "negative proxy", operator: 1000, proxy: -1, agent: 966},
		{name: "operator is agent", operator: 966, proxy: 967, agent: 966},
		{name: "proxy is agent", operator: 1000, proxy: 966, agent: 966},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := validateContainmentUIDRoles(tc.operator, tc.proxy, tc.agent); err == nil {
				t.Fatal("unsafe uid roles accepted")
			}
		})
	}
}

func TestEvalStartContainment(t *testing.T) {
	const ctrl = "127.0.0.1:5005"

	tests := []struct {
		name        string
		operator    ProbeResult
		agentCtrl   ProbeResult
		agentDirect []ProbeResult
		agentLocal  []ProbeResult
		wantErr     bool
	}{
		{
			name:        "contained: operator open, agent all blocked",
			operator:    openProbe(ctrl),
			agentCtrl:   blockedProbe(ctrl),
			agentDirect: allBlockedDirect(),
			agentLocal:  allBlockedLocal(),
			wantErr:     false,
		},
		{
			name:        "operator cannot reach control (broken probe) fails closed",
			operator:    blockedProbe(ctrl),
			agentCtrl:   blockedProbe(ctrl),
			agentDirect: allBlockedDirect(),
			agentLocal:  allBlockedLocal(),
			wantErr:     true,
		},
		{
			name:        "operator control refused (not open) fails closed",
			operator:    refusedProbe(ctrl),
			agentCtrl:   blockedProbe(ctrl),
			agentDirect: allBlockedDirect(),
			agentLocal:  allBlockedLocal(),
			wantErr:     true,
		},
		{
			name:        "agent reached control (drop not active) fails closed",
			operator:    openProbe(ctrl),
			agentCtrl:   openProbe(ctrl),
			agentDirect: allBlockedDirect(),
			agentLocal:  allBlockedLocal(),
			wantErr:     true,
		},
		{
			name:        "agent control refused (reachable-but-closed) is not containment",
			operator:    openProbe(ctrl),
			agentCtrl:   refusedProbe(ctrl),
			agentDirect: allBlockedDirect(),
			agentLocal:  allBlockedLocal(),
			wantErr:     true,
		},
		{
			name:        "empty direct suite fails closed (no vacuous pass)",
			operator:    openProbe(ctrl),
			agentCtrl:   blockedProbe(ctrl),
			agentDirect: nil,
			agentLocal:  allBlockedLocal(),
			wantErr:     true,
		},
		{
			name:        "empty local suite fails closed (no vacuous pass)",
			operator:    openProbe(ctrl),
			agentCtrl:   blockedProbe(ctrl),
			agentDirect: allBlockedDirect(),
			agentLocal:  nil,
			wantErr:     true,
		},
		{
			name:      "one direct route open fails closed",
			operator:  openProbe(ctrl),
			agentCtrl: blockedProbe(ctrl),
			agentDirect: func() []ProbeResult {
				d := allBlockedDirect()
				d[2] = openProbe(d[2].Target) // a public DNS route is reachable
				return d
			}(),
			agentLocal: allBlockedLocal(),
			wantErr:    true,
		},
		{
			name:      "one direct route refused (not blocked) fails closed",
			operator:  openProbe(ctrl),
			agentCtrl: blockedProbe(ctrl),
			agentDirect: func() []ProbeResult {
				d := allBlockedDirect()
				d[0] = refusedProbe(d[0].Target)
				return d
			}(),
			agentLocal: allBlockedLocal(),
			wantErr:    true,
		},
		{
			name:        "one local escape surface open fails closed",
			operator:    openProbe(ctrl),
			agentCtrl:   blockedProbe(ctrl),
			agentDirect: allBlockedDirect(),
			agentLocal: func() []ProbeResult {
				l := allBlockedLocal()
				l[0] = openProbe(l[0].Target)
				return l
			}(),
			wantErr: true,
		},
		{
			name:        "absent surface plus real denials passes honestly",
			operator:    openProbe(ctrl),
			agentCtrl:   blockedProbe(ctrl),
			agentDirect: allBlockedDirect(),
			agentLocal: func() []ProbeResult {
				l := allBlockedLocal()
				l[0] = ProbeResult{Target: l[0].Target, Absent: true, Detail: "absent"}
				return l
			}(),
			wantErr: false,
		},
		{
			name:        "all local surfaces absent proves no denial",
			operator:    openProbe(ctrl),
			agentCtrl:   blockedProbe(ctrl),
			agentDirect: allBlockedDirect(),
			agentLocal: func() []ProbeResult {
				l := allBlockedLocal()
				for i := range l {
					l[i] = ProbeResult{Target: l[i].Target, Absent: true, Detail: "absent"}
				}
				return l
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := evalStartContainment(tt.operator, tt.agentCtrl, tt.agentDirect, tt.agentLocal)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("evalStartContainment: want error, got nil")
				}
				if !errors.Is(err, ErrInVMContainmentNotProven) {
					t.Fatalf("evalStartContainment: error %v should wrap ErrInVMContainmentNotProven", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("evalStartContainment: want nil, got %v", err)
			}
		})
	}
}

func TestEvalProxyStartContract(t *testing.T) {
	t.Parallel()
	target := "127.0.0.1:8888"
	if err := evalProxyStartContract(target, ProbeResult{Target: target, Open: true}); err != nil {
		t.Fatalf("reachable configured proxy rejected: %v", err)
	}
	for _, probe := range []ProbeResult{
		{Target: target, Blocked: true, Detail: "timeout"},
		{Target: "127.0.0.1:8899", Open: true},
		{Target: target},
	} {
		if err := evalProxyStartContract(target, probe); err == nil {
			t.Fatalf("invalid proxy probe accepted: %+v", probe)
		}
	}
}

func TestVerifyInVMContainment_FailsClosedWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root to exercise the euid!=0 fail-closed path")
	}
	err := VerifyInVMContainment(context.Background(), "/nonexistent/toyagent", "pipelock-agent", DefaultContainedProxyPort)
	if !errors.Is(err, ErrInVMContainmentNotProven) {
		t.Fatalf("VerifyInVMContainment without root: want ErrInVMContainmentNotProven, got %v", err)
	}
}

func TestVerifyInVMContainment_FailsClosedWithoutProbeBin(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the empty-bin check is reached only after the root check passes")
	}
	err := VerifyInVMContainment(context.Background(), "", "pipelock-agent", DefaultContainedProxyPort)
	if !errors.Is(err, ErrInVMContainmentNotProven) {
		t.Fatalf("VerifyInVMContainment without probe bin: want ErrInVMContainmentNotProven, got %v", err)
	}
}

func TestSpawnAgentEgressProbe_RequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root to exercise the root-required path")
	}
	_, err := spawnAgentEgressProbe(context.Background(), "/nonexistent/toyagent", "pipelock-agent", []string{"10.0.0.1:443"})
	if err == nil {
		t.Fatalf("spawnAgentEgressProbe without root: want error, got nil")
	}
}

func TestSpawnAgentLocalEscapeProbe_RequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root to exercise the root-required path")
	}
	_, err := spawnAgentLocalEscapeProbe(context.Background(), "/nonexistent/toyagent", "pipelock-agent")
	if err == nil {
		t.Fatalf("spawnAgentLocalEscapeProbe without root: want error, got nil")
	}
}
