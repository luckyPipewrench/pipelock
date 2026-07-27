// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"slices"
	"testing"
)

func TestGoBuildArgs_DisablesVCSStamping(t *testing.T) {
	t.Parallel()
	args := goBuildArgs("./cmd/helper", "/tmp/helper")
	if !slices.Contains(args, "-buildvcs=false") {
		t.Fatalf("go build args must avoid mutable Git metadata: %v", args)
	}
}

func TestDecodeProbeResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		stdout          string
		expectedTargets []string
		wantErr         bool
		wantOpen        []bool
		wantBlocked     []bool
	}{
		{
			name:            "valid two results",
			stdout:          `[{"target":"127.0.0.1:1","open":false,"blocked":true,"detail":"blocked"},{"target":"127.0.0.1:2","open":true,"blocked":false,"detail":"connected"}]`,
			expectedTargets: []string{"127.0.0.1:1", "127.0.0.1:2"},
			wantOpen:        []bool{false, true},
			wantBlocked:     []bool{true, false},
		},
		{
			name:            "malformed json",
			stdout:          `not json`,
			expectedTargets: []string{"127.0.0.1:1"},
			wantErr:         true,
		},
		{
			name:            "count mismatch",
			stdout:          `[{"target":"127.0.0.1:1","open":false,"detail":"blocked"}]`,
			expectedTargets: []string{"127.0.0.1:1", "127.0.0.1:2"},
			wantErr:         true,
		},
		{
			name:            "empty array but expected one",
			stdout:          `[]`,
			expectedTargets: []string{"127.0.0.1:1"},
			wantErr:         true,
		},
		{
			name:            "target mismatch",
			stdout:          `[{"target":"127.0.0.1:2","open":false,"detail":"blocked"}]`,
			expectedTargets: []string{"127.0.0.1:1"},
			wantErr:         true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := decodeProbeResults([]byte(tc.stdout), tc.expectedTargets)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got results %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.wantOpen) {
				t.Fatalf("got %d results, want %d", len(got), len(tc.wantOpen))
			}
			for i, open := range tc.wantOpen {
				if got[i].Open != open {
					t.Errorf("result[%d].Open=%v want %v", i, got[i].Open, open)
				}
				if got[i].Blocked != tc.wantBlocked[i] {
					t.Errorf("result[%d].Blocked=%v want %v", i, got[i].Blocked, tc.wantBlocked[i])
				}
			}
		})
	}
}

// TestAllAgentBlocked_HappyAndEmpty pins both ends of AllAgentBlocked: the
// all-blocked happy path returns true, the empty suite returns false.
func TestAllAgentBlocked_HappyAndEmpty(t *testing.T) {
	t.Parallel()
	w := HostContainmentWitness{
		ProbeSuiteVersion: currentContainmentProbeSuite,
		ControlAgentProbe: ProbeResult{Open: false, Blocked: true},
		AgentProbes:       []ProbeResult{{Open: false, Blocked: true}, {Open: false, Blocked: true}},
		LocalAgentProbes:  []ProbeResult{{Open: false, Blocked: true}},
	}
	if !w.AllAgentBlocked() {
		t.Error("all-blocked suite should report AllAgentBlocked=true")
	}
	w.AgentProbes = []ProbeResult{{Open: false, Blocked: false}}
	if w.AllAgentBlocked() {
		t.Error("reachable-but-closed suite must not report AllAgentBlocked=true")
	}
	w.AgentProbes = nil
	if w.AllAgentBlocked() {
		t.Error("empty suite must not report AllAgentBlocked=true")
	}
}

func TestStatusEvent(t *testing.T) {
	t.Parallel()

	modelBacked := statusEvent(LiveStateContained, "run-1", true)
	if modelBacked.Type != LiveEventStatus || modelBacked.State != LiveStateContained || modelBacked.RunID != "run-1" {
		t.Fatalf("unexpected status event: %+v", modelBacked)
	}
	if modelBacked.Disclaimer != ThirdPartyModelDisclaimer {
		t.Errorf("model-backed status must carry the third-party disclaimer, got %q", modelBacked.Disclaimer)
	}

	deterministic := statusEvent(LiveStateDev, "run-2", false)
	if deterministic.Disclaimer != "" {
		t.Errorf("deterministic status must omit the disclaimer, got %q", deterministic.Disclaimer)
	}
}

func TestProxyBindAddrFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		port    int
		want    string
		wantErr bool
	}{
		{name: "zero is ephemeral", port: 0, want: "127.0.0.1:0"},
		{name: "fixed port", port: 8888, want: "127.0.0.1:8888"},
		{name: "high port", port: 65535, want: "127.0.0.1:65535"},
		{name: "negative rejected", port: -1, wantErr: true},
		{name: "out of range rejected", port: 70000, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := proxyBindAddrFor(tc.port)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("proxyBindAddrFor(%d) error = nil, want error", tc.port)
				}
				return
			}
			if err != nil {
				t.Fatalf("proxyBindAddrFor(%d) unexpected error: %v", tc.port, err)
			}
			if got != tc.want {
				t.Fatalf("proxyBindAddrFor(%d) = %q, want %q", tc.port, got, tc.want)
			}
		})
	}
}
