// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"testing"
)

// cannedResp is one canned (stdout, exitCode, err) the injected runner returns.
type cannedResp struct {
	out  string
	code int
	err  error
}

// conformanceRunner dispatches on the executable name: probe 8 shells out via
// "sudo", and probe 9 (with an empty OperatorUser) invokes curl directly, so
// the command name alone tells the two egress probes apart.
func conformanceRunner(probe8, probe9 cannedResp) ConformanceRunCommand {
	return func(_ context.Context, name string, _ ...string) (string, int, error) {
		if name == "sudo" {
			return probe8.out, probe8.code, probe8.err
		}
		return probe9.out, probe9.code, probe9.err
	}
}

func TestRunContainmentConformance_NilRunnerFailsClosed(t *testing.T) {
	results, exit, err := RunContainmentConformance(context.Background(), ConformanceEnv{})
	if err == nil {
		t.Fatal("nil runner: expected a fail-closed error, got nil")
	}
	if results != nil {
		t.Fatalf("nil runner: expected nil results, got %v", results)
	}
	if exit != conformanceExitInvalid {
		t.Fatalf("nil runner: exit = %d, want %d (invalid/config)", exit, conformanceExitInvalid)
	}
}

func TestRunContainmentConformance_Outcomes(t *testing.T) {
	const blockedExit = 7 // curl connection-refused style exit when egress is denied

	tests := []struct {
		name       string
		ctx        context.Context
		agentUser  string
		probe8     cannedResp // sudo -u agent -- curl
		probe9     cannedResp // curl (operator, empty user -> direct)
		wantExit   int
		wantStatus map[int]string // probe number -> expected status
	}{
		{
			name:      "both_pass_nil_ctx_default_agent_user",
			ctx:       nil, // exercises the ctx == nil default
			agentUser: "",  // exercises the defaultAgentUser fallback
			probe8:    cannedResp{out: "curl: (7) refused", code: blockedExit},
			probe9:    cannedResp{out: "200", code: 0},
			wantExit:  ConformanceExitOK,
			wantStatus: map[int]string{
				8: ConformanceStatusPass,
				9: ConformanceStatusPass,
			},
		},
		{
			name:      "agent_egress_leaked_fails",
			ctx:       context.Background(),
			agentUser: "pipelock-agent",
			probe8:    cannedResp{out: "200", code: 0}, // agent reached the internet -> leak
			probe9:    cannedResp{out: "200", code: 0},
			wantExit:  ConformanceExitFail,
			wantStatus: map[int]string{
				8: ConformanceStatusFail,
				9: ConformanceStatusPass,
			},
		},
		{
			name:      "runner_unavailable_skips",
			ctx:       context.Background(),
			agentUser: "pipelock-agent",
			probe8:    cannedResp{err: errors.New("sudo: command not found")},
			probe9:    cannedResp{err: errors.New("curl: command not found")},
			wantExit:  ConformanceExitSkip,
			wantStatus: map[int]string{
				8: ConformanceStatusSkip,
				9: ConformanceStatusSkip,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := ConformanceEnv{
				RunCommand: conformanceRunner(tc.probe8, tc.probe9),
				AgentUser:  tc.agentUser,
			}
			results, exit, err := RunContainmentConformance(tc.ctx, env)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if exit != tc.wantExit {
				t.Fatalf("exit = %d, want %d", exit, tc.wantExit)
			}
			if len(results) != len(tc.wantStatus) {
				t.Fatalf("got %d results, want %d", len(results), len(tc.wantStatus))
			}
			for _, r := range results {
				want, ok := tc.wantStatus[r.Probe]
				if !ok {
					t.Fatalf("unexpected probe %d in results", r.Probe)
				}
				if r.Status != want {
					t.Errorf("probe %d (%s): status = %q, want %q (detail: %s)", r.Probe, r.Name, r.Status, want, r.Detail)
				}
			}
		})
	}
}
