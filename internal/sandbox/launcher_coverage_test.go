// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"runtime"
	"strings"
	"testing"
)

func TestPrepareSandboxCmd_StrictAndBestEffortExclusive(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	workspace := t.TempDir()

	_, err := PrepareSandboxCmd(LaunchConfig{
		Command:    []string{"echo", "test"},
		Workspace:  workspace,
		Strict:     true,
		BestEffort: true,
	})
	if err == nil {
		t.Error("expected error for strict + best_effort")
	}
}

func TestLaunchStandalone_StrictAndBestEffortExclusive(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	workspace := t.TempDir()

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:    []string{"echo", "test"},
		Workspace:  workspace,
		Strict:     true,
		BestEffort: true,
	})
	if err == nil {
		t.Error("expected error for strict + best_effort")
	}
}

func TestPrepareSandboxCmd_WithPolicy(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	workspace := t.TempDir()

	policy := &Policy{
		Workspace:     workspace,
		AllowReadDirs: []string{"/usr/"},
		AllowRWDirs:   []string{workspace},
	}

	cmd, err := PrepareSandboxCmd(LaunchConfig{
		Command:   []string{"echo", "test"},
		Workspace: workspace,
		Policy:    policy,
	})
	if err != nil {
		t.Fatalf("PrepareSandboxCmd: %v", err)
	}

	// Verify policy JSON was passed in the command env.
	foundPolicy := false
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "__PIPELOCK_SANDBOX_POLICY=") {
			foundPolicy = true
			break
		}
	}
	if !foundPolicy {
		t.Error("expected __PIPELOCK_SANDBOX_POLICY in cmd env")
	}
}

func TestPrepareSandboxCmd_WithExtraEnv(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	workspace := t.TempDir()

	cmd, err := PrepareSandboxCmd(LaunchConfig{
		Command:   []string{"echo", "test"},
		Workspace: workspace,
		ExtraEnv:  []string{"MY_VAR=hello"},
	})
	if err != nil {
		t.Fatalf("PrepareSandboxCmd: %v", err)
	}

	// Verify extra env was passed.
	foundExtra := false
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "__PIPELOCK_SANDBOX_EXTRA_ENV=") {
			foundExtra = true
			break
		}
	}
	if !foundExtra {
		t.Error("expected __PIPELOCK_SANDBOX_EXTRA_ENV in cmd env")
	}
}

func TestPrepareSandboxCmd_NilCtxUsesBackground(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	workspace := t.TempDir()

	cmd, err := PrepareSandboxCmd(LaunchConfig{
		Ctx:       nil, // should default to context.Background()
		Command:   []string{"echo", "test"},
		Workspace: workspace,
	})
	if err != nil {
		t.Fatalf("PrepareSandboxCmd: %v", err)
	}
	if cmd == nil {
		t.Error("expected non-nil cmd")
	}
}

func TestResult_Methods(t *testing.T) {
	tests := []struct {
		name            string
		layers          []LayerStatus
		wantActive      int
		wantTotal       int
		wantFullContain bool
	}{
		{
			name:            "all active",
			layers:          []LayerStatus{{Active: true}, {Active: true}, {Active: true}},
			wantActive:      3,
			wantTotal:       3,
			wantFullContain: true,
		},
		{
			name:            "none active",
			layers:          []LayerStatus{{Active: false}, {Active: false}},
			wantActive:      0,
			wantTotal:       2,
			wantFullContain: false,
		},
		{
			name:            "mixed",
			layers:          []LayerStatus{{Active: true}, {Active: false}, {Active: true}},
			wantActive:      2,
			wantTotal:       3,
			wantFullContain: false,
		},
		{
			name:            "empty",
			layers:          nil,
			wantActive:      0,
			wantTotal:       0,
			wantFullContain: true, // 0 == 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Result{Layers: tt.layers}
			if got := r.ActiveCount(); got != tt.wantActive {
				t.Errorf("ActiveCount() = %d, want %d", got, tt.wantActive)
			}
			if got := r.TotalCount(); got != tt.wantTotal {
				t.Errorf("TotalCount() = %d, want %d", got, tt.wantTotal)
			}
			if got := r.IsFullyContained(); got != tt.wantFullContain {
				t.Errorf("IsFullyContained() = %v, want %v", got, tt.wantFullContain)
			}
		})
	}
}
