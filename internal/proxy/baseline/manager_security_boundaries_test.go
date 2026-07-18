// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBaselineAgentKeyAPIsRejectAmbiguousStorageKeys(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr string
	}{
		{name: "valid", key: "agent.prod-1"},
		{name: "empty", key: "", wantErr: "empty agent key"},
		{name: "path_separator", key: "tenant/agent", wantErr: "must match"},
		{name: "path_traversal", key: "tenant..agent", wantErr: "path traversal"},
		{name: "log_control", key: "agent\nforged", wantErr: "must match"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAgentKey(tc.key)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateAgentKey(%q): %v", tc.key, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateAgentKey(%q) error = %v, want %q", tc.key, err, tc.wantErr)
			}
		})
	}
}

func TestBaselineCheckErrFailsClosedBeforeEvaluation(t *testing.T) {
	mgr, err := NewManager(Config{
		Enabled:          true,
		LearningWindow:   1,
		AutoRatify:       true,
		SensitivitySigma: 2,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	mgr.RecordSession(testAgent, normalMetrics())

	deviations, err := mgr.CheckErr("../"+testAgent, SessionMetrics{ToolCalls: 9999})
	if err == nil {
		t.Fatal("CheckErr accepted a traversal-shaped agent key")
	}
	if deviations != nil {
		t.Fatalf("invalid key deviations = %+v, want nil fail-closed result", deviations)
	}

	deviations, err = mgr.CheckErr(testAgent, SessionMetrics{ToolCalls: 9999})
	if err != nil {
		t.Fatalf("CheckErr valid key: %v", err)
	}
	if len(deviations) == 0 {
		t.Fatal("CheckErr valid key did not report the locked profile deviation")
	}
}

func TestBaselineReconfigureRejectsInvalidPolicyWithoutPartialMutation(t *testing.T) {
	mgr, err := NewManager(Config{
		Enabled:          true,
		LearningWindow:   7,
		DeviationAction:  deviationActionBlock,
		SensitivitySigma: 3,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	original := mgr.cfg

	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "unknown_action",
			cfg:  Config{DeviationAction: "allow"},
		},
		{
			name: "unsupported_seasonality",
			cfg:  Config{DeviationAction: deviationActionBlock, SeasonalityMode: "hourly"},
		},
		{
			name: "unknown_lock_dimension",
			cfg:  Config{DeviationAction: deviationActionBlock, LockDimensions: []string{"shell_commands"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := mgr.Reconfigure(tc.cfg); err == nil {
				t.Fatal("Reconfigure accepted an unsupported enforcement policy")
			}
			if !reflect.DeepEqual(mgr.cfg, original) {
				t.Fatalf("failed Reconfigure mutated config: got %+v, want %+v", mgr.cfg, original)
			}
		})
	}

	mgr.RecordSession(testAgent, normalMetrics())
	if err := mgr.Reconfigure(Config{Enabled: true}); err != nil {
		t.Fatalf("Reconfigure to in-memory defaults: %v", err)
	}
	if mgr.cfg.LearningWindow != 10 || mgr.cfg.SensitivitySigma != 2 ||
		mgr.cfg.DeviationAction != deviationActionWarn || mgr.cfg.SeasonalityMode != seasonalityNone {
		t.Fatalf("Reconfigure defaults = %+v", mgr.cfg)
	}
	if state := mgr.GetState(testAgent); state != StateObserve {
		t.Fatalf("Reconfigure erased in-memory agent state: got %q, want %q", state, StateObserve)
	}
}

func TestBaselineNewManagerRejectsInvalidPolicyAndProfilePath(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{
			name: "unsupported_seasonality",
			cfg:  Config{SeasonalityMode: "weekly"},
		},
		{
			name: "unknown_lock_dimension",
			cfg:  Config{LockDimensions: []string{"process_tree"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewManager(tc.cfg); err == nil {
				t.Fatal("NewManager accepted an unsupported baseline policy")
			}
		})
	}

	t.Run("profile_path_is_file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "profiles")
		if err := os.WriteFile(path, []byte("attacker-controlled"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := NewManager(Config{ProfileDir: path}); err == nil ||
			!strings.Contains(err.Error(), "creating profile dir") {
			t.Fatalf("NewManager profile path error = %v, want directory creation failure", err)
		}
	})
}

func TestBaselineLifecycleRejectsMissingProfileAndMaliciousResetKey(t *testing.T) {
	mgr := &Manager{
		cfg: Config{},
		agents: map[string]*agentState{
			testAgent: {
				state: StateRatify,
			},
		},
	}

	if err := mgr.Ratify(testAgent); err == nil || !strings.Contains(err.Error(), "no profile") {
		t.Fatalf("Ratify missing profile error = %v", err)
	}
	if state := mgr.GetState(testAgent); state != StateRatify {
		t.Fatalf("failed Ratify changed state = %q, want %q", state, StateRatify)
	}

	if err := mgr.Reset("../" + testAgent); err == nil {
		t.Fatal("Reset accepted a traversal-shaped agent key")
	}
	if state := mgr.GetState(testAgent); state != StateRatify {
		t.Fatalf("rejected Reset changed legitimate agent state = %q, want %q", state, StateRatify)
	}
}

func TestBaselineLoadProfilesFilesystemBoundaries(t *testing.T) {
	t.Run("missing_directory_is_empty_restart", func(t *testing.T) {
		mgr := &Manager{
			cfg:    Config{ProfileDir: filepath.Join(t.TempDir(), "missing")},
			agents: make(map[string]*agentState),
		}
		if err := mgr.loadProfiles(); err != nil {
			t.Fatalf("loadProfiles missing directory: %v", err)
		}
		if len(mgr.agents) != 0 {
			t.Fatalf("missing profile directory loaded agents: %+v", mgr.agents)
		}
	})

	t.Run("profile_directory_is_file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "profiles")
		if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		mgr := &Manager{cfg: Config{ProfileDir: path}, agents: make(map[string]*agentState)}
		if err := mgr.loadProfiles(); err == nil || !strings.Contains(err.Error(), "reading profile directory") {
			t.Fatalf("loadProfiles file path error = %v, want directory read failure", err)
		}
	})

	t.Run("warn_mode_skips_json_directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "attacker.json"), 0o750); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		mgr, err := NewManager(Config{
			DeviationAction: deviationActionWarn,
			ProfileDir:      dir,
		})
		if err != nil {
			t.Fatalf("NewManager warn mode: %v", err)
		}
		if agents := mgr.ListAgents(); len(agents) != 0 {
			t.Fatalf("JSON directory created baseline agents: %v", agents)
		}
	})
}

func TestIntegrityManifestCommittedErrorPreservesCause(t *testing.T) {
	cause := errors.New("high-water write failed")
	committed := integrityManifestCommittedError{err: cause}
	wrapped := fmt.Errorf("persist profile: %w", committed)

	if !integrityManifestAlreadyCommitted(wrapped) {
		t.Fatal("wrapped committed-manifest error lost its commit marker")
	}
	if !errors.Is(wrapped, cause) {
		t.Fatal("wrapped committed-manifest error lost its underlying cause")
	}
	if got := committed.Error(); got != cause.Error() {
		t.Fatalf("Error() = %q, want %q", got, cause)
	}
}
