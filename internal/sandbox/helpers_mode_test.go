// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func TestIsStrictMode(t *testing.T) {
	tests := []struct {
		name   string
		envVal string
		want   bool
	}{
		{name: "set to 1", envVal: "1", want: true},
		{name: "set to 0", envVal: "0", want: false},
		{name: "empty string", envVal: "", want: false},
		{name: "set to true", envVal: "true", want: false},
		{name: "set to yes", envVal: "yes", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(strictEnvKey, tt.envVal)
			got := IsStrictMode()
			if got != tt.want {
				t.Errorf("IsStrictMode() = %v, want %v (env=%q)", got, tt.want, tt.envVal)
			}
		})
	}
}

func TestIsStandaloneInitMode(t *testing.T) {
	tests := []struct {
		name   string
		envVal string
		want   bool
	}{
		{name: "set to 1", envVal: "1", want: true},
		{name: "set to 0", envVal: "0", want: false},
		{name: "empty string", envVal: "", want: false},
		{name: "set to true", envVal: "true", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(standaloneInitEnv, tt.envVal)
			got := IsStandaloneInitMode()
			if got != tt.want {
				t.Errorf("IsStandaloneInitMode() = %v, want %v (env=%q)", got, tt.want, tt.envVal)
			}
		})
	}
}

func TestEncodePolicyJSON_RoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
	}{
		{
			name: "minimal policy",
			policy: Policy{
				Workspace: "/tmp/test",
			},
		},
		{
			name: "full policy",
			policy: Policy{
				Workspace:      "/workspace",
				AllowReadDirs:  []string{"/usr/", "/lib/"},
				AllowReadFiles: []string{"/etc/hosts"},
				AllowRWDirs:    []string{"/workspace"},
				AllowRWFiles:   []string{"/dev/null"},
				DenyReadDirs:   []string{"/home/.ssh"},
			},
		},
		{
			name: "empty workspace",
			policy: Policy{
				AllowReadDirs: []string{"/opt/"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := encodePolicyJSON(&tt.policy)
			if err != nil {
				t.Fatalf("encodePolicyJSON: %v", err)
			}

			var decoded Policy
			if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if decoded.Workspace != tt.policy.Workspace {
				t.Errorf("workspace = %q, want %q", decoded.Workspace, tt.policy.Workspace)
			}
			if len(decoded.AllowReadDirs) != len(tt.policy.AllowReadDirs) {
				t.Errorf("AllowReadDirs len = %d, want %d",
					len(decoded.AllowReadDirs), len(tt.policy.AllowReadDirs))
			}
		})
	}
}

func TestResolvePolicy_InvalidJSON_SubprocessExit(t *testing.T) {
	// resolvePolicy calls os.Exit(1) on invalid JSON. Test via subprocess.
	if os.Getenv("TEST_RESOLVE_POLICY_CRASH") == "1" {
		t.Setenv("__PIPELOCK_SANDBOX_POLICY", "{invalid json")
		resolvePolicy("/tmp/test")
		return
	}

	ctx := t.Context()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestResolvePolicy_InvalidJSON_SubprocessExit") //nolint:gosec // G204: re-exec of test binary for os.Exit testing
	cmd.Env = append(os.Environ(),
		"TEST_RESOLVE_POLICY_CRASH=1",
		"__PIPELOCK_SANDBOX_POLICY={invalid json",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit for invalid policy JSON")
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
	}
}

func TestReportLayer_UnavailableNoErrorNoReason(t *testing.T) {
	// When both Reason and err are empty, the output should show
	// an empty reason in parentheses.
	var buf bytes.Buffer
	status := LayerStatus{Name: LayerNetNS}
	reportLayer(&buf, status, nil)
	got := buf.String()
	if got == "" {
		t.Error("expected non-empty output")
	}
	expected := fmt.Sprintf("[sandbox] %s: UNAVAILABLE ()\n", LayerNetNS)
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}
