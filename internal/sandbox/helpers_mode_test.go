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
	"strconv"
	"strings"
	"testing"
	"time"
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

func TestWaitForParentHardening_DeniesEOF(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create readiness pipe: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	if err := writer.Close(); err != nil {
		t.Fatalf("close readiness writer: %v", err)
	}
	t.Setenv(sandboxReadinessFDEnv, strconv.FormatUint(uint64(duplicateTestFD(t, reader)), 10))

	if err := waitForParentHardening(); err == nil {
		t.Fatal("readiness EOF allowed sandbox target start")
	}
}

func TestWaitForParentHardening_ValidatesAndConsumesRelease(t *testing.T) {
	t.Run("no readiness descriptor", func(t *testing.T) {
		t.Setenv(sandboxReadinessFDEnv, "")
		if err := waitForParentHardening(); err != nil {
			t.Fatalf("ungated launch wait: %v", err)
		}
	})

	t.Run("invalid descriptor", func(t *testing.T) {
		t.Setenv(sandboxReadinessFDEnv, "-1")
		err := waitForParentHardening()
		if err == nil || !strings.Contains(err.Error(), "invalid readiness descriptor") {
			t.Fatalf("invalid descriptor wait = %v", err)
		}
	})

	t.Run("non-numeric descriptor", func(t *testing.T) {
		t.Setenv(sandboxReadinessFDEnv, "notafd")
		err := waitForParentHardening()
		if err == nil || !strings.Contains(err.Error(), "invalid readiness descriptor") {
			t.Fatalf("non-numeric descriptor wait = %v", err)
		}
	})

	t.Run("one byte release", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatalf("create readiness pipe: %v", err)
		}
		t.Cleanup(func() { _ = reader.Close() })
		if _, err := writer.Write([]byte{1}); err != nil {
			_ = reader.Close()
			t.Fatalf("write readiness release: %v", err)
		}
		if err := writer.Close(); err != nil {
			_ = reader.Close()
			t.Fatalf("close readiness writer: %v", err)
		}
		t.Setenv(sandboxReadinessFDEnv, strconv.FormatUint(uint64(duplicateTestFD(t, reader)), 10))
		if err := waitForParentHardening(); err != nil {
			t.Fatalf("released launch wait: %v", err)
		}
	})
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

func TestAppliedLaunchOutcome(t *testing.T) {
	activeLandlock := LayerStatus{Name: LayerLandlock, Active: true}
	activeSeccomp := LayerStatus{Name: LayerSeccomp, Active: true}
	inactiveLandlock := LayerStatus{Name: LayerLandlock, Reason: "unavailable"}
	inactiveSeccomp := LayerStatus{Name: LayerSeccomp, Reason: "unavailable"}

	tests := []struct {
		name             string
		strict           bool
		noNetNS          bool
		seccompSupported bool
		landlock         LayerStatus
		seccomp          LayerStatus
		want             AppliedLaunchOutcome
		wantErr          bool
	}{
		{name: "full", landlock: activeLandlock, seccomp: activeSeccomp, seccompSupported: true, want: LaunchOutcomeFull},
		{name: "arm64 partial", landlock: activeLandlock, seccomp: inactiveSeccomp, want: LaunchOutcomePartial},
		{name: "network advisory override", noNetNS: true, landlock: activeLandlock, seccomp: activeSeccomp, seccompSupported: true, want: LaunchOutcomeAdvisoryOverride},
		{name: "missing landlock refuses", landlock: inactiveLandlock, seccomp: activeSeccomp, seccompSupported: true, want: LaunchOutcomeRefused, wantErr: true},
		{name: "unexpected seccomp failure refuses", landlock: activeLandlock, seccomp: inactiveSeccomp, seccompSupported: true, want: LaunchOutcomeRefused, wantErr: true},
		{name: "strict arm64 refuses", strict: true, landlock: activeLandlock, seccomp: inactiveSeccomp, want: LaunchOutcomeRefused, wantErr: true},
		{name: "strict network degrade refuses", strict: true, noNetNS: true, landlock: activeLandlock, seccomp: activeSeccomp, seccompSupported: true, want: LaunchOutcomeRefused, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := appliedLaunchOutcome(tt.strict, tt.noNetNS, tt.seccompSupported, tt.landlock, tt.seccomp)
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Fatalf("appliedLaunchOutcome() = %q, %v; want %q, error=%v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestReportAppliedLaunchOutcome(t *testing.T) {
	for _, tt := range []struct {
		name    string
		outcome AppliedLaunchOutcome
		want    []string
	}{
		{name: "full", outcome: LaunchOutcomeFull, want: []string{"FULL", "Landlock + seccomp + network namespace applied"}},
		{name: "partial", outcome: LaunchOutcomePartial, want: []string{"PARTIAL", "seccomp filter unavailable in this build"}},
		{name: "advisory override", outcome: LaunchOutcomeAdvisoryOverride, want: []string{"ADVISORY-OVERRIDE", "direct egress may bypass Pipelock"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			reportAppliedLaunchOutcome(&buf, tt.outcome)
			for _, want := range tt.want {
				if got := buf.String(); !strings.Contains(got, want) {
					t.Fatalf("outcome output = %q, want substring %q", got, want)
				}
			}
		})
	}
}

func TestValidateBestEffortOverride(t *testing.T) {
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name    string
		reason  string
		expires string
		wantErr string
	}{
		{name: "duration", reason: "container user namespaces are disabled", expires: "30m"},
		{name: "timestamp", reason: "temporary compatibility exception", expires: "2026-09-03T12:30:00Z"},
		{name: "missing reason", expires: "30m", wantErr: "reason"},
		{name: "missing expiry", reason: "temporary compatibility exception", wantErr: "expiry"},
		{name: "expired duration", reason: "temporary compatibility exception", expires: "0s", wantErr: "expired"},
		{name: "expired timestamp", reason: "temporary compatibility exception", expires: "2026-09-03T11:59:59Z", wantErr: "expired"},
		{name: "invalid expiry", reason: "temporary compatibility exception", expires: "tomorrow", wantErr: "duration or RFC3339"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateBestEffortOverride(tt.reason, tt.expires, now)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("validateBestEffortOverride() error = %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("validateBestEffortOverride() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
