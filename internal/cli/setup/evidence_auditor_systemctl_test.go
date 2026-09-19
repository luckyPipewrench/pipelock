// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// The installer must be able to express only the two operations it needs, with
// every argument a literal, so it never becomes a general command surface.
func TestSystemctlCommandBuildsOnlyPermittedOperations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		op       systemctlOp
		wantArgs []string
	}{
		{
			name:     "daemon reload",
			op:       systemctlDaemonReload,
			wantArgs: []string{"systemctl", "--user", "daemon-reload"},
		},
		{
			name:     "enable auditor timer",
			op:       systemctlEnableAuditorTimer,
			wantArgs: []string{"systemctl", "--user", "enable", "--now", evidenceCorpusAuditorTimer},
		},
		{
			name:     "user running probe",
			op:       systemctlUserRunning,
			wantArgs: []string{"systemctl", "--user", "is-system-running"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd, err := systemctlCommand(t.Context(), tt.op)
			if err != nil {
				t.Fatalf("systemctlCommand(%q): %v", tt.op, err)
			}
			// Element-wise. A joined comparison makes {"enable", "--now"}
			// and {"enable --now"} look identical, which is the difference
			// between two arguments and one.
			if !slices.Equal(cmd.Args, tt.wantArgs) {
				t.Fatalf("args = %q, want %q", cmd.Args, tt.wantArgs)
			}
		})
	}
}

func TestSystemctlCommandRefusesUnknownOperation(t *testing.T) {
	t.Parallel()

	cmd, err := systemctlCommand(t.Context(), systemctlOp("stop pipelock.service"))
	if err == nil {
		t.Fatalf("unknown operation was accepted, built %q", cmd.Args)
	}
	if !strings.Contains(err.Error(), "unsupported systemctl operation") {
		t.Fatalf("error = %v, want an unsupported-operation error", err)
	}
}

// A failing systemctl must surface its combined output, because a silent
// install failure is how an auditor ends up never running.
func TestEvidenceAuditorSystemctlReportsCommandFailure(t *testing.T) {
	originalRun := evidenceAuditorRunCommand
	t.Cleanup(func() { evidenceAuditorRunCommand = originalRun })

	sentinel := errors.New("exit status 1")
	var seen []string
	evidenceAuditorRunCommand = func(cmd *exec.Cmd) ([]byte, error) {
		seen = cmd.Args
		return []byte("Failed to enable unit"), sentinel
	}

	err := runSystemctlOp(context.Background(), systemctlEnableAuditorTimer)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap the command failure", err)
	}
	if !strings.Contains(err.Error(), "Failed to enable unit") {
		t.Fatalf("error = %v, want the combined output included", err)
	}
	if want := []string{"systemctl", "--user", "enable", "--now", evidenceCorpusAuditorTimer}; !slices.Equal(seen, want) {
		t.Fatalf("ran %q, want %q", seen, want)
	}
}

// A permitted operation that succeeds must report success, which is the path
// every real install takes.
func TestEvidenceAuditorSystemctlSucceedsForPermittedOperation(t *testing.T) {
	originalRun := evidenceAuditorRunCommand
	t.Cleanup(func() { evidenceAuditorRunCommand = originalRun })

	var seen []string
	evidenceAuditorRunCommand = func(cmd *exec.Cmd) ([]byte, error) {
		seen = cmd.Args
		return nil, nil
	}

	if err := runSystemctlOp(context.Background(), systemctlDaemonReload); err != nil {
		t.Fatalf("daemon-reload: %v", err)
	}
	if want := []string{"systemctl", "--user", "daemon-reload"}; !slices.Equal(seen, want) {
		t.Fatalf("ran %q, want %q", seen, want)
	}
}

func TestEvidenceAuditorSystemctlRefusesUnknownOperation(t *testing.T) {
	originalRun := evidenceAuditorRunCommand
	t.Cleanup(func() { evidenceAuditorRunCommand = originalRun })

	ran := false
	evidenceAuditorRunCommand = func(*exec.Cmd) ([]byte, error) {
		ran = true
		return nil, nil
	}

	if err := runSystemctlOp(context.Background(), systemctlOp("disable pipelock.service")); err == nil {
		t.Fatal("unknown operation was executed")
	}
	if ran {
		t.Fatal("unknown operation reached the process seam")
	}
}

// The is-system-running probe always reports a *systemctlUserStateError
// carrying the printed state word, including on its "success" exit (state
// "running"): the caller, not this function, decides which states are
// usable, so a nil error here would throw that information away.
func TestEvidenceAuditorSystemctlUserRunningAlwaysReportsState(t *testing.T) {
	originalRun := evidenceAuditorRunCommand
	t.Cleanup(func() { evidenceAuditorRunCommand = originalRun })

	tests := []struct {
		name      string
		output    string
		runErr    error
		wantState string
	}{
		{
			name:      "healthy exit reports running",
			output:    "running\n",
			runErr:    nil,
			wantState: "running",
		},
		{
			name:      "degraded exit is still a reported state",
			output:    "degraded\n",
			runErr:    &exec.ExitError{},
			wantState: "degraded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidenceAuditorRunCommand = func(*exec.Cmd) ([]byte, error) {
				return []byte(tt.output), tt.runErr
			}

			err := runSystemctlOp(context.Background(), systemctlUserRunning)
			var stateErr *systemctlUserStateError
			if !errors.As(err, &stateErr) {
				t.Fatalf("error = %v, want a *systemctlUserStateError", err)
			}
			if stateErr.state != tt.wantState {
				t.Fatalf("state = %q, want %q", stateErr.state, tt.wantState)
			}
			if !strings.Contains(stateErr.Error(), tt.wantState) {
				t.Fatalf("Error() = %q, want it to include the state %q", stateErr.Error(), tt.wantState)
			}
		})
	}
}

// A launch failure that never produced output -- the binary missing, the
// session bus unreachable before systemctl could even print a state word --
// is not a reported state and must not be wrapped as one, or the caller's
// state-word switch would silently treat it as an unrecognized-but-real state
// instead of the launch failure it is.
func TestEvidenceAuditorSystemctlUserRunningReportsLaunchFailureDistinctly(t *testing.T) {
	originalRun := evidenceAuditorRunCommand
	t.Cleanup(func() { evidenceAuditorRunCommand = originalRun })

	sentinel := errors.New("exec: \"systemctl\": executable file not found in $PATH")
	evidenceAuditorRunCommand = func(*exec.Cmd) ([]byte, error) {
		return nil, sentinel
	}

	err := runSystemctlOp(context.Background(), systemctlUserRunning)
	var stateErr *systemctlUserStateError
	if errors.As(err, &stateErr) {
		t.Fatalf("launch failure was wrapped as a state error: %v", stateErr)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap the launch failure", err)
	}
	if !strings.Contains(err.Error(), "systemctl --user is-system-running") {
		t.Fatalf("error = %v, want it to name the probe", err)
	}
}

// No systemctl binary at all (a minimal container image, for example) must be
// reported by name rather than surfacing as a generic probe failure, since it
// is the cheapest and most common reason the auditor is unavailable.
func TestEvidenceAuditorUserSystemdUnavailableWhenSystemctlMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	unavailable, reason := evidenceAuditorUserSystemdUnavailable(context.Background())
	if !unavailable {
		t.Fatal("expected unavailable with no systemctl in PATH")
	}
	if !strings.Contains(reason, "systemctl not found in PATH") {
		t.Fatalf("reason = %q, want it to name the missing binary", reason)
	}
}

// is-system-running can exit non-zero with genuinely empty output (a stub
// init system, or systemctl killed before it could print), which is distinct
// from every named state word and must be reported as such rather than
// falling through to the generic default case's message.
func TestEvidenceAuditorUserSystemdUnavailableWhenProbeReturnsEmptyState(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
		if op == systemctlUserRunning {
			return &systemctlUserStateError{state: ""}
		}
		return nil
	})

	unavailable, reason := evidenceAuditorUserSystemdUnavailable(context.Background())
	if !unavailable {
		t.Fatal("expected unavailable for an empty probe state")
	}
	if !strings.Contains(reason, "returned no result") {
		t.Fatalf("reason = %q, want the no-result message", reason)
	}
}

func recordAuditorWaits(t *testing.T, onWait func(context.Context, time.Duration) error) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	stub(t, &evidenceAuditorWait, func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		if onWait != nil {
			return onWait(ctx, d)
		}
		return nil
	})
	return &waits
}

func assertAuditorWaitDurations(t *testing.T, waits []time.Duration, n int) {
	t.Helper()
	if len(waits) != n {
		t.Fatalf("waits = %d, want %d", len(waits), n)
	}
	for i, d := range waits {
		if d != evidenceAuditorSystemdStartWait {
			t.Fatalf("wait[%d] = %s, want %s", i, d, evidenceAuditorSystemdStartWait)
		}
	}
}

func TestEvidenceAuditorUserSystemdUnavailableRetriesStartingThenRunning(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	waits := recordAuditorWaits(t, nil)

	var probes int
	stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
		if op != systemctlUserRunning {
			return nil
		}
		probes++
		if probes == 1 {
			return &systemctlUserStateError{state: "starting"}
		}
		return &systemctlUserStateError{state: "running"}
	})

	unavailable, reason := evidenceAuditorUserSystemdUnavailable(context.Background())
	if unavailable {
		t.Fatalf("unavailable after starting then running: %s", reason)
	}
	if probes != 2 {
		t.Fatalf("probes = %d, want 2", probes)
	}
	assertAuditorWaitDurations(t, *waits, 1)
}

func TestEvidenceAuditorUserSystemdUnavailableRetriesInitializingThenDegraded(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	waits := recordAuditorWaits(t, nil)

	var probes int
	stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
		if op != systemctlUserRunning {
			return nil
		}
		probes++
		if probes == 1 {
			return &systemctlUserStateError{state: "initializing"}
		}
		return &systemctlUserStateError{state: "degraded"}
	})

	unavailable, reason := evidenceAuditorUserSystemdUnavailable(context.Background())
	if unavailable {
		t.Fatalf("unavailable after initializing then degraded: %s", reason)
	}
	if probes != 2 {
		t.Fatalf("probes = %d, want 2", probes)
	}
	assertAuditorWaitDurations(t, *waits, 1)
}

func TestEvidenceAuditorUserSystemdUnavailableGivesUpAfterStartingBudget(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	waits := recordAuditorWaits(t, nil)

	var probes int
	stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
		if op != systemctlUserRunning {
			return nil
		}
		probes++
		return &systemctlUserStateError{state: "starting"}
	})

	unavailable, reason := evidenceAuditorUserSystemdUnavailable(context.Background())
	if !unavailable {
		t.Fatal("expected unavailable after the starting budget")
	}
	if !strings.Contains(reason, `"starting"`) {
		t.Fatalf("reason = %q, want it to name starting", reason)
	}
	want := evidenceAuditorSystemdStartRetries + 1
	if probes != want {
		t.Fatalf("probes = %d, want %d", probes, want)
	}
	assertAuditorWaitDurations(t, *waits, evidenceAuditorSystemdStartRetries)
}

func TestEvidenceAuditorUserSystemdUnavailableDoesNotRetryOffline(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	var waits int
	stub(t, &evidenceAuditorWait, func(context.Context, time.Duration) error {
		waits++
		return nil
	})
	var probes int
	stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
		if op != systemctlUserRunning {
			return nil
		}
		probes++
		return &systemctlUserStateError{state: "offline"}
	})

	unavailable, reason := evidenceAuditorUserSystemdUnavailable(context.Background())
	if !unavailable {
		t.Fatal("expected unavailable for offline")
	}
	if !strings.Contains(reason, `"offline"`) {
		t.Fatalf("reason = %q, want it to name offline", reason)
	}
	if probes != 1 {
		t.Fatalf("probes = %d, want 1", probes)
	}
	if waits != 0 {
		t.Fatalf("waits = %d, want 0", waits)
	}
}

func TestEvidenceAuditorUserSystemdUnavailableDoesNotRetryMissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var waits int
	stub(t, &evidenceAuditorWait, func(context.Context, time.Duration) error {
		waits++
		return nil
	})
	var probes int
	stub(t, &evidenceAuditorSystemctl, func(context.Context, systemctlOp) error {
		probes++
		return &systemctlUserStateError{state: "starting"}
	})

	unavailable, reason := evidenceAuditorUserSystemdUnavailable(context.Background())
	if !unavailable {
		t.Fatal("expected unavailable with no systemctl in PATH")
	}
	if !strings.Contains(reason, "systemctl not found in PATH") {
		t.Fatalf("reason = %q, want the missing-binary message", reason)
	}
	if probes != 0 || waits != 0 {
		t.Fatalf("probes=%d waits=%d, want 0 and 0", probes, waits)
	}
}

func TestEvidenceAuditorWaitZeroDurationAndCancel(t *testing.T) {
	if err := evidenceAuditorWait(context.Background(), 0); err != nil {
		t.Fatalf("zero duration: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := evidenceAuditorWait(ctx, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled wait error = %v, want context.Canceled", err)
	}
	if err := evidenceAuditorWait(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("short wait: %v", err)
	}
}

func TestEvidenceAuditorUserSystemdUnavailableWaitCancel(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	waits := recordAuditorWaits(t, func(ctx context.Context, _ time.Duration) error {
		return ctx.Err()
	})
	var probes int
	stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
		if op != systemctlUserRunning {
			return nil
		}
		probes++
		return &systemctlUserStateError{state: "starting"}
	})
	unavailable, reason := evidenceAuditorUserSystemdUnavailable(ctx)
	if !unavailable {
		t.Fatal("expected unavailable when wait is canceled")
	}
	if !strings.Contains(reason, "unusable") {
		t.Fatalf("reason = %q, want unusable", reason)
	}
	if probes != 1 {
		t.Fatalf("probes = %d, want 1 (cancel during the first wait, not another probe)", probes)
	}
	assertAuditorWaitDurations(t, *waits, 1)
}
