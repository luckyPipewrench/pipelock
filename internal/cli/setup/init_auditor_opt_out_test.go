// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runInitForAuditorTest runs `pipelock init` with an isolated scan-home and
// output path and returns the combined stdout/stderr buffer and the error.
func runInitForAuditorTest(t *testing.T, extraArgs ...string) (string, error) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the auditor is installed only on linux")
	}

	home := t.TempDir()
	var buf bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	args := append([]string{
		"--scan-home", home,
		"--output", filepath.Join(home, "cfg", "pipelock.yaml"),
		"--skip-canary",
	}, extraArgs...)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// Default interactive path: the disclosure must appear before the install
// takes effect, and the summary reports the auditor as installed.
func TestInitAuditorDefaultDisclosesBeforeInstall(t *testing.T) {
	out, err := runInitForAuditorTest(t)
	if err != nil {
		t.Fatalf("init failed: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, evidenceAuditorDisclosure) {
		t.Fatalf("output missing disclosure line %q\noutput:\n%s", evidenceAuditorDisclosure, out)
	}
	discloseAt := strings.Index(out, evidenceAuditorDisclosure)
	installedAt := strings.Index(out, "Evidence corpus auditor timer installed:")
	if installedAt == -1 {
		t.Fatalf("output missing install confirmation\noutput:\n%s", out)
	}
	if discloseAt > installedAt {
		t.Fatalf("disclosure printed after install confirmation\noutput:\n%s", out)
	}
	if !strings.Contains(out, "Evidence auditor:   installed") {
		t.Fatalf("summary missing installed state\noutput:\n%s", out)
	}
}

// The disclosure must appear even when the subsequent install call fails,
// proving the print happens strictly BEFORE the enable attempt rather than
// only after a successful one.
func TestInitAuditorDisclosurePrintedEvenWhenEnableFails(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the auditor is installed only on linux")
	}
	stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
		if op == systemctlEnableAuditorTimer {
			return errors.New("simulated enable failure")
		}
		return nil
	})

	out, err := runInitForAuditorTest(t)
	if err == nil {
		t.Fatalf("expected init to fail when enabling the timer fails\noutput:\n%s", out)
	}
	if !strings.Contains(out, evidenceAuditorDisclosure) {
		t.Fatalf("disclosure must be printed before the failed enable call\noutput:\n%s", out)
	}
}

// "degraded" is the common ordinary-desktop state (some unrelated user unit
// failed) and must NOT be treated as unusable: the auditor installs normally,
// disclosure included.
func TestInitDegradedUserSystemdStillInstalls(t *testing.T) {
	stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
		if op == systemctlUserRunning {
			return &systemctlUserStateError{state: "degraded"}
		}
		return nil
	})

	out, err := runInitForAuditorTest(t)
	if err != nil {
		t.Fatalf("init failed on a degraded-but-usable session: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, evidenceAuditorDisclosure) {
		t.Fatalf("degraded session must still get the disclosure and install\noutput:\n%s", out)
	}
	if !strings.Contains(out, "Evidence auditor:   installed") {
		t.Fatalf("summary missing installed state for a degraded session\noutput:\n%s", out)
	}
}

// A recognized-but-not-usable state word ("offline") skips gracefully, same
// as an unrecognized word or a launch failure.
func TestInitOfflineUserSystemdSkipsWithoutFailing(t *testing.T) {
	stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
		if op == systemctlUserRunning {
			return &systemctlUserStateError{state: "offline"}
		}
		t.Fatalf("unexpected systemctl call for op %q after the probe should have skipped", op)
		return nil
	})

	out, err := runInitForAuditorTest(t)
	if err != nil {
		t.Fatalf("init must not fail for an offline user session: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, `systemctl --user reports "offline"`) {
		t.Fatalf("output missing the offline-state notice\noutput:\n%s", out)
	}
}

func TestInitNoAuditorFlagInstallsNothing(t *testing.T) {
	stub(t, &evidenceAuditorSystemctl, func(context.Context, systemctlOp) error {
		t.Fatal("no systemctl call should happen with --no-auditor")
		return nil
	})

	out, err := runInitForAuditorTest(t, "--no-auditor")
	if err != nil {
		t.Fatalf("init failed: %v\noutput:\n%s", err, out)
	}
	if strings.Contains(out, evidenceAuditorDisclosure) {
		t.Fatalf("--no-auditor must not print the install disclosure\noutput:\n%s", out)
	}
	if !strings.Contains(out, "Evidence auditor:   skipped (--no-auditor)") {
		t.Fatalf("summary missing skipped-by-flag state\noutput:\n%s", out)
	}
}

func TestInitDryRunInstallsNothingAndPrintsPlan(t *testing.T) {
	stub(t, &evidenceAuditorSystemctl, func(context.Context, systemctlOp) error {
		t.Fatal("no systemctl call should happen under --dry-run")
		return nil
	})

	out, err := runInitForAuditorTest(t, "--dry-run")
	if err != nil {
		t.Fatalf("init failed: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "Would install evidence corpus auditor: "+evidenceAuditorDisclosure) {
		t.Fatalf("dry run must print the plan, not perform it\noutput:\n%s", out)
	}
	if !strings.Contains(out, "Evidence auditor:   skipped (dry run)") {
		t.Fatalf("summary missing dry-run skipped state\noutput:\n%s", out)
	}
}

// No systemd --user session (e.g. a container with no session bus): init must
// skip with a printed notice and still exit 0, not fail.
func TestInitNoUserSystemdSkipsWithoutFailing(t *testing.T) {
	stub(t, &evidenceAuditorSystemctl, func(context.Context, systemctlOp) error {
		t.Fatal("no systemctl call should happen when no user session is detected")
		return nil
	})
	t.Setenv("XDG_RUNTIME_DIR", "")

	out, err := runInitForAuditorTest(t)
	if err != nil {
		t.Fatalf("init must not fail when there is no user systemd session: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "Evidence corpus auditor: skipped (no user systemd session") {
		t.Fatalf("output missing the no-user-systemd notice\noutput:\n%s", out)
	}
	if !strings.Contains(out, "Evidence auditor:   skipped (no user systemd session") {
		t.Fatalf("summary missing skipped-no-systemd state\noutput:\n%s", out)
	}
}

// systemctl present but the user session is unusable (probe fails): same
// graceful skip, not a hard failure.
func TestInitUnusableUserSystemdSkipsWithoutFailing(t *testing.T) {
	stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
		if op == systemctlUserRunning {
			return errors.New("dial unix /run/user/1000/bus: connect: no such file or directory")
		}
		t.Fatalf("unexpected systemctl call for op %q after the probe should have skipped", op)
		return nil
	})

	out, err := runInitForAuditorTest(t)
	if err != nil {
		t.Fatalf("init must not fail when systemctl --user is unusable: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "Evidence corpus auditor: skipped (systemctl --user is unusable") {
		t.Fatalf("output missing the unusable-session notice\noutput:\n%s", out)
	}
}

// Systemd present but the enable call genuinely fails (not an availability
// problem): init reports it honestly and fails, matching how the pre-existing
// TestInitCmdFailsWhenAuditorInstallFails treats an install failure elsewhere
// in this same phase - a real failure must not be silently downgraded to a skip.
func TestInitAuditorEnableFailureIsReportedNotSkipped(t *testing.T) {
	stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
		if op == systemctlEnableAuditorTimer {
			return errors.New("Failed to enable unit: Unit not found")
		}
		return nil
	})

	out, err := runInitForAuditorTest(t)
	if err == nil {
		t.Fatalf("expected init to fail when the timer cannot be enabled\noutput:\n%s", out)
	}
	if !strings.Contains(err.Error(), "installing evidence corpus auditor") {
		t.Fatalf("error = %v, want it to name the auditor install step", err)
	}
}
