// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
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
	// The plan must read as a plan. The bare disclosure opens with
	// "Installing", which is false under --dry-run, so the dry-run surface
	// rewrites that opening rather than prefixing it.
	if !strings.Contains(out, "Would install "+evidenceCorpusAuditorTimer+":") {
		t.Fatalf("dry run must print the plan, not perform it\noutput:\n%s", out)
	}
	if strings.Contains(out, "Installing "+evidenceCorpusAuditorTimer) {
		t.Fatalf("dry run claimed an install was happening\noutput:\n%s", out)
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

// --json previously suppressed the disclosure entirely and emitted its JSON
// only after the unit was already enabled, so the machine-readable mode
// installed a timer having named it nowhere beforehand. The disclosure now
// goes to stderr: stdout stays a single valid JSON document, and the consent
// contract holds on both surfaces.
func TestInitAuditorJSONDisclosesOnStderrAndKeepsStdoutValidJSON(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the auditor is installed only on linux")
	}

	home := t.TempDir()
	var out, errOut bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", filepath.Join(home, "cfg", "pipelock.yaml"),
		"--json",
		"--skip-canary",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errOut.String())
	}

	if !strings.Contains(errOut.String(), evidenceAuditorDisclosure) {
		t.Fatalf("--json must still disclose before installing\nstderr:\n%s", errOut.String())
	}
	if strings.Contains(out.String(), evidenceAuditorDisclosure) {
		t.Fatalf("the disclosure must not pollute the JSON document\nstdout:\n%s", out.String())
	}

	var result initResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not a single valid JSON document: %v\nstdout:\n%s", err, out.String())
	}
	if result.Auditor == nil || result.Auditor.Status != auditorStatusInstalled {
		t.Fatalf("auditor status = %+v, want %q", result.Auditor, auditorStatusInstalled)
	}
}

// An existing config that configures no flight_recorder.dir leaves nothing to
// audit. That path used to return no auditor result at all, so the summary and
// the JSON both went silent and "not installed" was invisible to the operator.
func TestInitAuditorExistingConfigWithoutRecorderDirReportsSkip(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the auditor is installed only on linux")
	}
	stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
		if op == systemctlUserRunning {
			return &systemctlUserStateError{state: "running"}
		}
		t.Fatalf("no unit should be installed when there is no recorder directory (op %q)", op)
		return nil
	})

	home := t.TempDir()
	configPath := filepath.Join(home, "pipelock.yaml")
	if err := os.WriteFile(configPath, []byte("mode: audit\n"), 0o600); err != nil {
		t.Fatalf("seed existing config: %v", err)
	}

	var out bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", configPath,
		"--skip-canary",
		"--skip-validate",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v\noutput:\n%s", err, out.String())
	}

	if !strings.Contains(out.String(), "Evidence auditor:   skipped (") {
		t.Fatalf("summary must name the auditor outcome even when it no-ops\noutput:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "no flight_recorder.dir") {
		t.Fatalf("the skip must say why\noutput:\n%s", out.String())
	}
}

// Ordering has to be asserted at the moment the installer is ENTERED. The
// installer writes every managed file before it ever calls systemctl, so
// comparing the disclosure against the post-install confirmation (or against
// the systemctl seam) still passes if the disclosure is printed after the
// first file has already landed -- which is exactly the contract this feature
// exists to hold.
func TestInitAuditorDisclosurePrecedesTheInstallerItself(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the auditor is installed only on linux")
	}

	var seen string
	var out bytes.Buffer
	stub(t, &evidenceAuditorInstall, func(context.Context, string) (evidenceCorpusAuditorInstall, error) {
		seen = out.String()
		return evidenceCorpusAuditorInstall{TimerPath: "/tmp/fake.timer"}, nil
	})

	home := t.TempDir()
	cmd := InitCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", filepath.Join(home, "cfg", "pipelock.yaml"),
		"--skip-canary",
		"--skip-validate",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init failed: %v\noutput:\n%s", err, out.String())
	}

	if seen == "" {
		t.Fatal("the installer seam never ran, so ordering was not exercised")
	}
	if !strings.Contains(seen, evidenceAuditorDisclosure) {
		t.Fatalf("the installer was entered before the disclosure was printed\noutput at installer entry:\n%s", seen)
	}
}

// A cancelled context kills the probe process, which returns an
// *exec.ExitError. Treating that as a state result reported an empty state,
// which the caller turns into a "no usable systemd session" skip -- so an
// interrupted init silently claimed the host had no systemd.
func TestEvidenceAuditorProbeReportsCancellationNotAnEmptyState(t *testing.T) {
	originalRun := evidenceAuditorRunCommand
	t.Cleanup(func() { evidenceAuditorRunCommand = originalRun })
	evidenceAuditorRunCommand = func(*exec.Cmd) ([]byte, error) {
		return nil, &exec.ExitError{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runSystemctlOp(ctx, systemctlUserRunning)
	var stateErr *systemctlUserStateError
	if errors.As(err, &stateErr) {
		t.Fatalf("cancellation was reported as state %q instead of a cancellation", stateErr.state)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want it to wrap context.Canceled", err)
	}

	// And the decision layer must not turn it into a skip.
	stub(t, &evidenceAuditorSystemctl, runSystemctlOp)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	unavailable, reason := evidenceAuditorUserSystemdUnavailable(ctx)
	if !unavailable {
		t.Fatal("a cancelled probe must not report a usable session")
	}
	if strings.Contains(reason, "returned no result") {
		t.Fatalf("cancellation was misreported as an empty probe state: %q", reason)
	}
}

// Fixing the cancellation swallow inside runSystemctlOp was not enough: the
// decision layer took any "unavailable" answer, cancellation included, and
// turned it into a clean skip with a nil error, so an interrupted init exited
// zero claiming the host had no user systemd session.
func TestInitCancelledProbeFailsRatherThanSkipping(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the auditor is installed only on linux")
	}
	stub(t, &evidenceAuditorSystemctl, runSystemctlOp)
	originalRun := evidenceAuditorRunCommand
	t.Cleanup(func() { evidenceAuditorRunCommand = originalRun })
	evidenceAuditorRunCommand = func(*exec.Cmd) ([]byte, error) { return nil, &exec.ExitError{} }
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	home := t.TempDir()
	var out bytes.Buffer
	cmd := InitCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--scan-home", home,
		"--output", filepath.Join(home, "cfg", "pipelock.yaml"),
		"--skip-canary",
		"--skip-validate",
	})

	err := cmd.ExecuteContext(ctx)
	if err == nil {
		t.Fatalf("a cancelled init reported success\noutput:\n%s", out.String())
	}
	if strings.Contains(out.String(), "Evidence corpus auditor: skipped") {
		t.Fatalf("cancellation was reported as a clean skip\noutput:\n%s", out.String())
	}
}
