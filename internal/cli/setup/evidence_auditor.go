// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	evidenceCorpusAuditorService = "pipelock-evidence-corpus-auditor.service"
	evidenceCorpusAuditorTimer   = "pipelock-evidence-corpus-auditor.timer"
	evidenceCorpusAuditorAlert   = "pipelock-evidence-corpus-alerts.yaml"
	managedEvidenceAuditorHeader = "# Managed by pipelock init; local edits will be replaced on rerun.\n"
)

// evidenceAuditorDisclosure is printed before pipelock init installs the
// auditor, so nothing lands on a user's system without being named first.
const evidenceAuditorDisclosure = "Installing " + evidenceCorpusAuditorTimer +
	": runs 'pipelock evidence doctor' every 15 minutes against your flight recorder directory and exports a Prometheus metric; disable it with 'systemctl --user disable --now " + evidenceCorpusAuditorTimer + "', which stops it and leaves the generated unit, alert and metric files in place."

var (
	evidenceAuditorUserConfigDir = os.UserConfigDir
	evidenceAuditorExecutable    = os.Executable
	// evidenceAuditorRunCommand is the only seam that touches a real process.
	// Keeping it to one line leaves systemctlCommand below directly testable.
	evidenceAuditorRunCommand = func(cmd *exec.Cmd) ([]byte, error) { return cmd.CombinedOutput() }

	evidenceAuditorSystemctl = runSystemctlOp
)

// runSystemctlOp is the real implementation behind evidenceAuditorSystemctl.
// It is named rather than anonymous so tests can exercise it directly, since
// the package's TestMain replaces the variable with a no-op for install tests.
func runSystemctlOp(ctx context.Context, op systemctlOp) error {
	cmd, err := systemctlCommand(ctx, op)
	if err != nil {
		return err
	}
	output, runErr := evidenceAuditorRunCommand(cmd)
	if op == systemctlUserRunning {
		// is-system-running prints a single state word and exits non-zero for
		// every state except "running" (including the common, harmless
		// "degraded" caused by an unrelated failed unit elsewhere on the
		// system), so its exit code alone carries no usable signal here.
		// Report the state word itself and let the caller decide which
		// states count as a usable session; only a launch failure that never
		// produced output (missing binary, unreachable bus, etc.) is a bare
		// error.
		if runErr != nil {
			// A cancelled context kills the process, which surfaces as an
			// *exec.ExitError. Classifying that as a state result would report
			// an empty state, which the caller reads as "no usable session"
			// and turns into a silent skip -- so an interrupted init would
			// claim the host has no systemd instead of reporting the
			// cancellation. Check the context before trusting the exit shape.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return fmt.Errorf("systemctl --user %s: %w", op, ctxErr)
			}
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) {
				return fmt.Errorf("systemctl --user %s: %w", op, runErr)
			}
		}
		return &systemctlUserStateError{state: strings.TrimSpace(string(output))}
	}
	if runErr != nil {
		return fmt.Errorf("systemctl --user %s: %w: %s", op, runErr, strings.TrimSpace(string(output)))
	}
	return nil
}

// systemctlUserStateError carries the state word printed by
// `systemctl --user is-system-running`. It is always returned for that probe
// (never nil), even for the healthy "running" state, so evidenceAuditorSystemctl's
// plain `error` return still gives evidenceAuditorUserSystemdUnavailable enough
// information to distinguish "running"/"degraded" (usable) from every other
// state (not usable) without a second seam.
type systemctlUserStateError struct{ state string }

func (e *systemctlUserStateError) Error() string {
	return fmt.Sprintf("systemctl --user is-system-running: %q", e.state)
}

// systemctlCommand builds the argument vector for one permitted operation.
// Every argument is a literal or a package constant, so this installer exposes
// no command or argument surface at all, and an unrecognized operation is
// refused rather than passed through. Taking an operation rather than variadic
// strings is what makes that true by construction instead of by convention.
func systemctlCommand(ctx context.Context, op systemctlOp) (*exec.Cmd, error) {
	switch op {
	case systemctlDaemonReload:
		return exec.CommandContext(ctx, "systemctl", "--user", "daemon-reload"), nil
	case systemctlEnableAuditorTimer:
		return exec.CommandContext(ctx, "systemctl", "--user", "enable", "--now", evidenceCorpusAuditorTimer), nil
	case systemctlUserRunning:
		return exec.CommandContext(ctx, "systemctl", "--user", "is-system-running"), nil
	default:
		return nil, fmt.Errorf("unsupported systemctl operation %q", op)
	}
}

// systemctlOp is the closed set of systemctl operations the evidence auditor
// installer may perform. A closed set keeps the subprocess argument vector
// entirely compile-time constant.
type systemctlOp string

const (
	systemctlDaemonReload       systemctlOp = "daemon-reload"
	systemctlEnableAuditorTimer systemctlOp = "enable --now " + evidenceCorpusAuditorTimer
	// systemctlUserRunning is a read-only probe used only to decide whether a
	// user systemd session exists at all before attempting an install.
	systemctlUserRunning systemctlOp = "is-system-running"
)

// evidenceAuditorUserSystemdUnavailable reports whether this host has no
// usable systemd --user session, and why, so init can skip the auditor with a
// printed notice instead of failing outright. Checked in order from cheapest
// to most expensive: missing binary, missing runtime dir (the standard signal
// that no user session/session bus exists), then a live probe.
//
// "running" and "degraded" both count as usable: `is-system-running` exits
// non-zero for "degraded" whenever ANY unrelated user unit has failed, which
// is common on ordinary desktops and has nothing to do with whether this
// timer can be installed and run. Every other state - "offline", "unknown",
// an empty result, "initializing"/"starting", or a non-zero exit with no
// recognized state word at all - is treated as not usable, same as a launch
// failure (missing binary, unreachable session bus).
func evidenceAuditorUserSystemdUnavailable(ctx context.Context) (bool, string) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return true, "systemctl not found in PATH"
	}
	if strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")) == "" {
		return true, "no user systemd session (XDG_RUNTIME_DIR is not set)"
	}
	err := evidenceAuditorSystemctl(ctx, systemctlUserRunning)
	if err == nil {
		return false, "" // fake/success path (e.g. TestMain's global stub): treat as "running".
	}
	var stateErr *systemctlUserStateError
	if errors.As(err, &stateErr) {
		switch stateErr.state {
		case "running", "degraded":
			return false, ""
		case "":
			return true, "systemctl --user is-system-running returned no result"
		default:
			return true, fmt.Sprintf("systemctl --user reports %q", stateErr.state)
		}
	}
	return true, fmt.Sprintf("systemctl --user is unusable: %v", err)
}

type evidenceCorpusAuditorInstall struct {
	ServicePath string
	TimerPath   string
	AlertPath   string
	MetricPath  string
}

// installEvidenceCorpusAuditor installs the out-of-process corpus check. Its
// result is exported through a Prometheus textfile collector, not the proxy's
// in-memory registry, so a damaged historical branch cannot gate traffic.
func installEvidenceCorpusAuditor(ctx context.Context, recorderDir string) (evidenceCorpusAuditorInstall, error) {
	if strings.TrimSpace(recorderDir) == "" {
		return evidenceCorpusAuditorInstall{}, fmt.Errorf("evidence corpus auditor needs a configured flight_recorder.dir")
	}
	configDir, err := evidenceAuditorUserConfigDir()
	if err != nil {
		return evidenceCorpusAuditorInstall{}, fmt.Errorf("determining user config directory for evidence corpus auditor: %w", err)
	}
	pipelockPath, err := evidenceAuditorExecutable()
	if err != nil {
		return evidenceCorpusAuditorInstall{}, fmt.Errorf("resolving pipelock executable for evidence corpus auditor: %w", err)
	}
	configDir = filepath.Clean(configDir)
	install := evidenceCorpusAuditorInstall{
		ServicePath: filepath.Join(configDir, "systemd", "user", evidenceCorpusAuditorService),
		TimerPath:   filepath.Join(configDir, "systemd", "user", evidenceCorpusAuditorTimer),
		AlertPath:   filepath.Join(configDir, "pipelock", "prometheus", "rules", evidenceCorpusAuditorAlert),
		MetricPath:  filepath.Join(configDir, "pipelock", "prometheus", "textfile", "pipelock_evidence_corpus.prom"),
	}
	renderedFiles := []struct {
		path string
		body string
	}{
		{install.ServicePath, renderEvidenceCorpusAuditorService(pipelockPath, recorderDir, install.MetricPath)},
		{install.TimerPath, renderEvidenceCorpusAuditorTimer()},
		{install.AlertPath, renderEvidenceCorpusAuditorAlert()},
	}
	// Validate the whole managed set before replacing anything. In particular,
	// init may be running from a temporary binary with a temporary recorder
	// directory; replacing a durable service with that target makes its next
	// timer run silently stop producing fresh evidence.
	for _, rendered := range renderedFiles {
		if err := validateManagedEvidenceAuditorFile(rendered.path, rendered.body); err != nil {
			return evidenceCorpusAuditorInstall{}, err
		}
	}
	if err := validateEvidenceCorpusAuditorServiceTarget(renderedFiles[0].path, renderedFiles[0].body); err != nil {
		return evidenceCorpusAuditorInstall{}, err
	}
	for _, rendered := range renderedFiles {
		if err := writeManagedEvidenceAuditorFile(rendered.path, rendered.body); err != nil {
			return evidenceCorpusAuditorInstall{}, err
		}
	}
	if err := evidenceAuditorSystemctl(ctx, systemctlDaemonReload); err != nil {
		return evidenceCorpusAuditorInstall{}, fmt.Errorf("reloading evidence corpus auditor unit: %w", err)
	}
	if err := evidenceAuditorSystemctl(ctx, systemctlEnableAuditorTimer); err != nil {
		return evidenceCorpusAuditorInstall{}, fmt.Errorf("enabling evidence corpus auditor timer: %w", err)
	}
	return install, nil
}

func writeManagedEvidenceAuditorFile(path, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating evidence corpus auditor directory: %w", err)
	}
	if existing, err := os.ReadFile(filepath.Clean(path)); err == nil && string(existing) == body {
		return nil
	}
	if err := validateManagedEvidenceAuditorFile(path, body); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("writing evidence corpus auditor file %s: %w", path, err)
	}
	return nil
}

func validateManagedEvidenceAuditorFile(path, body string) error {
	if existing, err := os.ReadFile(filepath.Clean(path)); err == nil {
		if string(existing) == body {
			return nil
		}
		if !strings.HasPrefix(string(existing), managedEvidenceAuditorHeader) {
			return fmt.Errorf("refusing to overwrite unmanaged evidence corpus auditor file %s", path)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading evidence corpus auditor file %s: %w", path, err)
	}
	return nil
}

func validateEvidenceCorpusAuditorServiceTarget(path, desired string) error {
	existing, err := os.ReadFile(filepath.Clean(path))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading evidence corpus auditor file %s: %w", path, err)
	}
	if !strings.HasPrefix(string(existing), managedEvidenceAuditorHeader) {
		return fmt.Errorf("refusing to overwrite unmanaged evidence corpus auditor file %s", path)
	}
	desiredTarget, ok := evidenceCorpusAuditorServiceTarget(desired)
	if !ok {
		return fmt.Errorf("rendering evidence corpus auditor service target for %s", path)
	}
	existingTarget, ok := evidenceCorpusAuditorServiceTarget(string(existing))
	if !ok {
		return fmt.Errorf("refusing to replace managed evidence corpus auditor service %s because its executable and flight recorder directory cannot be determined", path)
	}
	if existingTarget != desiredTarget {
		return fmt.Errorf("refusing to replace managed evidence corpus auditor service target in %s; rerun the binary and flight_recorder.dir already configured there; to migrate, stop %s with systemctl --user, update this service's ExecStart to the intended binary and recorder directory, run systemctl --user daemon-reload, then rerun init", path, evidenceCorpusAuditorTimer)
	}
	return nil
}

func evidenceCorpusAuditorServiceTarget(service string) (string, bool) {
	for _, line := range strings.Split(service, "\n") {
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		textfileFlag := strings.LastIndex(line, " --prometheus-textfile ")
		if textfileFlag == -1 {
			return "", false
		}
		return line[:textfileFlag], true
	}
	return "", false
}

func renderEvidenceCorpusAuditorService(pipelockPath, recorderDir, metricPath string) string {
	return managedEvidenceAuditorHeader + "[Unit]\nDescription=Pipelock whole-corpus evidence integrity audit\n\n[Service]\nType=oneshot\nExecStart=" + systemdArgument(pipelockPath) + " evidence doctor " + systemdArgument(recorderDir) + " --prometheus-textfile " + systemdArgument(metricPath) + "\n"
}

func renderEvidenceCorpusAuditorTimer() string {
	return managedEvidenceAuditorHeader + "[Unit]\nDescription=Run the Pipelock whole-corpus evidence integrity audit\n\n[Timer]\nOnBootSec=5m\nOnUnitActiveSec=15m\nPersistent=true\nUnit=" + evidenceCorpusAuditorService + "\n\n[Install]\nWantedBy=timers.target\n"
}

func renderEvidenceCorpusAuditorAlert() string {
	return managedEvidenceAuditorHeader + "groups:\n  - name: pipelock-evidence-corpus\n    rules:\n      - alert: PipelockEvidenceCorpusIntegrityFailed\n        expr: absent(pipelock_evidence_corpus_integrity_ok) or absent(pipelock_evidence_corpus_last_audit_timestamp_seconds) or pipelock_evidence_corpus_integrity_ok != 1 or time() - pipelock_evidence_corpus_last_audit_timestamp_seconds > 1800\n        for: 0m\n        labels:\n          severity: critical\n        annotations:\n          summary: Pipelock evidence corpus integrity audit failed\n          description: The whole-corpus evidence auditor found structural damage, could not complete a scan, or has not reported within 30 minutes. Proxy traffic remains independent. Treat this corpus as unverified for any evidence already published or handed to an auditor, and run 'pipelock evidence doctor DIR' to locate the damage.\n"
}

func systemdArgument(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "%", "%%",
		"\a", "\\a", "\b", "\\b", "\f", "\\f", "\n", "\\n", "\r", "\\r", "\t", "\\t", "\v", "\\v")
	return "\"" + replacer.Replace(value) + "\""
}
