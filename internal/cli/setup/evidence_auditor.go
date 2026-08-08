// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
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
	if output, err := evidenceAuditorRunCommand(cmd); err != nil {
		return fmt.Errorf("systemctl --user %s: %w: %s", op, err, strings.TrimSpace(string(output)))
	}
	return nil
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
)

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
	for _, rendered := range []struct {
		path string
		body string
	}{
		{install.ServicePath, renderEvidenceCorpusAuditorService(pipelockPath, recorderDir, install.MetricPath)},
		{install.TimerPath, renderEvidenceCorpusAuditorTimer()},
		{install.AlertPath, renderEvidenceCorpusAuditorAlert()},
	} {
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
	data := []byte(body)
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
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing evidence corpus auditor file %s: %w", path, err)
	}
	return nil
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
	replacer := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "%", "%%")
	return "\"" + replacer.Replace(value) + "\""
}
