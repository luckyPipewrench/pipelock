// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInitCmdInstallsEvidenceCorpusAuditorWithRenderedConsumer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("init installs the auditor only on linux")
	}

	home := t.TempDir()
	configPath := filepath.Join(home, "cfg", "pipelock.yaml")
	cmd := InitCmd()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--scan-home", home, "--output", configPath, "--skip-canary", "--skip-validate"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	configDir, err := evidenceAuditorUserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	servicePath := filepath.Join(configDir, "systemd", "user", evidenceCorpusAuditorService)
	timerPath := filepath.Join(configDir, "systemd", "user", evidenceCorpusAuditorTimer)
	alertPath := filepath.Join(configDir, "pipelock", "prometheus", "rules", evidenceCorpusAuditorAlert)
	metricPath := filepath.Join(configDir, "pipelock", "prometheus", "textfile", "pipelock_evidence_corpus.prom")

	assertRenderedFileContains(t, servicePath,
		"Type=oneshot",
		"evidence doctor",
		"--prometheus-textfile",
		metricPath,
	)
	assertRenderedFileContains(t, timerPath,
		"OnUnitActiveSec=15m",
		"Persistent=true",
		"Unit="+evidenceCorpusAuditorService,
		"WantedBy=timers.target",
	)
	assertRenderedFileContains(t, alertPath,
		"alert: PipelockEvidenceCorpusIntegrityFailed",
		"pipelock_evidence_corpus_integrity_ok != 1",
		"pipelock_evidence_corpus_last_audit_timestamp_seconds",
	)
}

func TestEvidenceCorpusAuditorRenderersQuotePathsAndRemainOutOfBand(t *testing.T) {
	service := renderEvidenceCorpusAuditorService("/opt/Pipe Lock/pipelock", "/var/lib/pipelock/evidence corpus", "/var/lib/node exporter/pipelock.prom")
	if !strings.Contains(service, `ExecStart="/opt/Pipe Lock/pipelock" evidence doctor "/var/lib/pipelock/evidence corpus" --prometheus-textfile "/var/lib/node exporter/pipelock.prom"`) {
		t.Fatalf("service did not quote rendered arguments:\n%s", service)
	}
	alert := renderEvidenceCorpusAuditorAlert()
	if strings.Contains(alert, "require_receipts") || strings.Contains(alert, "local_recorder_operational") {
		t.Fatalf("corpus alert must not be wired to request gating or process-local health:\n%s", alert)
	}
	if strings.Contains(alert, "current_ael") {
		t.Fatalf("corpus alert must not aggregate the mixed-version legacy AEL series:\n%s", alert)
	}
}

func TestEvidenceCorpusAuditorRerunRepairsManagedTimerButRefusesUnmanagedFile(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "pipelock.yaml")
	runInitForEvidenceAuditorTest(t, home, configPath)
	configDir, err := evidenceAuditorUserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	timerPath := filepath.Join(configDir, "systemd", "user", evidenceCorpusAuditorTimer)
	if err := os.WriteFile(timerPath, []byte(managedEvidenceAuditorHeader+"broken\n"), 0o600); err != nil {
		t.Fatalf("damage managed timer: %v", err)
	}
	runInitForEvidenceAuditorTest(t, home, configPath)
	assertRenderedFileContains(t, timerPath, "OnUnitActiveSec=15m", "Persistent=true")

	servicePath := filepath.Join(configDir, "systemd", "user", evidenceCorpusAuditorService)
	defer func() {
		if err := os.WriteFile(servicePath, []byte(renderEvidenceCorpusAuditorService("/usr/bin/pipelock", filepath.Join(home, "recorder"), filepath.Join(configDir, "pipelock", "prometheus", "textfile", "pipelock_evidence_corpus.prom"))), 0o600); err != nil {
			t.Errorf("restore managed service: %v", err)
		}
	}()
	if err := os.WriteFile(servicePath, []byte("[Service]\nExecStart=/operator/custom\n"), 0o600); err != nil {
		t.Fatalf("write unmanaged service: %v", err)
	}
	if _, err := installEvidenceCorpusAuditor(t.Context(), filepath.Join(home, "recorder")); err == nil {
		t.Fatal("unmanaged service was overwritten")
	}
}

func runInitForEvidenceAuditorTest(t *testing.T, home, configPath string) {
	t.Helper()
	cmd := InitCmd()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--scan-home", home, "--output", configPath, "--skip-canary", "--skip-validate"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}
}

func assertRenderedFileContains(t *testing.T, path string, wants ...string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read rendered %s: %v", path, err)
	}
	for _, want := range wants {
		if !strings.Contains(string(data), want) {
			t.Fatalf("rendered %s missing %q:\n%s", path, want, data)
		}
	}
}
