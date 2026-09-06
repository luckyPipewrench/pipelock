// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"context"
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

	configDir := isolatedEvidenceAuditorInstall(t)
	home := t.TempDir()
	configPath := filepath.Join(home, "cfg", "pipelock.yaml")
	cmd := InitCmd()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--scan-home", home, "--output", configPath, "--skip-canary", "--skip-validate"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
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

func TestEvidenceCorpusAuditorServiceTargetKeepsQuotedTargetPaths(t *testing.T) {
	service := renderEvidenceCorpusAuditorService(
		"/opt/one evidence doctor two/pipelock",
		"/var/one --prometheus-textfile two/recorder",
		"/var/lib/pipelock/pipelock.prom",
	)
	target, ok := evidenceCorpusAuditorServiceTarget(service)
	if !ok {
		t.Fatal("rendered service has no target")
	}
	want := `ExecStart="/opt/one evidence doctor two/pipelock" evidence doctor "/var/one --prometheus-textfile two/recorder"`
	if target != want {
		t.Fatalf("target = %q, want %q", target, want)
	}
}

func TestEvidenceCorpusAuditorServiceKeepsControlCharactersInArguments(t *testing.T) {
	for _, tt := range []struct {
		name, value, escaped string
	}{
		{"newline", "\n", `\n`},
		{"carriage return", "\r", `\r`},
		{"tab", "\t", `\t`},
		{"vertical tab", "\v", `\v`},
		{"form feed", "\f", `\f`},
		{"bell", "\a", `\a`},
		{"backspace", "\b", `\b`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			service := renderEvidenceCorpusAuditorService("/opt/"+tt.value+"/pipelock", "/var/"+tt.value+"/recorder", "/var/"+tt.value+"/metric.prom")
			if strings.Count(service, tt.escaped) != 3 {
				t.Fatalf("service did not escape each argument with %q: %q", tt.escaped, service)
			}
			if strings.Count(service, "\n") != strings.Count(renderEvidenceCorpusAuditorService("/bin/pipelock", "/recorder", "/metric"), "\n") {
				t.Fatalf("argument introduced a new unit directive: %q", service)
			}
			if _, ok := evidenceCorpusAuditorServiceTarget(service); !ok {
				t.Fatalf("rendered target cannot be read on rerun: %q", service)
			}
		})
	}
}

// TestEvidenceCorpusAuditorAlertRemediationNamesAShippedSurface keeps the
// annotation honest. It previously told the operator to "stop evidence export",
// and Pipelock ships no evidence-export surface to stop: `pipelock evidence`
// offers view, expire, serve, verify-cert and doctor, so the instruction was
// advisory against whatever external workflow the operator had built. A
// remediation that names a control the product does not have teaches operators
// the alert is not worth reading. The remediation must point at something that
// actually exists, and `evidence doctor` is the command this same file's
// service unit already runs.
func TestEvidenceCorpusAuditorAlertRemediationNamesAShippedSurface(t *testing.T) {
	alert := renderEvidenceCorpusAuditorAlert()
	if strings.Contains(alert, "evidence export") {
		t.Fatalf("corpus alert instructs an evidence-export control that does not ship:\n%s", alert)
	}
	// The full command, not the bare phrase: `evidence doctor` alone would still
	// match a remediation that named no binary or omitted the required
	// directory argument, which is the same half-usable instruction this
	// annotation was rewritten to stop giving.
	if !strings.Contains(alert, "pipelock evidence doctor DIR") {
		t.Fatalf("corpus alert remediation is not the runnable command:\n%s", alert)
	}
	// The other half of the remediation: damage to the corpus says something
	// about evidence already handed out, and an operator who is not told that
	// has no reason to revisit it.
	if !strings.Contains(alert, "Treat this corpus as unverified for any evidence already published or handed to an auditor") {
		t.Fatalf("corpus alert does not tell operators to treat already-published evidence as unverified:\n%s", alert)
	}
}

func TestEvidenceCorpusAuditorRerunRepairsManagedTimerButRefusesUnmanagedFile(t *testing.T) {
	configDir := isolatedEvidenceAuditorInstall(t)
	home := t.TempDir()
	configPath := filepath.Join(home, "pipelock.yaml")
	runInitForEvidenceAuditorTest(t, home, configPath)
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

func TestInstallEvidenceCorpusAuditorPreservesExistingManagedTarget(t *testing.T) {
	configDir := isolatedEvidenceAuditorInstall(t)
	recorderDir := filepath.Join(t.TempDir(), "persistent-recorder")
	if _, err := installEvidenceCorpusAuditor(t.Context(), recorderDir); err != nil {
		t.Fatalf("install persistent auditor: %v", err)
	}

	paths := []string{
		filepath.Join(configDir, "systemd", "user", evidenceCorpusAuditorService),
		filepath.Join(configDir, "systemd", "user", evidenceCorpusAuditorTimer),
		filepath.Join(configDir, "pipelock", "prometheus", "rules", evidenceCorpusAuditorAlert),
	}
	before := make(map[string][]byte, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read installed %s: %v", path, err)
		}
		before[path] = data
	}

	for _, tt := range []struct {
		name        string
		executable  string
		recorderDir string
	}{
		{
			name:        "different executable",
			executable:  "/tmp/pipelock-candidate",
			recorderDir: recorderDir,
		},
		{
			name:        "different recorder directory",
			executable:  "/usr/bin/pipelock",
			recorderDir: filepath.Join(t.TempDir(), "temporary-recorder"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stub(t, &evidenceAuditorExecutable, func() (string, error) { return tt.executable, nil })

			_, err := installEvidenceCorpusAuditor(t.Context(), tt.recorderDir)
			if err == nil {
				t.Fatal("install replaced an existing managed auditor target")
			}
			if !strings.Contains(err.Error(), "refusing to replace managed evidence corpus auditor service target") {
				t.Fatalf("error = %v, want target-preservation refusal", err)
			}

			for _, path := range paths {
				data, readErr := os.ReadFile(filepath.Clean(path))
				if readErr != nil {
					t.Fatalf("read preserved %s: %v", path, readErr)
				}
				if string(data) != string(before[path]) {
					t.Fatalf("refused install changed %s:\n%s", path, data)
				}
			}
		})
	}
}

func TestEvidenceCorpusAuditorServiceTargetRefusesUnverifiableUnits(t *testing.T) {
	valid := renderEvidenceCorpusAuditorService("/usr/bin/pipelock", "/var/lib/recorder", "/var/lib/metric.prom")
	for _, tt := range []struct {
		name, existing, desired, want string
		directory                     bool
	}{
		{name: "unreadable file", desired: valid, directory: true, want: "reading evidence corpus auditor file"},
		{name: "unmanaged unit", existing: "[Service]\nExecStart=/usr/bin/true\n", desired: valid, want: "refusing to overwrite unmanaged"},
		{name: "missing command", existing: managedEvidenceAuditorHeader + "[Service]\n", desired: valid, want: "cannot be determined"},
		{name: "incomplete command", existing: managedEvidenceAuditorHeader + "[Service]\nExecStart=/usr/bin/pipelock evidence doctor /var/lib/recorder\n", desired: valid, want: "cannot be determined"},
		{name: "invalid replacement", existing: valid, desired: "[Service]\n", want: "rendering evidence corpus auditor service target"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "auditor.service")
			if tt.directory {
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte(tt.existing), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validateEvidenceCorpusAuditorServiceTarget(path, tt.desired); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestInstallEvidenceCorpusAuditorPreflightsSecondaryManagedFiles(t *testing.T) {
	configDir := isolatedEvidenceAuditorInstall(t)
	recorderDir := filepath.Join(t.TempDir(), "recorder")
	if _, err := installEvidenceCorpusAuditor(t.Context(), recorderDir); err != nil {
		t.Fatalf("install auditor: %v", err)
	}
	servicePath := filepath.Join(configDir, "systemd", "user", evidenceCorpusAuditorService)
	before, err := os.ReadFile(filepath.Clean(servicePath))
	if err != nil {
		t.Fatalf("read service before failed install: %v", err)
	}
	timerPath := filepath.Join(configDir, "systemd", "user", evidenceCorpusAuditorTimer)
	if err := os.WriteFile(timerPath, []byte("[Timer]\nOnCalendar=daily\n"), 0o600); err != nil {
		t.Fatalf("write unmanaged timer: %v", err)
	}

	_, err = installEvidenceCorpusAuditor(t.Context(), recorderDir)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite unmanaged evidence corpus auditor file") {
		t.Fatalf("error = %v, want unmanaged secondary-file refusal", err)
	}
	after, err := os.ReadFile(filepath.Clean(servicePath))
	if err != nil {
		t.Fatalf("read service after failed install: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("unmanaged timer refusal changed service:\n%s", after)
	}
}

func isolatedEvidenceAuditorInstall(t *testing.T) string {
	t.Helper()
	configDir := t.TempDir()
	stub(t, &evidenceAuditorUserConfigDir, func() (string, error) { return configDir, nil })
	stub(t, &evidenceAuditorExecutable, func() (string, error) { return "/usr/bin/pipelock", nil })
	stub(t, &evidenceAuditorSystemctl, func(context.Context, systemctlOp) error { return nil })
	return configDir
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
