// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDoctorJSONReportsWarningsForDefaultTopology(t *testing.T) {
	var buf bytes.Buffer
	cmd := DoctorCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--json"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected warnings for default topology")
	}
	if cliutil.ExitCodeOf(err) != 1 {
		t.Fatalf("exit code = %d, want 1", cliutil.ExitCodeOf(err))
	}

	var report doctorReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}
	if report.Summary.Warnings == 0 {
		t.Fatalf("expected warnings in report: %+v", report.Summary)
	}
	if !doctorReportHasCheck(report, "direct_egress_boundary", doctorStatusInfo) {
		t.Fatalf("missing direct egress info: %+v", report.Checks)
	}
}

func TestBuildDoctorReportFlagsMissingMCPManifest(t *testing.T) {
	cfg := config.Defaults()
	cfg.MCPBinaryIntegrity.Enabled = true
	cfg.MCPBinaryIntegrity.ManifestPath = filepath.Join(t.TempDir(), "missing.json")

	report := buildDoctorReport(cfg, configLabelDefaults)
	if !doctorReportHasCheck(report, "mcp_binary_integrity", doctorStatusFail) {
		t.Fatalf("expected mcp_binary_integrity failure: %+v", report.Checks)
	}
}

func TestBuildDoctorReportAcceptsReadableMCPManifestButStillWarns(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	cfg := config.Defaults()
	cfg.MCPBinaryIntegrity.Enabled = true
	cfg.MCPBinaryIntegrity.ManifestPath = manifestPath

	report := buildDoctorReport(cfg, configLabelDefaults)
	var got doctorReportCheck
	for _, check := range report.Checks {
		if check.Name == "mcp_binary_integrity" {
			got = check
			break
		}
	}
	if got.Status != doctorStatusWarn {
		t.Fatalf("status = %q, want warn; check=%+v", got.Status, got)
	}
	if !strings.Contains(got.Detail, "wrapper invocation") {
		t.Fatalf("detail should mention wrapper proof, got %q", got.Detail)
	}
}

func TestBuildDoctorReportRejectsDirectoryMCPManifest(t *testing.T) {
	cfg := config.Defaults()
	cfg.MCPBinaryIntegrity.Enabled = true
	cfg.MCPBinaryIntegrity.ManifestPath = t.TempDir()

	report := buildDoctorReport(cfg, configLabelDefaults)
	if !doctorReportHasCheck(report, "mcp_binary_integrity", doctorStatusFail) {
		t.Fatalf("expected directory mcp_binary_integrity failure: %+v", report.Checks)
	}
}

func TestBuildDoctorReportRejectsStatOnlyMCPManifest(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can open mode 000 files")
	}
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte("{}\n"), 0o000); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	cfg := config.Defaults()
	cfg.MCPBinaryIntegrity.Enabled = true
	cfg.MCPBinaryIntegrity.ManifestPath = manifestPath

	report := buildDoctorReport(cfg, configLabelDefaults)
	if !doctorReportHasCheck(report, "mcp_binary_integrity", doctorStatusFail) {
		t.Fatalf("expected unreadable mcp_binary_integrity failure: %+v", report.Checks)
	}
}

func TestBuildDoctorReportWarnsWhenGlobalEnforceDisabled(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.pem")
	caKey := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(caCert, []byte("test ca cert bytes\n"), 0o600); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}
	if err := os.WriteFile(caKey, []byte("test ca key bytes\n"), 0o600); err != nil {
		t.Fatalf("write ca key: %v", err)
	}

	cfg := config.Defaults()
	enforce := false
	cfg.Enforce = &enforce
	cfg.TLSInterception.Enabled = true
	cfg.TLSInterception.CACertPath = caCert
	cfg.TLSInterception.CAKeyPath = caKey
	cfg.BrowserShield.Enabled = true

	report := buildDoctorReport(cfg, configLabelDefaults)
	for _, name := range []string{"http_proxy", "request_body_scanning", "tls_interception", "browser_shield"} {
		if !doctorReportHasCheck(report, name, doctorStatusWarn) {
			t.Errorf("expected %s warning when enforce=false: %+v", name, doctorCheckFor(report, name))
		}
		if check := doctorCheckFor(report, name); check.Enforcing {
			t.Errorf("expected %s Enforcing=false when enforce=false, got %+v", name, check)
		}
	}
}

func TestDoctorChecksCoverConfiguredBranches(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.pem")
	caKey := filepath.Join(dir, "ca.key")
	manifestPath := filepath.Join(dir, "manifest.json")
	watchDir := filepath.Join(dir, "watch")
	for path, data := range map[string][]byte{
		caCert:       []byte("cert\n"),
		caKey:        []byte("key\n"),
		manifestPath: []byte("{}\n"),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	if err := os.Mkdir(watchDir, 0o700); err != nil {
		t.Fatalf("mkdir watch: %v", err)
	}

	t.Run("tls ok when ca files readable", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.TLSInterception.Enabled = true
		cfg.TLSInterception.CACertPath = caCert
		cfg.TLSInterception.CAKeyPath = caKey
		check := checkDoctorTLSInterception(cfg)
		if check.Status != doctorStatusOK || !check.Enforcing {
			t.Fatalf("check = %+v, want enforcing ok", check)
		}
	})

	t.Run("request body scanning action gates enforcement", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.RequestBodyScanning.Enabled = false
		if check := checkDoctorRequestBodyScanning(cfg); check.Status != doctorStatusWarn {
			t.Fatalf("disabled check = %+v, want warn", check)
		}
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionWarn
		if check := checkDoctorRequestBodyScanning(cfg); check.Status != doctorStatusWarn || check.Enforcing {
			t.Fatalf("warn action check = %+v, want warning without enforcement", check)
		}
		cfg.RequestBodyScanning.Action = config.ActionBlock
		if check := checkDoctorRequestBodyScanning(cfg); check.Status != doctorStatusOK || !check.Enforcing {
			t.Fatalf("block action check = %+v, want enforcing ok", check)
		}
	})

	t.Run("browser shield reachability follows TLS visibility", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.BrowserShield.Enabled = false
		if check := checkDoctorBrowserShield(cfg); check.Status != doctorStatusInfo {
			t.Fatalf("disabled check = %+v, want info", check)
		}
		cfg.BrowserShield.Enabled = true
		cfg.TLSInterception.Enabled = false
		if check := checkDoctorBrowserShield(cfg); check.Status != doctorStatusWarn || check.Reachable {
			t.Fatalf("no tls check = %+v, want warning without reachability", check)
		}
		cfg.TLSInterception.Enabled = true
		if check := checkDoctorBrowserShield(cfg); check.Status != doctorStatusOK || !check.Enforcing {
			t.Fatalf("tls check = %+v, want enforcing ok", check)
		}
	})

	t.Run("mcp wrapper and provenance report configured warnings", func(t *testing.T) {
		cfg := config.Defaults()
		if check := checkDoctorMCPWrapperFeatures(cfg); check.Status != doctorStatusInfo {
			t.Fatalf("disabled wrapper check = %+v, want info", check)
		}
		cfg.MCPInputScanning.Enabled = true
		cfg.MCPToolScanning.Enabled = true
		cfg.MCPToolPolicy.Enabled = true
		cfg.MCPSessionBinding.Enabled = true
		check := checkDoctorMCPWrapperFeatures(cfg)
		if check.Status != doctorStatusWarn || !strings.Contains(check.Detail, "mcp_session_binding") {
			t.Fatalf("enabled wrapper check = %+v, want warning with enabled feature list", check)
		}
		cfg.MCPToolProvenance.Enabled = true
		cfg.MCPToolProvenance.Mode = config.ProvenanceModePipelock
		check = checkDoctorMCPToolProvenance(cfg)
		if check.Status != doctorStatusWarn || !strings.Contains(check.Detail, config.ProvenanceModePipelock) {
			t.Fatalf("provenance check = %+v, want warning with mode", check)
		}
	})

	t.Run("binary integrity manifest states", func(t *testing.T) {
		cfg := config.Defaults()
		if check := checkDoctorMCPBinaryIntegrity(cfg); check.Status != doctorStatusInfo {
			t.Fatalf("disabled check = %+v, want info", check)
		}
		cfg.MCPBinaryIntegrity.Enabled = true
		cfg.MCPBinaryIntegrity.ManifestPath = ""
		if check := checkDoctorMCPBinaryIntegrity(cfg); check.Status != doctorStatusFail {
			t.Fatalf("empty manifest check = %+v, want fail", check)
		}
		cfg.MCPBinaryIntegrity.ManifestPath = manifestPath
		if check := checkDoctorMCPBinaryIntegrity(cfg); check.Status != doctorStatusWarn || !check.Reachable {
			t.Fatalf("readable manifest check = %+v, want reachable warning", check)
		}
	})

	t.Run("file sentry watch path states", func(t *testing.T) {
		cfg := config.Defaults()
		if check := checkDoctorFileSentry(cfg); check.Status != doctorStatusInfo {
			t.Fatalf("disabled check = %+v, want info", check)
		}
		cfg.FileSentry.Enabled = true
		cfg.FileSentry.WatchPaths = nil
		if check := checkDoctorFileSentry(cfg); check.Status != doctorStatusFail {
			t.Fatalf("empty paths check = %+v, want fail", check)
		}
		cfg.FileSentry.WatchPaths = []string{filepath.Join(dir, "missing")}
		if check := checkDoctorFileSentry(cfg); check.Status != doctorStatusFail {
			t.Fatalf("missing path check = %+v, want fail", check)
		}
		cfg.FileSentry.WatchPaths = []string{watchDir}
		check := checkDoctorFileSentry(cfg)
		if check.Status != doctorStatusWarn || !check.Reachable {
			t.Fatalf("readable path check = %+v, want reachable warning", check)
		}
	})

	t.Run("sentry states", func(t *testing.T) {
		cfg := config.Defaults()
		disabled := false
		cfg.Sentry.Enabled = &disabled
		if check := checkDoctorSentry(cfg); check.Status != doctorStatusWarn || check.Configured {
			t.Fatalf("disabled sentry check = %+v, want unconfigured warning", check)
		}
		enabled := true
		cfg.Sentry.Enabled = &enabled
		cfg.Sentry.DSN = ""
		t.Setenv("SENTRY_DSN", "")
		if check := checkDoctorSentry(cfg); check.Status != doctorStatusWarn || !check.Configured {
			t.Fatalf("no dsn sentry check = %+v, want configured warning", check)
		}
		cfg.Sentry.DSN = "https://public@example.invalid/1"
		if check := checkDoctorSentry(cfg); check.Status != doctorStatusOK || !check.Enforcing {
			t.Fatalf("dsn sentry check = %+v, want ok", check)
		}
	})
}

func TestDoctorHelpersAndStatusTags(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if missing := missingReadablePaths("", file, dir); len(missing) != 1 || missing[0] != "<empty>" {
		t.Fatalf("missingReadablePaths = %+v, want only empty path", missing)
	}
	if missing := missingReadableFiles("", file, dir); len(missing) != 2 || missing[0] != "<empty>" || missing[1] != dir {
		t.Fatalf("missingReadableFiles = %+v, want empty and directory", missing)
	}
	if !pathReadable(file) || !pathReadable(dir) {
		t.Fatalf("pathReadable should accept readable files and directories")
	}
	if pathReadable(filepath.Join(dir, "missing")) || pathReadableFile(dir) {
		t.Fatalf("pathReadable helpers accepted missing path or directory file")
	}

	cases := []struct {
		status string
		want   string
	}{
		{doctorStatusOK, "\033[32m[OK]\033[0m"},
		{doctorStatusWarn, "\033[33m[WARN]\033[0m"},
		{doctorStatusFail, "\033[31m[FAIL]\033[0m"},
		{doctorStatusInfo, "\033[36m[INFO]\033[0m"},
		{"other", "\033[36m[INFO]\033[0m"},
	}
	for _, tt := range cases {
		if got := doctorStatusTag(tt.status, true); got != tt.want {
			t.Fatalf("doctorStatusTag(%q, true) = %q, want %q", tt.status, got, tt.want)
		}
	}
	if got := doctorStatusTag(doctorStatusWarn, false); got != "[WARN]" {
		t.Fatalf("plain status tag = %q, want [WARN]", got)
	}
}

func TestDoctorReportJSONOmitsBannerWhenUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test only meaningful when run unprivileged")
	}
	var buf bytes.Buffer
	cmd := DoctorCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--json"})
	_ = cmd.Execute()
	var report doctorReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if report.RootRunBanner != "" {
		t.Fatalf("root_run_banner should be omitted/empty when euid != 0, got %q", report.RootRunBanner)
	}
}

func TestDoctorRootBannerMessageShape(t *testing.T) {
	const wantSubstr = "running as root"
	if os.Geteuid() == 0 {
		if msg := doctorRootBannerMessage(); !strings.Contains(msg, wantSubstr) {
			t.Fatalf("banner = %q, want substring %q", msg, wantSubstr)
		}
		return
	}
	if !strings.Contains(doctorRootBannerText, wantSubstr) {
		t.Fatalf("banner constant = %q, want substring %q", doctorRootBannerText, wantSubstr)
	}
	if msg := doctorRootBannerMessage(); msg != "" {
		t.Fatalf("banner = %q, want substring %q", msg, wantSubstr)
	}
}

func doctorCheckFor(report doctorReport, name string) doctorReportCheck {
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	return doctorReportCheck{}
}

func TestDoctorHumanOutputMentionsConfiguredVsEnforcing(t *testing.T) {
	var buf bytes.Buffer
	cmd := DoctorCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--no-color"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected warning exit")
	}
	out := buf.String()
	for _, want := range []string{"Pipelock Enforcement Doctor", "direct_egress_boundary", "launch agents through plk/containment"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func doctorReportHasCheck(report doctorReport, name, status string) bool {
	for _, check := range report.Checks {
		if check.Name == name && check.Status == status {
			return true
		}
	}
	return false
}
