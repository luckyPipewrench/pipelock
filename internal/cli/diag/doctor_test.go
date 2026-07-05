// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
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

func TestBuildDoctorReportShowsLicenseExpiryWarning(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lic := license.License{
		ID:        "lic_doctor_warning",
		Email:     "doctor@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(7 * 24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.LicenseKey = token
	cfg.LicensePublicKey = hex.EncodeToString(pub)

	report := buildDoctorReport(cfg, configLabelDefaults)
	check := doctorCheckFor(report, "license_status")
	if check.Status != doctorStatusWarn {
		t.Fatalf("license status = %+v, want warning", check)
	}
	if !strings.Contains(check.Detail, "7-day renewal band") {
		t.Fatalf("detail = %q, want renewal band", check.Detail)
	}
}

func TestDoctorLicenseStatusBranches(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	active := license.License{
		ID:        "lic_doctor_active",
		Email:     "doctor@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(45 * 24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	activeToken, err := license.Issue(active, priv)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("missing", func(t *testing.T) {
		check := checkDoctorLicense(config.Defaults())
		if check.Status != doctorStatusInfo {
			t.Fatalf("check = %+v, want info", check)
		}
	})

	t.Run("invalid configured public key fails verification", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.LicenseKey = activeToken
		cfg.LicensePublicKey = "not-hex"
		check := checkDoctorLicense(cfg)
		if check.Status != doctorStatusWarn || !strings.Contains(check.Detail, "invalid license public key") {
			t.Fatalf("check = %+v, want invalid key warning", check)
		}
	})

	t.Run("decode fallback without public key", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.LicenseKey = activeToken
		check := checkDoctorLicense(cfg)
		if check.Status != doctorStatusWarn || !strings.Contains(check.Detail, "signature could not be verified") {
			t.Fatalf("check = %+v, want no-key verification warning", check)
		}
	})

	t.Run("configured revoked flag fails", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.LicenseKey = activeToken
		cfg.LicensePublicKey = hex.EncodeToString(pub)
		cfg.LicenseRevoked = true
		cfg.LicenseRevocationReason = "revoked by issuer; contact billing"
		check := checkDoctorLicense(cfg)
		if check.Status != doctorStatusFail || !strings.Contains(check.Detail, "revoked") {
			t.Fatalf("check = %+v, want revoked failure", check)
		}
	})

	t.Run("thirty day expiry band is info", func(t *testing.T) {
		lic := active
		lic.ID = "lic_doctor_30"
		lic.ExpiresAt = now.Add(29 * 24 * time.Hour).Unix()
		token, err := license.Issue(lic, priv)
		if err != nil {
			t.Fatal(err)
		}
		cfg := config.Defaults()
		cfg.LicenseKey = token
		cfg.LicensePublicKey = hex.EncodeToString(pub)
		check := checkDoctorLicense(cfg)
		if check.Status != doctorStatusInfo || !strings.Contains(check.Detail, "30-day renewal band") {
			t.Fatalf("check = %+v, want info renewal band", check)
		}
	})

	t.Run("bad CRL path reports verification warning", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.LicenseKey = activeToken
		cfg.LicensePublicKey = hex.EncodeToString(pub)
		cfg.LicenseCRLFile = filepath.Join(t.TempDir(), "missing-crl.json")
		check := checkDoctorLicense(cfg)
		if check.Status != doctorStatusWarn || !strings.Contains(check.Detail, "license verification failed") {
			t.Fatalf("check = %+v, want CRL verification warning", check)
		}
	})

	t.Run("valid signed CRL", func(t *testing.T) {
		crl, err := license.SignCRL(license.CRLPayload{
			Version:   license.CRLVersion,
			IssuedAt:  now.Add(-time.Hour).Unix(),
			ExpiresAt: now.Add(24 * time.Hour).Unix(),
			Revoked: []license.RevokedLicense{{
				ID:        "lic_other",
				RevokedAt: now.Add(-time.Hour).Unix(),
			}},
		}, priv)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(crl)
		if err != nil {
			t.Fatal(err)
		}
		crlPath := filepath.Join(t.TempDir(), "crl.json")
		if err := os.WriteFile(crlPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := config.Defaults()
		cfg.LicenseKey = activeToken
		cfg.LicensePublicKey = hex.EncodeToString(pub)
		cfg.LicenseCRLFile = crlPath
		check := checkDoctorLicense(cfg)
		if check.Status != doctorStatusOK || !strings.Contains(check.Detail, "signed CRL configured") {
			t.Fatalf("check = %+v, want ok CRL detail", check)
		}
	})

	t.Run("valid intermediate detail", func(t *testing.T) {
		rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		intermediatePub, intermediatePriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		im, err := license.SignIntermediate(license.IntermediatePayload{
			Serial:    "im_doctor",
			Purpose:   license.PurposeLicenseSigning,
			Algorithm: license.AlgorithmEd25519,
			PublicKey: hex.EncodeToString(intermediatePub),
			NotBefore: now.Add(-time.Minute).Unix(),
			NotAfter:  now.Add(time.Hour).Unix(),
			IssuedAt:  now.Add(-time.Minute).Unix(),
		}, rootPriv)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := json.Marshal(im)
		if err != nil {
			t.Fatal(err)
		}
		token, err := license.Issue(active, intermediatePriv)
		if err != nil {
			t.Fatal(err)
		}
		cfg := config.Defaults()
		cfg.LicenseKey = token
		cfg.LicensePublicKey = hex.EncodeToString(rootPub)
		cfg.LicenseIntermediateCert = cert

		check := checkDoctorLicense(cfg)
		if check.Status != doctorStatusOK || !strings.Contains(check.Detail, "intermediate certificate configured") {
			t.Fatalf("check = %+v, want ok intermediate detail", check)
		}
	})

	t.Run("revoked from CRL", func(t *testing.T) {
		crl, err := license.SignCRL(license.CRLPayload{
			Version:   license.CRLVersion,
			IssuedAt:  now.Add(-time.Hour).Unix(),
			ExpiresAt: now.Add(24 * time.Hour).Unix(),
			Revoked: []license.RevokedLicense{{
				ID:        active.ID,
				RevokedAt: now.Add(-time.Hour).Unix(),
			}},
		}, priv)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(crl)
		if err != nil {
			t.Fatal(err)
		}
		crlPath := filepath.Join(t.TempDir(), "crl.json")
		if err := os.WriteFile(crlPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := config.Defaults()
		cfg.LicenseKey = activeToken
		cfg.LicensePublicKey = hex.EncodeToString(pub)
		cfg.LicenseCRLFile = crlPath
		check := checkDoctorLicense(cfg)
		if check.Status != doctorStatusFail {
			t.Fatalf("check = %+v, want fail", check)
		}
	})
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
		// required:false missing path: degrades to warn (matches the new
		// startup behavior where non-required misses log degraded and
		// continue rather than crash-loop).
		cfg.FileSentry.WatchPaths = []config.WatchPath{{Path: filepath.Join(dir, "missing")}}
		if check := checkDoctorFileSentry(cfg); check.Status != doctorStatusWarn {
			t.Fatalf("missing optional path check = %+v, want warn (degraded)", check)
		}
		// required:true missing path: hard fail.
		cfg.FileSentry.WatchPaths = []config.WatchPath{{Path: filepath.Join(dir, "missing"), Required: true}}
		if check := checkDoctorFileSentry(cfg); check.Status != doctorStatusFail {
			t.Fatalf("missing required path check = %+v, want fail", check)
		}
		cfg.FileSentry.WatchPaths = []config.WatchPath{{Path: watchDir}}
		check := checkDoctorFileSentry(cfg)
		if check.Status != doctorStatusWarn || !check.Reachable {
			t.Fatalf("readable path check = %+v, want reachable warning", check)
		}
	})

	t.Run("sentry states", func(t *testing.T) {
		cfg := config.Defaults()
		disabled := false
		cfg.Sentry.Enabled = &disabled
		if check := checkDoctorSentry(cfg); check.Status != doctorStatusInfo || check.Configured {
			t.Fatalf("disabled sentry check = %+v, want informational disabled-by-default", check)
		} else if !strings.Contains(check.Next, "sentry.enabled: true") || !strings.Contains(check.Next, "SENTRY_DSN") {
			t.Fatalf("disabled sentry next = %q, want enabled flag and DSN guidance", check.Next)
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
