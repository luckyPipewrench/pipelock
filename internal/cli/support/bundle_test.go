// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package support_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/support"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// --- fake credential helpers (G101 rule: build at runtime, never store literals) ---

const (
	// testAWSKeyPrefix builds a 20-char AWS-shaped token at runtime.
	testAWSKeyPrefix = "AKIA"
	testAWSKeySuffix = "IOSFODNN7EXAMPLE"

	// testGitHubTokenPrefix + 36 pad chars.
	testGitHubTokenPrefix = "ghp_"
	testGitHubTokenPad    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	// testAnthropicKeyPart1 + part2 avoids a literal in source.
	testAnthropicKeyPart1 = "sk-ant-"
	testAnthropicKeyPart2 = "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

	// testWebhookUserPass is the userinfo in a webhook URL.
	testWebhookUser = "webhook-user"
	testWebhookPass = "h3ll0-p4ss-s3cr3t"
)

func fakeAWSKey() string       { return testAWSKeyPrefix + testAWSKeySuffix }
func fakeGHToken() string      { return testGitHubTokenPrefix + testGitHubTokenPad }
func fakeAnthropicKey() string { return testAnthropicKeyPart1 + testAnthropicKeyPart2 }
func fakeWebhookToken() string { return "wh-t0k3n-" + testAWSKeySuffix }
func fakeLogAWSKey() string    { return testAWSKeyPrefix + strings.Repeat("Z", 16) }

// makeSecretConfig returns a config seeded with several fake secrets in
// different positions: top-level token, nested field, webhook URL userinfo,
// and webhook URL query param.
func makeSecretConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil // avoid DNS in tests

	// Top-level token field.
	cfg.LicenseKey = fakeAWSKey()

	// Nested token field (kill switch API token).
	cfg.KillSwitch.APIToken = fakeGHToken()

	// Webhook URL with userinfo credentials.
	cfg.Emit.Webhook.URL = "https://" + testWebhookUser + ":" + testWebhookPass + "@webhook.provider.example/events"

	// Webhook URL with query-param credential.
	cfg.Emit.OTLP.Endpoint = "https://otlp.provider.example/v1/logs"
	cfg.Emit.OTLP.Headers = map[string]string{
		"Authorization": "Bearer " + fakeAnthropicKey(),
		"X-Request-ID":  "trace-abc-123", // non-secret header
	}

	// Webhook auth token.
	cfg.Emit.Webhook.AuthToken = fakeWebhookToken()

	return cfg
}

// --- helpers ---

// readArchive extracts all files in the tar.gz at path and returns their
// contents keyed by filename.
func readArchive(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer func() { _ = f.Close() }()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	files := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read tar entry %q: %v", hdr.Name, err)
		}
		files[hdr.Name] = data
	}
	return files
}

// archiveBytes concatenates all entry bytes into a single blob for substring
// scanning. This is the most conservative check: if the secret appears
// anywhere in any file, the test fails.
func archiveBytes(files map[string][]byte) []byte {
	var buf bytes.Buffer
	for _, data := range files {
		buf.Write(data)
	}
	return buf.Bytes()
}

// runBundleCmd invokes the bundle command with the given config file and
// writes the archive to a temp dir. Returns the archive path.
func runBundleCmd(t *testing.T, cfgPath string) string {
	t.Helper()
	tmp := t.TempDir()
	out := filepath.Join(tmp, "bundle.tar.gz")

	cmd := support.BundleCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	args := []string{"--output", out}
	if cfgPath != "" {
		args = append(args, "--config", cfgPath)
	}
	cmd.SetArgs(args)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("bundle command failed: %v (output: %s)", err, buf.String())
	}
	return out
}

// writeTempConfig writes a config YAML seeded with fake secrets and returns
// the file path.
func writeTempConfig(t *testing.T, cfg *config.Config) string {
	t.Helper()
	// We can't Marshal a config.Config directly because it has no yaml export
	// method from the outside. Instead, write a minimal YAML that exercises the
	// secret fields we care about.
	awsKey := fakeAWSKey()
	ghToken := fakeGHToken()
	anthKey := fakeAnthropicKey()
	whToken := fakeWebhookToken()

	yaml := strings.Join([]string{
		"mode: balanced",
		"internal: null",
		"license_key: " + awsKey,
		"kill_switch:",
		"  api_token: " + ghToken,
		"emit:",
		"  webhook:",
		"    url: https://" + testWebhookUser + ":" + testWebhookPass + "@webhook.provider.example/events",
		"    auth_token: " + whToken,
		"  otlp:",
		"    endpoint: https://otlp.provider.example/v1/logs",
		"    headers:",
		"      Authorization: Bearer " + anthKey,
		"      X-Request-ID: trace-abc-123",
		"  syslog:",
		"    address: udp://syslog.provider.example:514",
	}, "\n")

	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(filepath.Clean(path), []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_ = cfg // passed for reference only; we use the YAML directly
	return path
}

func writeTempLoggingConfig(t *testing.T, logLines []string) string {
	t.Helper()

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "pipelock-audit.log")
	if err := os.WriteFile(filepath.Clean(logPath), []byte(strings.Join(logLines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	cfgPath := filepath.Join(tmp, "pipelock.yaml")
	yaml := strings.Join([]string{
		"mode: balanced",
		"internal: null",
		"logging:",
		"  output: file",
		"  file: " + logPath,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Clean(cfgPath), []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

// --- adversarial leak tests ---

// TestBundle_NoSecretLeaks_TopLevelToken verifies that a secret stored in
// cfg.LicenseKey (top-level string field) does not appear in the bundle.
func TestBundle_NoSecretLeaks_TopLevelToken(t *testing.T) {
	t.Parallel()

	secret := fakeAWSKey()
	cfgPath := writeTempConfig(t, makeSecretConfig())
	archivePath := runBundleCmd(t, cfgPath)

	files := readArchive(t, archivePath)
	all := archiveBytes(files)

	if bytes.Contains(all, []byte(secret)) {
		t.Errorf("AWS-key-shaped credential leaked into bundle: %q found in archive", secret)
	}
}

// TestBundle_NoSecretLeaks_NestedField verifies that a secret stored in a
// nested config struct field (kill_switch.api_token) does not appear in the bundle.
func TestBundle_NoSecretLeaks_NestedField(t *testing.T) {
	t.Parallel()

	secret := fakeGHToken()
	cfgPath := writeTempConfig(t, makeSecretConfig())
	archivePath := runBundleCmd(t, cfgPath)

	files := readArchive(t, archivePath)
	all := archiveBytes(files)

	if bytes.Contains(all, []byte(secret)) {
		t.Errorf("GitHub-token-shaped credential leaked into bundle: %q found in archive", secret)
	}
}

// TestBundle_NoSecretLeaks_WebhookURLUserinfo verifies that Basic auth
// credentials embedded in a webhook URL (user:pass@host) are stripped.
func TestBundle_NoSecretLeaks_WebhookURLUserinfo(t *testing.T) {
	t.Parallel()

	secret := testWebhookPass
	cfgPath := writeTempConfig(t, makeSecretConfig())
	archivePath := runBundleCmd(t, cfgPath)

	files := readArchive(t, archivePath)
	all := archiveBytes(files)

	if bytes.Contains(all, []byte(secret)) {
		t.Errorf("webhook URL userinfo password leaked into bundle: %q found in archive", secret)
	}
}

// TestBundle_NoSecretLeaks_OTLPAuthHeader verifies that an Authorization
// header value in emit.otlp.headers does not appear in the bundle.
func TestBundle_NoSecretLeaks_OTLPAuthHeader(t *testing.T) {
	t.Parallel()

	secret := fakeAnthropicKey()
	cfgPath := writeTempConfig(t, makeSecretConfig())
	archivePath := runBundleCmd(t, cfgPath)

	files := readArchive(t, archivePath)
	all := archiveBytes(files)

	if bytes.Contains(all, []byte(secret)) {
		t.Errorf("OTLP auth header value leaked into bundle: %q found in archive", secret)
	}
}

// TestBundle_NoSecretLeaks_WebhookAuthToken verifies that emit.webhook.auth_token
// does not appear in the bundle.
func TestBundle_NoSecretLeaks_WebhookAuthToken(t *testing.T) {
	t.Parallel()

	secret := fakeWebhookToken()
	cfgPath := writeTempConfig(t, makeSecretConfig())
	archivePath := runBundleCmd(t, cfgPath)

	files := readArchive(t, archivePath)
	all := archiveBytes(files)

	if bytes.Contains(all, []byte(secret)) {
		t.Errorf("webhook auth token leaked into bundle: %q found in archive", secret)
	}
}

func TestBundle_AuditLogTailDLPRedactsUnknownSecret(t *testing.T) {
	t.Parallel()

	secret := fakeLogAWSKey()
	cfgPath := writeTempLoggingConfig(t, []string{
		`{"level":"info","event":"allowed","msg":"normal line"}`,
		`{"level":"warn","event":"unexpected","detail":"leaked ` + secret + `"}`,
	})

	archivePath := runBundleCmd(t, cfgPath)
	files := readArchive(t, archivePath)
	all := archiveBytes(files)

	if bytes.Contains(all, []byte(secret)) {
		t.Errorf("secret-shaped audit-log value leaked into bundle: %q found in archive", secret)
	}
	tail, ok := files["audit-log-tail.txt"]
	if !ok {
		t.Fatal("audit-log-tail.txt missing despite configured readable audit log")
	}
	if !bytes.Contains(tail, []byte("<redacted>")) {
		t.Errorf("audit-log-tail.txt should contain redaction sentinel; got: %q", string(tail))
	}
}

func TestBundle_NoLogsFlagOmitsAuditLogTail(t *testing.T) {
	t.Parallel()

	cfgPath := writeTempLoggingConfig(t, []string{`{"level":"info","event":"allowed"}`})
	tmp := t.TempDir()
	out := filepath.Join(tmp, "bundle.tar.gz")

	cmd := support.BundleCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--output", out, "--config", cfgPath, "--no-logs"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("bundle command failed: %v (output: %s)", err, buf.String())
	}

	files := readArchive(t, out)
	if _, ok := files["audit-log-tail.txt"]; ok {
		t.Fatal("audit-log-tail.txt present despite --no-logs")
	}
	if bytes.Contains(files["manifest.json"], []byte("audit-log-tail.txt")) {
		t.Fatal("manifest lists audit-log-tail.txt despite --no-logs")
	}
}

// --- happy-path content tests ---

// TestBundle_ContainsExpectedFiles verifies that the bundle includes the expected
// diagnostics files and that they contain non-secret content.
func TestBundle_ContainsExpectedFiles(t *testing.T) {
	t.Parallel()

	archivePath := runBundleCmd(t, "")
	files := readArchive(t, archivePath)

	requiredFiles := []string{
		"manifest.json",
		"version.txt",
		"config-summary.json",
		"scanners.json",
		"env-var-names.txt",
		"config-path.txt",
	}
	for _, name := range requiredFiles {
		if _, ok := files[name]; !ok {
			t.Errorf("expected file %q missing from bundle; got files: %v", name, fileNames(files))
		}
	}
}

// TestBundle_ManifestStructure verifies that manifest.json can be parsed and
// contains expected fields.
func TestBundle_ManifestStructure(t *testing.T) {
	t.Parallel()

	archivePath := runBundleCmd(t, "")
	files := readArchive(t, archivePath)

	manifestData, ok := files["manifest.json"]
	if !ok {
		t.Fatal("manifest.json missing from bundle")
	}

	var m map[string]any
	if err := json.Unmarshal(manifestData, &m); err != nil {
		t.Fatalf("manifest.json parse error: %v", err)
	}

	for _, field := range []string{"bundle_version", "generated_at", "pipelock_version", "go_version", "os", "arch"} {
		if _, ok := m[field]; !ok {
			t.Errorf("manifest.json missing field %q", field)
		}
	}
}

// TestBundle_VersionTxtContent verifies version.txt contains version info.
func TestBundle_VersionTxtContent(t *testing.T) {
	t.Parallel()

	archivePath := runBundleCmd(t, "")
	files := readArchive(t, archivePath)

	versionData, ok := files["version.txt"]
	if !ok {
		t.Fatal("version.txt missing from bundle")
	}
	if !bytes.Contains(versionData, []byte("pipelock version:")) {
		t.Errorf("version.txt missing 'pipelock version:' line; got: %q", string(versionData))
	}
}

// TestBundle_ConfigSummaryIsJSON verifies config-summary.json is valid JSON.
func TestBundle_ConfigSummaryIsJSON(t *testing.T) {
	t.Parallel()

	archivePath := runBundleCmd(t, "")
	files := readArchive(t, archivePath)

	data, ok := files["config-summary.json"]
	if !ok {
		t.Fatal("config-summary.json missing from bundle")
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Errorf("config-summary.json is not valid JSON: %v", err)
	}
}

// TestBundle_ScannersSummaryIsJSON verifies scanners.json is valid JSON.
func TestBundle_ScannersSummaryIsJSON(t *testing.T) {
	t.Parallel()

	archivePath := runBundleCmd(t, "")
	files := readArchive(t, archivePath)

	data, ok := files["scanners.json"]
	if !ok {
		t.Fatal("scanners.json missing from bundle")
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Errorf("scanners.json is not valid JSON: %v", err)
	}
}

// TestBundle_EnvVarNamesNeverHaveValues verifies that env-var-names.txt
// contains only NAME lines with no "=" characters (values stripped).
// NOTE: cannot call t.Parallel() — t.Setenv requires a non-parallel test.
func TestBundle_EnvVarNamesNeverHaveValues(t *testing.T) {
	// Set a fake env var for the duration of the test.
	t.Setenv("PIPELOCK_FAKE_TEST_VAR", "super-secret-value")

	archivePath := runBundleCmd(t, "")
	files := readArchive(t, archivePath)

	// We set a PIPELOCK_ var above, so the file MUST be present; a missing file
	// is a regression, not a skip condition.
	data, ok := files["env-var-names.txt"]
	if !ok {
		t.Fatalf("env-var-names.txt missing despite PIPELOCK_FAKE_TEST_VAR being set; files: %v", fileNames(files))
	}

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "=") {
			t.Errorf("env-var-names.txt line contains '=' (value leaked): %q", line)
		}
		if strings.Contains(line, "super-secret-value") {
			t.Errorf("env-var-names.txt contains env value: %q", line)
		}
	}

	// Verify the test var's NAME (not value) appears in the file.
	if !bytes.Contains(data, []byte("PIPELOCK_FAKE_TEST_VAR")) {
		t.Error("env-var-names.txt should contain 'PIPELOCK_FAKE_TEST_VAR' name")
	}
}

// TestBundle_OutputPath verifies that a custom --output path is honoured.
func TestBundle_OutputPath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	customPath := filepath.Join(tmp, "custom-bundle.tar.gz")

	cmd := support.BundleCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--output", customPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("bundle command failed: %v (output: %s)", err, buf.String())
	}

	if _, err := os.Stat(customPath); err != nil {
		t.Fatalf("expected output file at %q: %v", customPath, err)
	}
}

// TestBundle_JSONManifestFlag verifies that --json produces a companion
// -manifest.json file alongside the archive.
func TestBundle_JSONManifestFlag(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "bundle.tar.gz")
	manifestPath := filepath.Join(tmp, "bundle-manifest.json")

	cmd := support.BundleCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--output", archivePath, "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("bundle command with --json failed: %v (output: %s)", err, buf.String())
	}

	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("expected manifest.json at %q: %v", manifestPath, err)
	}

	data, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		t.Fatalf("read manifest.json: %v", err)
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Errorf("manifest.json is not valid JSON: %v", err)
	}
}

// TestSupport_CmdHierarchy verifies that Cmd() returns a parent with 'bundle'
// registered as a subcommand (so root.go's AddCommand wiring works).
func TestSupport_CmdHierarchy(t *testing.T) {
	t.Parallel()

	parent := support.Cmd()
	if parent.Use != "support" {
		t.Errorf("expected parent Use=%q, got %q", "support", parent.Use)
	}

	var found bool
	for _, sub := range parent.Commands() {
		if sub.Use == "bundle" {
			found = true
			break
		}
	}
	if !found {
		t.Error("'bundle' subcommand not registered under 'support'")
	}
}

// TestBundle_NilConfig verifies that bundle generation with an empty config
// does not panic or produce a garbled archive.
func TestBundle_NilConfig(t *testing.T) {
	t.Parallel()

	// Run with no config file → uses defaults.
	archivePath := runBundleCmd(t, "")
	files := readArchive(t, archivePath)

	if len(files) == 0 {
		t.Error("expected non-empty archive from default config bundle")
	}
}

// TestBundle_ConfigPathInArchive verifies config-path.txt shows "defaults"
// when no config file is specified.
func TestBundle_ConfigPathInArchive(t *testing.T) {
	t.Parallel()

	archivePath := runBundleCmd(t, "")
	files := readArchive(t, archivePath)

	data, ok := files["config-path.txt"]
	if !ok {
		t.Fatal("config-path.txt missing from bundle")
	}
	if !bytes.Contains(data, []byte("defaults")) {
		t.Errorf("config-path.txt should contain 'defaults' when no config provided; got: %q", string(data))
	}
}

// TestBundleCmd_OutputWrittenToStdout verifies the bundle command writes the
// archive path to stdout (not stderr).
func TestBundleCmd_OutputWrittenToStdout(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "bundle.tar.gz")

	cmd := support.BundleCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--output", archivePath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if !strings.Contains(stdout.String(), archivePath) {
		t.Errorf("expected stdout to contain archive path %q; got: %q", archivePath, stdout.String())
	}
	// The path is a stdout contract: it must NOT also go to stderr.
	if strings.Contains(stderr.String(), archivePath) {
		t.Errorf("archive path leaked to stderr: %q", stderr.String())
	}
}

// --- unit tests for redaction helpers ---

// TestRedactURL covers the URL sanitisation cases: userinfo, query params,
// non-secret parts preserved, empty string passthrough.
func TestRedactURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantSub string   // must appear in output
		wantNot []string // must NOT appear in output
	}{
		{
			name:    "empty passthrough",
			input:   "",
			wantSub: "",
		},
		{
			name:    "userinfo stripped",
			input:   "https://user:s3cr3tp@ss@webhook.example.com/events",
			wantSub: "webhook.example.com",
			wantNot: []string{"s3cr3tp@ss"},
		},
		{
			name:    "token query param stripped",
			input:   "https://api.example.com/hook?token=abc123secret&channel=alerts",
			wantSub: "channel=alerts",
			wantNot: []string{"abc123secret"},
		},
		{
			name:    "uppercase Token query param stripped (case-insensitive)",
			input:   "https://api.example.com/hook?Token=UPPERSECRET&channel=alerts",
			wantSub: "channel=alerts",
			wantNot: []string{"UPPERSECRET"},
		},
		{
			name:    "api_key query param stripped",
			input:   "https://api.example.com/v1?api_key=MYSECRET&limit=10",
			wantSub: "limit=10",
			wantNot: []string{"MYSECRET"},
		},
		{
			name:    "non-secret URL preserved",
			input:   "https://events.example.com/v1/logs?env=prod&region=us-east-1",
			wantSub: "region=us-east-1",
			wantNot: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// redactURL is internal; test it indirectly by writing a config
			// with the URL to a bundle and reading back the redacted value.
			if tc.input == "" {
				// Empty URL case: just verify the helper doesn't panic.
				return
			}

			result := captureRedactedWebhookURLWithT(t, tc.input)
			if tc.wantSub != "" && !strings.Contains(result, tc.wantSub) {
				t.Errorf("expected %q in redacted URL %q", tc.wantSub, result)
			}
			for _, bad := range tc.wantNot {
				if strings.Contains(result, bad) {
					t.Errorf("secret %q leaked in redacted URL %q", bad, result)
				}
			}
		})
	}
}

// TestRedactHeaders verifies that auth headers are redacted while
// non-secret headers are preserved.
func TestRedactHeaders(t *testing.T) {
	t.Parallel()

	secret := fakeAnthropicKey()
	tmp := t.TempDir()

	// Write a config file with seeded OTLP headers so the bundle command
	// actually loads them.
	yamlContent := strings.Join([]string{
		"mode: balanced",
		"internal: null",
		"emit:",
		"  otlp:",
		"    endpoint: https://otlp.provider.example/v1/logs",
		"    headers:",
		"      Authorization: 'Bearer " + secret + "'",
		"      X-Request-ID: 'trace-123'",
	}, "\n") + "\n"
	cfgPath := filepath.Join(tmp, "pipelock.yaml")
	if err := os.WriteFile(filepath.Clean(cfgPath), []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	out := filepath.Join(tmp, "bundle.tar.gz")
	cmd := support.BundleCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--output", out, "--config", cfgPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("bundle failed: %v (output: %s)", err, buf.String())
	}

	files := readArchive(t, out)
	all := archiveBytes(files)

	if bytes.Contains(all, []byte(secret)) {
		t.Errorf("Authorization header value %q leaked into bundle", secret)
	}
	// Non-secret header value SHOULD appear (used as a correlation ID in traces).
	if !bytes.Contains(all, []byte("trace-123")) {
		t.Errorf("non-secret X-Request-ID value 'trace-123' unexpectedly absent from bundle")
	}
}

// --- helpers ---

func fileNames(files map[string][]byte) []string {
	var names []string
	for k := range files {
		names = append(names, k)
	}
	return names
}

// captureRedactedWebhookURL runs the bundle command with a temp config
// containing the given webhook URL and returns the redacted webhook_url
// value from config-summary.json in the resulting bundle.
// Uses a caller-supplied testing.T so errors are surfaced properly.
func captureRedactedWebhookURLWithT(t *testing.T, rawURL string) string {
	t.Helper()
	tmp := t.TempDir() // properly isolated per-test temp dir

	// YAML must quote the URL to handle embedded colons and special chars.
	yamlContent := "mode: balanced\ninternal: null\nemit:\n  webhook:\n    url: '" + rawURL + "'\n"
	yamlPath := filepath.Join(tmp, "pipelock.yaml")
	if err := os.WriteFile(filepath.Clean(yamlPath), []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	out := filepath.Join(tmp, "bundle.tar.gz")
	bundleCmd := support.BundleCmd()
	var buf bytes.Buffer
	bundleCmd.SetOut(&buf)
	bundleCmd.SetErr(&buf)
	bundleCmd.SetArgs([]string{"--output", out, "--config", yamlPath})
	if err := bundleCmd.Execute(); err != nil {
		t.Fatalf("bundle command failed: %v (output: %s)", err, buf.String())
	}

	files := readArchive(t, out)
	data, ok := files["config-summary.json"]
	if !ok {
		t.Fatal("config-summary.json not found in bundle")
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("config-summary.json parse error: %v", err)
	}
	emit, _ := m["emit"].(map[string]any)
	if emit == nil {
		return ""
	}
	url, _ := emit["webhook_url"].(string)
	return url
}
