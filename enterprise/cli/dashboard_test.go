//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signingflag"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// dashTestToken is built by concatenation so credential linters do not flag a
// literal secret; it is a test-only value.
var dashTestToken = "dash-test-" + "operator-token"

type dashSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *dashSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *dashSyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *dashSyncBuffer) contains(s string) bool {
	return strings.Contains(b.String(), s)
}

func newDashKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func issueDashLicense(t *testing.T, priv ed25519.PrivateKey, features []string) string {
	t.Helper()
	tok, err := license.Issue(license.License{
		ID:        "lic_dash_test",
		Email:     "test@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Features:  features,
	}, priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

// setDashLicenseEnv pins every license-relevant env variable so tests are
// hermetic regardless of the host environment.
func setDashLicenseEnv(t *testing.T, tok, pubHex string) {
	t.Helper()
	t.Setenv(license.EnvLicenseKey, tok)
	t.Setenv(license.EnvLicensePublicKey, pubHex)
	t.Setenv(license.EnvLicenseCRLFile, "")
	t.Setenv(license.EnvLicenseIntermediateFile, "")
}

func writeDashTokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dashboard.token")
	if err := os.WriteFile(path, []byte(dashTestToken+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestDashboardCmd_Tree(t *testing.T) {
	cmd := DashboardCmd()
	wantCommands := map[string]bool{
		"backup": false, "restore": false, "rebuild-read-model": false,
	}
	for _, child := range cmd.Commands() {
		if _, ok := wantCommands[child.Name()]; ok {
			wantCommands[child.Name()] = true
		}
	}
	for name, found := range wantCommands {
		if !found {
			t.Errorf("dashboard command missing %q", name)
		}
	}
	if cmd.Use != "dashboard" {
		t.Fatalf("Use = %q, want dashboard", cmd.Use)
	}
	serve, _, err := cmd.Find([]string{"serve"})
	if err != nil || serve.Use != "serve" {
		t.Fatalf("dashboard serve subcommand not found: %v", err)
	}
	for _, flag := range []string{"listen", "receipt-dir", "config", "exemption-store", "delivery-inbox", "read-model-index", "legal-hold-store", "auth-token-file", "raw-token-file", "compliance-token-file", "runtime-snapshot-file", "trusted-signer", "license-crl-file", "anchor-expected", "anchor-local-log", "rekor-log-key", "tls-cert", "tls-key", "client-ca-file", "require-client-cert", "client-cert-role-map"} {
		if serve.Flags().Lookup(flag) == nil {
			t.Errorf("serve is missing --%s", flag)
		}
	}
}

func writeDashRawTokenFile(t *testing.T) (path, token string) {
	t.Helper()
	token = "dash-raw-" + "elevated-token"
	path = filepath.Join(t.TempDir(), "dashboard-raw.token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path, token
}

func writeDashConfigFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	body := []byte(`mode: balanced
response_scanning:
  enabled: false
  exempt_domains:
    - api.vendor.example
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	return path
}

func TestDashboardServe_RawTokenMustDifferFromAuthToken(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))
	// Point --raw-token-file at the SAME file as --auth-token-file: identical
	// tokens make the two roles indistinguishable and must be rejected.
	tokenFile := writeDashTokenFile(t)
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", t.TempDir(),
		"--auth-token-file", tokenFile,
		"--raw-token-file", tokenFile,
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("identical raw+auth token: want must-differ error, got %v", err)
	}
}

func TestDashboardServe_RejectsUnreadableRawTokenFile(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", t.TempDir(),
		"--auth-token-file", writeDashTokenFile(t),
		"--raw-token-file", filepath.Join(t.TempDir(), "missing.raw-token"),
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--raw-token-file") {
		t.Fatalf("missing raw token file: want --raw-token-file error, got %v", err)
	}
}

func TestDashboardServe_RawTokenElevatesAndAudits(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))
	rawTokenFile, rawToken := writeDashRawTokenFile(t)

	out := &dashSyncBuffer{}
	errOut := &dashSyncBuffer{}
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", t.TempDir(),
		"--auth-token-file", writeDashTokenFile(t),
		"--raw-token-file", rawTokenFile,
		"--listen", "127.0.0.1:0",
	})
	cmd.SetOut(out)
	cmd.SetErr(errOut)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	testwait.For(t, 10*time.Second, func() bool { return out.contains("dashboard listening on") },
		"serve never printed the listening banner; stderr: %s", errOut.String())
	m := regexp.MustCompile(`listening on http://(127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("could not parse listen address from %q", out.String())
	}
	base := "http://" + m[1]
	client := &http.Client{Timeout: 5 * time.Second}

	do := func(tok string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	// The raw token is a valid operator token (metadata-level access too).
	if code := do(rawToken); code != http.StatusOK {
		t.Fatalf("raw token access = %d, want 200", code)
	}
	// Its access is audited on stderr with the raw role.
	testwait.For(t, 5*time.Second, func() bool { return errOut.contains("role=raw") },
		"raw access was not audited; stderr: %s", errOut.String())

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve shutdown error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not shut down")
	}
}

func TestDashboardServe_FailsClosedWithoutLicense(t *testing.T) {
	setDashLicenseEnv(t, "", "")
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{"--receipt-dir", t.TempDir(), "--auth-token-file", writeDashTokenFile(t)})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if !errors.Is(err, license.ErrAgentsLicenseRequired) {
		t.Fatalf("serve without license: want ErrAgentsLicenseRequired, got %v", err)
	}
}

func TestDashboardServe_FailsClosedWithoutAgentsFeature(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAssess}), hex.EncodeToString(pub))
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{"--receipt-dir", t.TempDir(), "--auth-token-file", writeDashTokenFile(t)})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if !errors.Is(err, license.ErrAgentsLicenseRequired) {
		t.Fatalf("serve without agents feature: want ErrAgentsLicenseRequired, got %v", err)
	}
}

func TestVerifyDashboardLicenseWithOptionsAcceptsAgentsOrFleet(t *testing.T) {
	tests := []struct {
		name        string
		features    []string
		wantErr     error
		wantFeature string
	}{
		{
			name:        "agents",
			features:    []string{license.FeatureAgents},
			wantFeature: license.FeatureAgents,
		},
		{
			name:        "fleet",
			features:    []string{license.FeatureFleet},
			wantFeature: license.FeatureFleet,
		},
		{
			name:     "neither",
			features: []string{license.FeatureAssess},
			wantErr:  license.ErrAgentsLicenseRequired,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, priv := newDashKeyPair(t)
			setDashLicenseEnv(t, issueDashLicense(t, priv, tt.features), hex.EncodeToString(pub))
			got, err := verifyDashboardLicenseWithOptions(license.FleetVerifyInputs{})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				for _, want := range []string{"dashboard", license.FeatureAgents, license.FeatureFleet} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error = %v, want message containing %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("verifyDashboardLicenseWithOptions() error = %v", err)
			}
			if !got.HasFeature(tt.wantFeature) {
				t.Fatalf("license features = %v, want %q", got.Features, tt.wantFeature)
			}
		})
	}
}

func TestDashboardServe_RefusesNonLoopbackWithoutTLS(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", t.TempDir(),
		"--auth-token-file", writeDashTokenFile(t),
		"--listen", "0.0.0.0:0",
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "refusing to serve") {
		t.Fatalf("non-loopback cleartext listen: want refusal, got %v", err)
	}
}

func TestDashboardServe_RejectsMissingReceiptDir(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", filepath.Join(t.TempDir(), "does-not-exist"),
		"--auth-token-file", writeDashTokenFile(t),
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--receipt-dir") {
		t.Fatalf("missing receipt dir: want --receipt-dir error, got %v", err)
	}
}

func TestDashboardServe_RejectsBadConfigPath(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", t.TempDir(),
		"--auth-token-file", writeDashTokenFile(t),
		"--config", filepath.Join(t.TempDir(), "missing.yaml"),
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--config") {
		t.Fatalf("missing config: want --config error, got %v", err)
	}
}

func TestDashboardServe_RejectsConfigDirectory(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", t.TempDir(),
		"--auth-token-file", writeDashTokenFile(t),
		"--config", t.TempDir(),
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--config") {
		t.Fatalf("config directory: want --config error, got %v", err)
	}
}

func TestDashboardServe_RejectsMalformedConfig(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))
	configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(configPath, []byte("mode: balanced\nresponse_scanning: ["), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", t.TempDir(),
		"--auth-token-file", writeDashTokenFile(t),
		"--config", configPath,
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--config") {
		t.Fatalf("malformed config: want --config error, got %v", err)
	}
}

func TestDashboardServe_InspectionConfigIgnoresUnreadableReferencedFile(t *testing.T) {
	// A read-only inventory must not resolve unrelated runtime-side files it does
	// not need. An unreadable license_file referenced by --config (a file the
	// exemptions view never uses) must NOT prevent the dashboard from starting.
	// This exercises the real serve path: runDashboardServe loads --config via
	// config.LoadForInspection, so a regression back to config.Load (which reads
	// license_file) would fail before the listening banner and fail this test.
	// Empty env license so config.Load, if it were used, would resolve the
	// config's license_file (env takes priority over license_file). The
	// dashboard's own license is supplied via the lic argument, independent of
	// --config, so config's unreadable license_file only bites the config load.
	t.Setenv(license.EnvLicenseKey, "")
	dir := t.TempDir()
	licensePath := filepath.Join(dir, "unrelated-license.token")
	if err := os.WriteFile(licensePath, []byte("unused"), 0o600); err != nil {
		t.Fatalf("WriteFile(license): %v", err)
	}
	if err := os.Chmod(licensePath, 0); err != nil {
		t.Fatalf("Chmod(license): %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(licensePath, 0o600) })
	configPath := filepath.Join(dir, "pipelock.yaml")
	body := "mode: balanced\nlicense_file: unrelated-license.token\nbrowser_shield:\n  enabled: false\n  exempt_domains:\n    - my.internal.example\n"
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}

	out := &dashSyncBuffer{}
	errOut := &dashSyncBuffer{}
	cmd := dashboardServeCmd()
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd.SetContext(ctx)

	done := make(chan error, 1)
	go func() {
		done <- runDashboardServe(cmd, dashboardServeOptions{
			listen:        "127.0.0.1:0",
			receiptDir:    t.TempDir(),
			authTokenFile: writeDashTokenFile(t),
			configFile:    configPath,
		}, license.License{Features: []string{license.FeatureAgents}})
	}()

	// LoadForInspection reaches the listening banner. A regression to config.Load
	// returns the unreadable-license_file error before the banner and fails here.
	testwait.For(t, 10*time.Second, func() bool {
		select {
		case err := <-done:
			t.Fatalf("serve returned before the listening banner (config load read the unrelated license_file?): %v", err)
			return false
		default:
			return out.contains("dashboard listening on")
		}
	}, "serve never printed the listening banner; stderr: %s", errOut.String())

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not shut down after context cancel")
	}
}

func TestDashboardServe_InspectionConfigRejectsMalformedYAML(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(configPath, []byte("mode: balanced\n\tbroken: [::\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	if _, err := config.LoadForInspection(configPath); err == nil {
		t.Fatal("LoadForInspection(malformed yaml) = nil error, want parse failure (fail closed)")
	}
}

func TestDashboardServe_EndToEnd(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))

	out := &dashSyncBuffer{}
	errOut := &dashSyncBuffer{}
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", t.TempDir(),
		"--auth-token-file", writeDashTokenFile(t),
		"--config", writeDashConfigFile(t),
		"--listen", "127.0.0.1:0",
	})
	cmd.SetOut(out)
	cmd.SetErr(errOut)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	testwait.For(t, 10*time.Second, func() bool { return out.contains("dashboard listening on") },
		"serve never printed the listening banner; stderr: %s", errOut.String())

	addrRe := regexp.MustCompile(`listening on http://(127\.0\.0\.1:\d+)`)
	m := addrRe.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("could not parse listen address from output %q", out.String())
	}
	base := "http://" + m[1]
	client := &http.Client{Timeout: 5 * time.Second}

	get := func(auth string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /: %v", err)
		}
		return resp
	}

	t.Run("no auth is 401 with challenge", func(t *testing.T) {
		resp := get("")
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Basic") {
			t.Errorf("missing WWW-Authenticate Basic challenge")
		}
	})

	t.Run("wrong bearer is 401", func(t *testing.T) {
		resp := get("Bearer wrong-value")
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("bearer token is 200 html", func(t *testing.T) {
		resp := get("Bearer " + dashTestToken)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Errorf("Content-Type = %q, want text/html", ct)
		}
		if resp.Header.Get("Content-Security-Policy") == "" {
			t.Errorf("missing Content-Security-Policy header")
		}
	})

	t.Run("exemptions uses loaded config", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/exemptions", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+dashTestToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /exemptions: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		text := string(body)
		// The metadata operator token does not carry raw access, so configured
		// values are redacted; the view still shows the inventory, states, and
		// the redaction note.
		for _, want := range []string{"Exemptions inventory", "raw access is required", "inert"} {
			if !strings.Contains(text, want) {
				t.Fatalf("body missing %q: %s", want, text)
			}
		}
		if strings.Contains(text, "api.vendor.example") {
			t.Fatalf("metadata view leaked a configured domain: %s", text)
		}
	})

	t.Run("basic auth password is 200", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.SetBasicAuth("operator", dashTestToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("authenticated POST is rejected", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+dashTestToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST /: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", resp.StatusCode)
		}
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned error on shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not shut down after context cancel")
	}
}

func TestDashboardServe_RejectsBadTokenFile(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", t.TempDir(),
		"--auth-token-file", filepath.Join(t.TempDir(), "missing.token"),
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "read --auth-token-file") {
		t.Fatalf("missing token file: want read error, got %v", err)
	}
}

func TestDashboardServe_RejectsBadTrustedSigner(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", t.TempDir(),
		"--auth-token-file", writeDashTokenFile(t),
		"--trusted-signer", "inline=not-a-key",
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "parse public key") {
		t.Fatalf("bad trusted signer: want parse error, got %v", err)
	}
}

func TestDashboardServe_InvalidTLSMaterialFailsServe(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))
	dir := t.TempDir()
	badCert := filepath.Join(dir, "cert.pem")
	badKey := filepath.Join(dir, "key.pem")
	for _, p := range []string{badCert, badKey} {
		if err := os.WriteFile(p, []byte("not pem"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", t.TempDir(),
		"--auth-token-file", writeDashTokenFile(t),
		"--listen", "127.0.0.1:0",
		"--tls-cert", badCert,
		"--tls-key", badKey,
	})
	out := &dashSyncBuffer{}
	cmd.SetOut(out)
	cmd.SetErr(&dashSyncBuffer{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("invalid TLS material: want serve error, got nil")
	}
	if out.contains("dashboard listening on") {
		t.Fatalf("invalid TLS material printed listening banner before refusing startup: %q", out.String())
	}
}

func TestDashboardAuthorizeFunc(t *testing.T) {
	authorize := dashboardAuthorizeFunc(func(r *http.Request) bool {
		return dashboardTokenMatches(r, dashTestToken)
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := authorize(req); err == nil {
		t.Fatal("unauthenticated request: want error, got nil")
	}
	req.Header.Set("Authorization", "Bearer "+dashTestToken)
	if err := authorize(req); err != nil {
		t.Fatalf("authenticated request: want nil, got %v", err)
	}
}

func TestDashboardGlobalAuthorizationScopesComplianceToken(t *testing.T) {
	operatorAuthorized := func(r *http.Request) bool {
		return dashboardTokenMatches(r, dashTestToken)
	}
	complianceAuthorized := func(r *http.Request) bool {
		return dashboardTokenMatches(r, "auditor-token")
	}
	authorized := dashboardGlobalAuthorized(operatorAuthorized, complianceAuthorized)

	for _, tc := range []struct {
		name       string
		path       string
		token      string
		wantStatus int
	}{
		{name: "operator reaches non-compliance route", path: "/", token: dashTestToken, wantStatus: http.StatusNoContent},
		{name: "compliance reaches compliance route", path: "/compliance", token: "auditor-token", wantStatus: http.StatusNoContent},
		{name: "compliance rejected before non-compliance handler", path: "/", token: "auditor-token", wantStatus: http.StatusUnauthorized},
		{name: "compliance rejected from compliance subpath", path: "/compliance/export", token: "auditor-token", wantStatus: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			handler := dashboardAuthHandler(authorized, nil, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.wantStatus)
			}
			wantCalled := tc.wantStatus == http.StatusNoContent
			if called != wantCalled {
				t.Fatalf("inner handler called = %v, want %v", called, wantCalled)
			}
			if err := dashboardAuthorizeFunc(authorized)(req); (err == nil) != wantCalled {
				t.Fatalf("global Authorize error = %v, allowed = %v", err, wantCalled)
			}
		})
	}
}

func TestDashboardServe_RejectsReceiptDirThatIsAFile(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))
	file := filepath.Join(t.TempDir(), "receipts.log")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{"--receipt-dir", file, "--auth-token-file", writeDashTokenFile(t)})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("file as receipt dir: want not-a-directory error, got %v", err)
	}
}

// TestRunDashboardServe_BindFailure calls runDashboardServe directly (nil
// command context) with a port that is already bound, covering the
// context-fallback and listener-error paths.
func TestRunDashboardServe_BindFailure(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	opts := dashboardServeOptions{
		listen:        ln.Addr().String(),
		receiptDir:    t.TempDir(),
		authTokenFile: writeDashTokenFile(t),
	}
	err = runDashboardServe(cmd, opts, license.License{Features: []string{license.FeatureAgents}})
	if err == nil {
		t.Fatal("bind to an in-use port: want error, got nil")
	}
}

// writeDashTLSCert writes a self-signed server certificate for 127.0.0.1 and
// returns the cert/key file paths plus a pool that trusts the certificate.
func writeDashTLSCert(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	pub, priv := newDashKeyPair(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pipelock-dashboard-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(cert): %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(key): %v", err)
	}
	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM failed")
	}
	return certFile, keyFile, pool
}

func TestDashboardServe_TLSEndToEnd(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))
	certFile, keyFile, pool := writeDashTLSCert(t)

	out := &dashSyncBuffer{}
	errOut := &dashSyncBuffer{}
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", t.TempDir(),
		"--auth-token-file", writeDashTokenFile(t),
		"--listen", "127.0.0.1:0",
		"--tls-cert", certFile,
		"--tls-key", keyFile,
	})
	cmd.SetOut(out)
	cmd.SetErr(errOut)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	testwait.For(t, 10*time.Second, func() bool { return out.contains("dashboard listening on https://") },
		"serve never printed the TLS listening banner; stderr: %s", errOut.String())

	addrRe := regexp.MustCompile(`listening on https://(127\.0\.0\.1:\d+)`)
	m := addrRe.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("could not parse listen address from output %q", out.String())
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+m[1]+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+dashTestToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET over TLS: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned error on shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not shut down after context cancel")
	}
}

func TestDashboardTokenMatches(t *testing.T) {
	tests := []struct {
		name  string
		token string
		setup func(*http.Request)
		want  bool
	}{
		{"empty configured token fails closed", "", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer ")
		}, false},
		{"no header", dashTestToken, func(*http.Request) {}, false},
		{"bearer match", dashTestToken, func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+dashTestToken)
		}, true},
		{"bearer prefix case-insensitive", dashTestToken, func(r *http.Request) {
			r.Header.Set("Authorization", "BEARER "+dashTestToken)
		}, true},
		{"bearer mismatch", dashTestToken, func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer nope")
		}, false},
		{"basic password match, any username", dashTestToken, func(r *http.Request) {
			r.SetBasicAuth("whoever", dashTestToken)
		}, true},
		{"basic password mismatch", dashTestToken, func(r *http.Request) {
			r.SetBasicAuth("whoever", "nope")
		}, false},
		{"token as basic username does not count", dashTestToken, func(r *http.Request) {
			r.SetBasicAuth(dashTestToken, "")
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			tc.setup(req)
			if got := dashboardTokenMatches(req, tc.token); got != tc.want {
				t.Errorf("dashboardTokenMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDashboardAuthorizePermissionFunc(t *testing.T) {
	metaReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatalf("NewRequest meta: %v", err)
	}
	metaReq.Header.Set("Authorization", "Bearer "+dashTestToken)

	rawReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatalf("NewRequest raw: %v", err)
	}
	rawReq.Header.Set("Authorization", "Bearer raw-"+dashTestToken)

	authorize := dashboardAuthorizePermissionFunc(
		func(r *http.Request) bool { return dashboardTokenMatches(r, dashTestToken) },
		func(r *http.Request) bool { return dashboardTokenMatches(r, "raw-"+dashTestToken) },
		func(*http.Request) bool { return false },
	)

	for _, permission := range []dashboard.Permission{
		dashboard.PermissionEvidenceRead,
		dashboard.PermissionExemptionsRead,
		dashboard.PermissionAgentsRead,
		dashboard.PermissionBudgetsRead,
		dashboard.PermissionFleetRead,
		dashboard.PermissionSignedActionRead,
		dashboard.PermissionIncidentRead,
	} {
		if err := authorize(metaReq, permission); err != nil {
			t.Fatalf("metadata token denied %s: %v", permission, err)
		}
	}
	if err := authorize(metaReq, dashboard.PermissionTrustKeysRead); err == nil {
		t.Fatal("metadata token unexpectedly granted trust and keys permission")
	}
	if err := authorize(rawReq, dashboard.PermissionTrustKeysRead); err != nil {
		t.Fatalf("raw token denied trust and keys permission: %v", err)
	}
	if err := authorize(metaReq, dashboard.PermissionRawRead); err == nil {
		t.Fatal("metadata token unexpectedly granted raw permission")
	}
	if err := authorize(rawReq, dashboard.PermissionRawRead); err != nil {
		t.Fatalf("raw token denied raw permission: %v", err)
	}
	if err := authorize(metaReq, dashboard.Permission("dashboard:unknown")); err == nil {
		t.Fatal("unknown dashboard permission unexpectedly allowed")
	}
}

func TestDashboardAuthorizePermissionFunc_ComplianceAuditorIsReadOnly(t *testing.T) {
	auditorReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/compliance", nil)
	if err != nil {
		t.Fatalf("NewRequest auditor: %v", err)
	}
	auditorReq.Header.Set("Authorization", "Bearer auditor-token")
	authorize := dashboardAuthorizePermissionFunc(
		func(*http.Request) bool { return false },
		func(*http.Request) bool { return false },
		func(r *http.Request) bool { return dashboardTokenMatches(r, "auditor-token") },
	)
	if err := authorize(auditorReq, dashboard.PermissionComplianceRead); err != nil {
		t.Fatalf("auditor denied compliance read: %v", err)
	}
	for _, permission := range dashboard.AllPermissions() {
		if permission == dashboard.PermissionComplianceRead {
			continue
		}
		if err := authorize(auditorReq, permission); err == nil {
			t.Fatalf("auditor unexpectedly granted %s", permission)
		}
	}
}

// TestDashboardAuthorizePermissionFunc_MapsEveryPermission fails when a new
// dashboard route permission is added without updating the CLI token mapping.
// An unmapped permission fails closed in dashboardAuthorizePermissionFunc, so
// forgetting the mapping would silently 403 the new route in `dashboard serve`.
func TestDashboardAuthorizePermissionFunc_MapsEveryPermission(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	authorize := dashboardAuthorizePermissionFunc(
		func(*http.Request) bool { return true },
		func(*http.Request) bool { return true },
		func(*http.Request) bool { return false },
	)
	for _, permission := range dashboard.AllPermissions() {
		if err := authorize(req, permission); err != nil {
			t.Errorf("dashboard permission %s has no CLI token mapping: %v", permission, err)
		}
	}
}

func TestValidateDashboardListen(t *testing.T) {
	tests := []struct {
		name    string
		opts    dashboardServeOptions
		wantErr string
	}{
		{"loopback v4 ok", dashboardServeOptions{listen: "127.0.0.1:8896"}, ""},
		{"loopback v6 ok", dashboardServeOptions{listen: "[::1]:8896"}, ""},
		{"localhost hostname refused", dashboardServeOptions{listen: "localhost:8896"}, "refusing"},
		{"all interfaces refused", dashboardServeOptions{listen: "0.0.0.0:8896"}, "refusing"},
		{"private address refused", dashboardServeOptions{listen: "10.0.0.5:8896"}, "refusing"},
		{"hostname refused", dashboardServeOptions{listen: "dash.internal:8896"}, "refusing"},
		{"empty host refused", dashboardServeOptions{listen: ":8896"}, "refusing"},
		{"malformed listen", dashboardServeOptions{listen: "not-an-addr"}, "--listen"},
		{"tls pair allows non-loopback", dashboardServeOptions{listen: "0.0.0.0:8896", tlsCert: "c.pem", tlsKey: "k.pem"}, ""},
		{"cert without key refused", dashboardServeOptions{listen: "127.0.0.1:8896", tlsCert: "c.pem"}, "must be set together"},
		{"key without cert refused", dashboardServeOptions{listen: "127.0.0.1:8896", tlsKey: "k.pem"}, "must be set together"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDashboardListen(tc.opts)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestDashboardTrustCRLSource(t *testing.T) {
	originalEmbedded := license.PublicKeyHex
	license.PublicKeyHex = ""
	t.Cleanup(func() { license.PublicKeyHex = originalEmbedded })
	t.Setenv(license.EnvLicenseCRLFile, "")
	t.Setenv(license.EnvLicensePublicKey, "")

	t.Run("not configured", func(t *testing.T) {
		source, err := dashboardTrustCRLSource("")
		if err != nil || source != nil {
			t.Fatalf("source configured=%t err=%v, want false nil", source != nil, err)
		}
	})

	t.Run("configured without root fails closed", func(t *testing.T) {
		_, err := dashboardTrustCRLSource(filepath.Join(t.TempDir(), "crl.json"))
		if err == nil || !strings.Contains(err.Error(), "no license root") {
			t.Fatalf("error = %v, want missing root", err)
		}
	})

	t.Run("malformed root fails closed", func(t *testing.T) {
		t.Setenv(license.EnvLicensePublicKey, "not-a-key")
		_, err := dashboardTrustCRLSource(filepath.Join(t.TempDir(), "crl.json"))
		if err == nil || !strings.Contains(err.Error(), "parse license root") {
			t.Fatalf("error = %v, want root parse failure", err)
		}
	})

	t.Run("verified then corrupt reload", func(t *testing.T) {
		pub, priv := newDashKeyPair(t)
		t.Setenv(license.EnvLicensePublicKey, hex.EncodeToString(pub))
		now := time.Now().UTC()
		crl, err := license.SignCRL(license.CRLPayload{
			Version: license.CRLVersion, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
			Revoked: []license.RevokedLicense{},
		}, priv)
		if err != nil {
			t.Fatalf("SignCRL: %v", err)
		}
		data, err := json.Marshal(crl)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		path := filepath.Join(t.TempDir(), "crl.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		source, err := dashboardTrustCRLSource(path)
		if err != nil {
			t.Fatalf("dashboardTrustCRLSource: %v", err)
		}
		loaded, err := source()
		if err != nil || loaded == nil || loaded.SHA256 == "" {
			t.Fatalf("loaded=%+v err=%v", loaded, err)
		}
		if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
			t.Fatalf("corrupt CRL: %v", err)
		}
		if _, err := source(); err == nil || !strings.Contains(err.Error(), "verify license CRL") {
			t.Fatalf("corrupt reload error = %v", err)
		}
	})
}

func TestRunDashboardServe_TrustVerifierStartupFailures(t *testing.T) {
	t.Setenv(license.EnvLicenseCRLFile, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	originalEmbedded := license.PublicKeyHex
	license.PublicKeyHex = ""
	t.Cleanup(func() { license.PublicKeyHex = originalEmbedded })

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte(dashTestToken), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	base := dashboardServeOptions{
		listen: dashboardDefaultListen, receiptDir: dir, authTokenFile: tokenPath,
	}
	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	t.Run("invalid Rekor key", func(t *testing.T) {
		opts := base
		opts.rekorLogKeys = []string{"not-a-key"}
		err := runDashboardServe(cmd, opts, license.License{})
		if err == nil || !strings.Contains(err.Error(), "anchor verifier") {
			t.Fatalf("error = %v, want anchor verifier failure", err)
		}
	})

	t.Run("CRL without root", func(t *testing.T) {
		opts := base
		opts.licenseCRLFile = filepath.Join(dir, "crl.json")
		err := runDashboardServe(cmd, opts, license.License{})
		if err == nil || !strings.Contains(err.Error(), "no license root") {
			t.Fatalf("error = %v, want CRL root failure", err)
		}
	})
}

func TestParseTrustedSigners(t *testing.T) {
	pub, _ := newDashKeyPair(t)
	keyHex := hex.EncodeToString(pub)
	keyFile := filepath.Join(t.TempDir(), "signer.pub")
	if err := os.WriteFile(keyFile, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Run("empty returns nil", func(t *testing.T) {
		got, err := signingflag.ParseTrustedSigners(nil)
		if err != nil || got != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", got, err)
		}
	})

	t.Run("inline hex with source", func(t *testing.T) {
		got, err := signingflag.ParseTrustedSigners([]string{"inline=" + keyHex + ",source=ops runbook"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got[keyHex] != (dashboard.TrustedKey{Source: "ops runbook", ProvenanceKind: "static inline", Location: "--trusted-signer"}) {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("empty parts from trailing comma are skipped", func(t *testing.T) {
		got, err := signingflag.ParseTrustedSigners([]string{"inline=" + keyHex + ","})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if _, ok := got[keyHex]; !ok {
			t.Fatalf("got %+v, want key present", got)
		}
	})

	t.Run("file key with default source", func(t *testing.T) {
		got, err := signingflag.ParseTrustedSigners([]string{"file=" + keyFile})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got[keyHex] != (dashboard.TrustedKey{Source: signingflag.DefaultSource, ProvenanceKind: "imported file", Location: keyFile}) {
			t.Fatalf("got %+v", got)
		}
	})

	errCases := []struct {
		name string
		in   string
		want string
	}{
		{"inline and file exclusive", "inline=" + keyHex + ",file=" + keyFile, "mutually exclusive"},
		{"neither inline nor file", "source=x", "one of inline= or file= is required"},
		{"unknown kv key", "inline=" + keyHex + ",color=green", "unknown key"},
		{"missing equals", "justakey", "expected key=value"},
		{"duplicate inline rejected", "inline=" + keyHex + ",inline=" + keyHex, "inline= may appear only once"},
		{"duplicate file rejected", "file=" + keyFile + ",file=" + keyFile, "file= may appear only once"},
		{"duplicate source rejected", "inline=" + keyHex + ",source=one,source=two", "source= may appear only once"},
		{"empty inline rejected", "inline= ", "inline= value is empty"},
		{"empty file rejected", "file= ", "file= value is empty"},
		{"garbage key rejected", "inline=zz-not-a-key", "parse public key"},
		{"unreadable file", "file=" + filepath.Join(t.TempDir(), "nope.pub"), "read key file"},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := signingflag.ParseTrustedSigners([]string{tc.in})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}

	t.Run("duplicate key rejected", func(t *testing.T) {
		_, err := signingflag.ParseTrustedSigners([]string{"inline=" + keyHex, "file=" + keyFile})
		if err == nil || !strings.Contains(err.Error(), "duplicate key") {
			t.Fatalf("want duplicate-key error, got %v", err)
		}
	})
}

func TestDashboardRuntimeHasFeature(t *testing.T) {
	now := time.Now().Unix()
	tests := []struct {
		name    string
		lic     license.License
		feature string
		want    bool
	}{
		{"valid with feature", license.License{Features: []string{license.FeatureAgents}, ExpiresAt: now + 3600}, license.FeatureAgents, true},
		{"perpetual with feature", license.License{Features: []string{license.FeatureAgents}}, license.FeatureAgents, true},
		{"expired at runtime", license.License{Features: []string{license.FeatureAgents}, ExpiresAt: now - 1}, license.FeatureAgents, false},
		{"missing feature", license.License{Features: []string{license.FeatureAssess}, ExpiresAt: now + 3600}, license.FeatureAgents, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := dashboardRuntimeHasFeature(tc.lic)(tc.feature); got != tc.want {
				t.Errorf("hasFeature(%q) = %v, want %v", tc.feature, got, tc.want)
			}
		})
	}
}

func TestLoadDashboardTokenFile(t *testing.T) {
	t.Run("valid token trimmed", func(t *testing.T) {
		got, err := loadDashboardTokenFile("--auth-token-file", writeDashTokenFile(t))
		if err != nil || got != dashTestToken {
			t.Fatalf("got (%q, %v), want (%q, nil)", got, err, dashTestToken)
		}
	})
	t.Run("empty path", func(t *testing.T) {
		if _, err := loadDashboardTokenFile("--auth-token-file", "  "); err == nil ||
			!strings.Contains(err.Error(), "required") {
			t.Fatalf("want required error, got %v", err)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		if _, err := loadDashboardTokenFile("--auth-token-file", filepath.Join(t.TempDir(), "nope")); err == nil ||
			!strings.Contains(err.Error(), "read --auth-token-file") {
			t.Fatalf("want read error, got %v", err)
		}
	})
	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.token")
		if err := os.WriteFile(path, []byte(" \n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := loadDashboardTokenFile("--auth-token-file", path); err == nil ||
			!strings.Contains(err.Error(), "is empty") {
			t.Fatalf("want empty error, got %v", err)
		}
	})
}
