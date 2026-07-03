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
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
	"github.com/luckyPipewrench/pipelock/internal/license"
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
	if cmd.Use != "dashboard" {
		t.Fatalf("Use = %q, want dashboard", cmd.Use)
	}
	serve, _, err := cmd.Find([]string{"serve"})
	if err != nil || serve.Use != "serve" {
		t.Fatalf("dashboard serve subcommand not found: %v", err)
	}
	for _, flag := range []string{"listen", "receipt-dir", "auth-token-file", "trusted-signer", "license-crl-file", "tls-cert", "tls-key"} {
		if serve.Flags().Lookup(flag) == nil {
			t.Errorf("serve is missing --%s", flag)
		}
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

func TestDashboardServe_EndToEnd(t *testing.T) {
	pub, priv := newDashKeyPair(t)
	setDashLicenseEnv(t, issueDashLicense(t, priv, []string{license.FeatureAgents}), hex.EncodeToString(pub))

	out := &dashSyncBuffer{}
	errOut := &dashSyncBuffer{}
	cmd := dashboardServeCmd()
	cmd.SetArgs([]string{
		"--receipt-dir", t.TempDir(),
		"--auth-token-file", writeDashTokenFile(t),
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
	authorize := dashboardAuthorizeFunc(dashTestToken)
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

func TestDashboardRequestAuthorized(t *testing.T) {
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
			if got := dashboardRequestAuthorized(req, tc.token); got != tc.want {
				t.Errorf("dashboardRequestAuthorized = %v, want %v", got, tc.want)
			}
		})
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

func TestParseTrustedSigners(t *testing.T) {
	pub, _ := newDashKeyPair(t)
	keyHex := hex.EncodeToString(pub)
	keyFile := filepath.Join(t.TempDir(), "signer.pub")
	if err := os.WriteFile(keyFile, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Run("empty returns nil", func(t *testing.T) {
		got, err := parseTrustedSigners(nil)
		if err != nil || got != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", got, err)
		}
	})

	t.Run("inline hex with source", func(t *testing.T) {
		got, err := parseTrustedSigners([]string{"inline=" + keyHex + ",source=ops runbook"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got[keyHex] != (dashboard.TrustedKey{Source: "ops runbook"}) {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("empty parts from trailing comma are skipped", func(t *testing.T) {
		got, err := parseTrustedSigners([]string{"inline=" + keyHex + ","})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if _, ok := got[keyHex]; !ok {
			t.Fatalf("got %+v, want key present", got)
		}
	})

	t.Run("file key with default source", func(t *testing.T) {
		got, err := parseTrustedSigners([]string{"file=" + keyFile})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got[keyHex] != (dashboard.TrustedKey{Source: trustedSignerDefaultSource}) {
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
			_, err := parseTrustedSigners([]string{tc.in})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}

	t.Run("duplicate key rejected", func(t *testing.T) {
		_, err := parseTrustedSigners([]string{"inline=" + keyHex, "file=" + keyFile})
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
		got, err := loadDashboardTokenFile(writeDashTokenFile(t))
		if err != nil || got != dashTestToken {
			t.Fatalf("got (%q, %v), want (%q, nil)", got, err, dashTestToken)
		}
	})
	t.Run("empty path", func(t *testing.T) {
		if _, err := loadDashboardTokenFile("  "); err == nil ||
			!strings.Contains(err.Error(), "required") {
			t.Fatalf("want required error, got %v", err)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		if _, err := loadDashboardTokenFile(filepath.Join(t.TempDir(), "nope")); err == nil ||
			!strings.Contains(err.Error(), "read --auth-token-file") {
			t.Fatalf("want read error, got %v", err)
		}
	})
	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.token")
		if err := os.WriteFile(path, []byte(" \n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := loadDashboardTokenFile(path); err == nil ||
			!strings.Contains(err.Error(), "is empty") {
			t.Fatalf("want empty error, got %v", err)
		}
	})
}
