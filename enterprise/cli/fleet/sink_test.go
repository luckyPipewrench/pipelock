//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package fleet

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/fleet/sink"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestTrustedAuditKeyResolver_InlineAndFile(t *testing.T) {
	pub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "audit.pub")
	if err := os.WriteFile(keyPath, []byte(signing.EncodePublicKey(pub)), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver, bindings, err := trustedAuditKeyResolver([]string{
		"id=inline-key,inline=" + signing.EncodePublicKey(pub),
		"id=file-key,file=" + keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 0 {
		t.Fatalf("expected no bindings, got %d", len(bindings))
	}
	for _, id := range []string{"inline-key", "file-key"} {
		key, err := resolver(id)
		if err != nil {
			t.Fatalf("resolve %q: %v", id, err)
		}
		if key.KeyPurpose != signing.PurposeAuditBatchSigning {
			t.Fatalf("key %q purpose = %q", id, key.KeyPurpose)
		}
	}
	if _, err := resolver("missing"); !errors.Is(err, conductor.ErrInvalidSignature) {
		t.Fatalf("missing key err = %v, want ErrInvalidSignature", err)
	}
}

func TestTrustedAuditKeyResolver_TenantBinding(t *testing.T) {
	pub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, bindings, err := trustedAuditKeyResolver([]string{
		"id=acme-fleet-a,inline=" + signing.EncodePublicKey(pub) +
			",org=acme,fleet=prod,instance=pl-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, ok := bindings["acme-fleet-a"]
	if !ok {
		t.Fatal("binding for acme-fleet-a missing")
	}
	if binding.OrgID != "acme" || binding.FleetID != "prod" || binding.InstanceID != "pl-1" {
		t.Fatalf("binding = %+v", binding)
	}
}

func TestParseAuditKeySpec_RejectsBadInputs(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", "empty"},
		{"no_id", "inline=AAA", "id= required"},
		{"missing_key_source", "id=x", "inline= or file= required"},
		{"both_key_sources", "id=x,inline=AAA,file=/tmp/k", "inline= or file= required"},
		{"duplicate_field", "id=x,inline=AAA,inline=BBB", "duplicate key"},
		{"unknown_field", "id=x,inline=AAA,bogus=1", "unknown field"},
		{"missing_eq", "id=x,inline", "expected k=v"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAuditKeySpec(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseAuditKeySpec(%q) = %v, want substring %q", tc.raw, err, tc.want)
			}
		})
	}
}

func TestTrustedAuditKeyResolver_RejectsBadInputs(t *testing.T) {
	pub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		values []string
	}{
		{"missing", nil},
		{"bad_format", []string{"audit-signer"}},
		{"duplicate", []string{
			"id=audit-signer,inline=" + signing.EncodePublicKey(pub),
			"id=audit-signer,inline=" + signing.EncodePublicKey(pub),
		}},
		{"bad_inline", []string{"id=audit-signer,inline=not-a-key"}},
		{"missing_file", []string{"id=audit-signer,file=/nonexistent/key.pub"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := trustedAuditKeyResolver(tc.values); err == nil {
				t.Fatal("trustedAuditKeyResolver accepted invalid input")
			}
		})
	}
}

func TestLoadReaderToken(t *testing.T) {
	if got, err := loadReaderToken(""); err != nil || got != "" {
		t.Fatalf("empty path: got=%q err=%v", got, err)
	}
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("  s3cret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadReaderToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cret-token" {
		t.Fatalf("token = %q", got)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadReaderToken(empty); err == nil {
		t.Fatal("empty token file accepted")
	}
	if _, err := loadReaderToken("/nonexistent/token"); err == nil {
		t.Fatal("missing token file accepted")
	}
}

func TestValidateBindAddress(t *testing.T) {
	tmpCA := writeTestCA(t)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name        string
		addr        string
		tlsCert     string
		tlsKey      string
		clientCA    string
		readerToken string
		wantErr     string
	}{
		{"loopback_ipv4", "127.0.0.1:8894", "", "", "", "", ""},
		{"loopback_ipv6", "[::1]:8894", "", "", "", "", ""},
		{"loopback_name", "localhost:8894", "", "", "", "", ""},
		{"empty_host", ":8894", "", "", "", "", "--tls-cert and --tls-key are required"},
		{"public_no_tls", "10.0.0.1:8894", "", "", "", "", "--tls-cert and --tls-key are required"},
		{"public_cert_no_key", "10.0.0.1:8894", "/tmp/c", "", tmpCA, "", "--tls-cert and --tls-key are required"},
		{"public_tls_no_auth", "10.0.0.1:8894", "/tmp/c", "/tmp/k", "", "", "--client-ca (mTLS) or --reader-token-file is required"},
		{"public_tls_with_ca", "10.0.0.1:8894", "/tmp/c", "/tmp/k", tmpCA, "", ""},
		{"public_tls_with_token", "10.0.0.1:8894", "/tmp/c", "/tmp/k", "", "tok", ""},
		{"invalid_addr", "not-an-addr", "", "", "", "", "invalid --listen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBindAddress(tc.addr, tc.tlsCert, tc.tlsKey, tc.clientCA, tc.readerToken)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected err = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateBindAddress = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestListenerTLSConfigRequiresTLS13AndClientCA(t *testing.T) {
	cfg, err := listenerTLSConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
	}

	path := t.TempDir() + "/bad-ca.pem"
	if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenerTLSConfig(path); err == nil {
		t.Fatal("listenerTLSConfig accepted invalid client CA")
	}
	if _, err := listenerTLSConfig("/nonexistent/ca.pem"); err == nil {
		t.Fatal("listenerTLSConfig accepted missing CA path")
	}

	caPath := writeTestCA(t)
	cfg, err = listenerTLSConfig(caPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("ClientCAs is nil")
	}
}

func TestSinkCmdValidatesArgsBeforeServing(t *testing.T) {
	pub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	encoded := signing.EncodePublicKey(pub)
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"extra_arg", []string{"extra"}},
		{"missing_storage", nil},
		{"missing_key", []string{"--storage-dir", t.TempDir()}},
		{"bad_key_spec", []string{
			"--storage-dir", t.TempDir(),
			"--trusted-audit-key", "audit-signer", // missing id=, inline= etc
		}},
		{"client_ca_without_tls", []string{
			"--storage-dir", t.TempDir(),
			"--trusted-audit-key", "id=audit-signer,inline=" + encoded,
			"--client-ca", writeTestCA(t),
		}},
		{"non_loopback_no_tls", []string{
			"--storage-dir", t.TempDir(),
			"--trusted-audit-key", "id=audit-signer,inline=" + encoded,
			"--listen", "10.0.0.1:9999",
		}},
		{"non_loopback_tls_no_auth", []string{
			"--storage-dir", t.TempDir(),
			"--trusted-audit-key", "id=audit-signer,inline=" + encoded,
			"--listen", "10.0.0.1:9999",
			"--tls-cert", "/tmp/cert.pem",
			"--tls-key", "/tmp/key.pem",
		}},
		{"missing_token_file", []string{
			"--storage-dir", t.TempDir(),
			"--trusted-audit-key", "id=audit-signer,inline=" + encoded,
			"--reader-token-file", "/nonexistent/tok",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setTestFleetLicense(t)
			cmd := SinkCmd()
			cmd.SetArgs(tc.args)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetContext(context.Background())
			if err := cmd.Execute(); err == nil {
				t.Fatal("SinkCmd accepted invalid invocation")
			}
		})
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"", false},
		{"localhost", true},
		{"127.0.0.1", true},
		{"127.1.2.3", true}, // entire 127/8 is loopback
		{"::1", true},
		{"10.0.0.1", false},
		{"example.com", false}, // non-IP hostname is not loopback
		{"not-an-ip", false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			if got := isLoopbackHost(tc.host); got != tc.want {
				t.Fatalf("isLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestSignalContextCancel(t *testing.T) {
	ctx, cancel := signalContext(context.Background())
	cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("signal context did not cancel")
	}
}

// TestSinkCmd_RunOnLoopback covers the happy-path RunE up to ListenAndServe
// returning the harmless ErrServerClosed after we cancel the parent context.
// This wires together the resolver, store, scanner, and handler so all of
// SinkCmd's setup branches are exercised.
func TestSinkCmd_RunOnLoopback(t *testing.T) {
	setTestFleetLicense(t)
	pub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cmd := SinkCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	ctx, cancel := context.WithCancel(context.Background())
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{
		"--storage-dir", t.TempDir(),
		"--trusted-audit-key", "id=audit-signer,inline=" + signing.EncodePublicKey(pub),
		"--listen", "127.0.0.1:0",
	})
	// Cancel via the readiness seam, not a fixed sleep: this fires after setup
	// (including the store migration) completes and just before the listener
	// blocks, so the listener exits cleanly via Shutdown without racing setup.
	// A 50ms sleep here flaked under CI load by cancelling mid-migration.
	prev := sinkReadyHook
	sinkReadyHook = cancel
	t.Cleanup(func() { sinkReadyHook = prev })
	if err := cmd.Execute(); err != nil {
		t.Fatalf("SinkCmd.Execute() = %v", err)
	}
}

// TestSinkCmd_TLSCertWithoutKey makes sure operators get a clear error when
// they configure half the TLS pair. The check fires after the OS-level
// startup chatter (resolver + store) so we exercise the deferred branches.
func TestSinkCmd_TLSCertWithoutKey(t *testing.T) {
	setTestFleetLicense(t)
	pub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cmd := SinkCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{
		"--storage-dir", t.TempDir(),
		"--trusted-audit-key", "id=audit-signer,inline=" + signing.EncodePublicKey(pub),
		"--listen", "127.0.0.1:0",
		"--tls-cert", "/tmp/cert.pem", // key intentionally missing
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("SinkCmd accepted --tls-cert without --tls-key")
	}
}

// TestKeyBindingMatches covers the table of binding constraints used by
// the ingest handler.
func TestKeyBindingMatches(t *testing.T) {
	env := conductor.AuditBatchEnvelope{OrgID: "acme", FleetID: "prod", InstanceID: "pl-1"}
	for _, tc := range []struct {
		name    string
		binding sink.KeyBinding
		want    bool
	}{
		{"unrestricted", sink.KeyBinding{}, true},
		{"matching_org", sink.KeyBinding{OrgID: "acme"}, true},
		{"wrong_org", sink.KeyBinding{OrgID: "globex"}, false},
		{"matching_full", sink.KeyBinding{OrgID: "acme", FleetID: "prod", InstanceID: "pl-1"}, true},
		{"wrong_instance", sink.KeyBinding{OrgID: "acme", FleetID: "prod", InstanceID: "pl-2"}, false},
		{"matching_fleet_only", sink.KeyBinding{FleetID: "prod"}, true},
		{"wrong_fleet", sink.KeyBinding{FleetID: "staging"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.binding.Matches(env); got != tc.want {
				t.Fatalf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/ca.pem"
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
