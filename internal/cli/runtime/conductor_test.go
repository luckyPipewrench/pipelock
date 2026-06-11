//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestNewConductorMTLSClientConfiguresClientCertificate(t *testing.T) {
	dir := t.TempDir()
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	trustPath := filepath.Join(dir, "trust-roster.json")
	caPath := filepath.Join(dir, "boss-ca.pem")
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	writePrivateTestFile(t, trustPath, []byte(`{"keys":[]}`))
	writePrivateTestFile(t, caPath, clientPEM)
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	client, err := newConductorMTLSClient(config.Conductor{
		ConductorURL:    "https://conductor.example",
		TrustRosterPath: trustPath,
		ServerCAFile:    caPath,
		ClientCertPath:  clientCertPath,
		ClientKeyPath:   clientKeyPath,
	})
	if err != nil {
		t.Fatalf("newConductorMTLSClient() error = %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig = nil, want mTLS config")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %d, want TLS 1.3", transport.TLSClientConfig.MinVersion)
	}
	if len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("Certificates len = %d, want 1", len(transport.TLSClientConfig.Certificates))
	}
	if transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("RootCAs = nil; mTLS client must pin Boss server cert against roster, not system trust")
	}
	if transport.TLSClientConfig.ServerName != "conductor.example" {
		t.Fatalf("ServerName = %q, want pinned host conductor.example", transport.TLSClientConfig.ServerName)
	}
	if transport.TLSHandshakeTimeout == 0 {
		t.Fatal("TLSHandshakeTimeout = 0, want bounded handshake timeout")
	}
	if transport.ResponseHeaderTimeout == 0 {
		t.Fatal("ResponseHeaderTimeout = 0, want bounded response header timeout")
	}
	if transport.MaxResponseHeaderBytes == 0 {
		t.Fatal("MaxResponseHeaderBytes = 0, want explicit cap")
	}
}

func TestNewConductorMTLSClientRejectsMissingClientCertificate(t *testing.T) {
	dir := t.TempDir()
	certPEM, _ := testTLSClientCert(t)
	caPath := filepath.Join(dir, "boss-ca.pem")
	writePrivateTestFile(t, caPath, certPEM)

	_, err := newConductorMTLSClient(config.Conductor{
		ConductorURL:    "https://conductor.example",
		TrustRosterPath: filepath.Join(t.TempDir(), "trust.json"),
		ServerCAFile:    caPath,
		ClientCertPath:  filepath.Join(t.TempDir(), "missing.crt"),
		ClientKeyPath:   filepath.Join(t.TempDir(), "missing.key"),
	})
	if err == nil || !strings.Contains(err.Error(), "mTLS client certificate") {
		t.Fatalf("newConductorMTLSClient() = %v, want certificate load error", err)
	}
}

func TestNewConductorMTLSClientRejectsMissingServerCABundle(t *testing.T) {
	dir := t.TempDir()
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	_, err := newConductorMTLSClient(config.Conductor{
		ConductorURL:    "https://conductor.example",
		TrustRosterPath: filepath.Join(t.TempDir(), "trust.json"),
		ServerCAFile:    filepath.Join(t.TempDir(), "missing.pem"),
		ClientCertPath:  clientCertPath,
		ClientKeyPath:   clientKeyPath,
	})
	if err == nil || !strings.Contains(err.Error(), "server CA bundle") {
		t.Fatalf("newConductorMTLSClient() = %v, want server CA bundle load error", err)
	}
}

func TestNewConductorMTLSClientRejectsNonPEMServerCABundle(t *testing.T) {
	dir := t.TempDir()
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	caPath := filepath.Join(dir, "boss-ca.pem")
	writePrivateTestFile(t, caPath, []byte("not a PEM bundle"))
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	_, err := newConductorMTLSClient(config.Conductor{
		ConductorURL:    "https://conductor.example",
		TrustRosterPath: filepath.Join(t.TempDir(), "trust.json"),
		ServerCAFile:    caPath,
		ClientCertPath:  clientCertPath,
		ClientKeyPath:   clientKeyPath,
	})
	if err == nil || !strings.Contains(err.Error(), "PEM-encoded certificates") {
		t.Fatalf("newConductorMTLSClient() = %v, want PEM parse error", err)
	}
}

// TestNewConductorMTLSClient_VerifiesAgainstPinnedRosterOnly is the "proves
// the pin" test. Two test CAs sign two server certs. The follower's mTLS
// client gets only one CA in its roster. A request to the matching server
// succeeds; a request to the off-roster server is rejected at TLS verification
// even though both certs are valid X.509 leaves with healthy chains.
func TestNewConductorMTLSClient_VerifiesAgainstPinnedRosterOnly(t *testing.T) {
	dir := t.TempDir()
	pinnedCAPEM, pinnedServer := newTestTLSServer(t)
	_, offRosterServer := newTestTLSServer(t)
	defer pinnedServer.Close()
	defer offRosterServer.Close()

	caPath := filepath.Join(dir, "boss-ca.pem")
	writePrivateTestFile(t, caPath, pinnedCAPEM)
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	client, err := newConductorMTLSClient(config.Conductor{
		ConductorURL:    pinnedServer.URL,
		TrustRosterPath: filepath.Join(t.TempDir(), "trust.json"),
		ServerCAFile:    caPath,
		ClientCertPath:  clientCertPath,
		ClientKeyPath:   clientKeyPath,
	})
	if err != nil {
		t.Fatalf("newConductorMTLSClient() error = %v", err)
	}

	// Override ServerName because httptest servers bind 127.0.0.1 and the
	// pinned-cert SAN below is also 127.0.0.1. The production code derives
	// ServerName from the configured URL, so this test mirrors that path.
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.ServerName = mustHostname(t, pinnedServer.URL)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pinnedServer.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest(pinned) error = %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do(pinned) error = %v; pinned-CA chain must validate", err)
	}
	_ = resp.Body.Close()

	transport.TLSClientConfig.ServerName = mustHostname(t, offRosterServer.URL)
	transport.CloseIdleConnections()
	offReq, err := http.NewRequestWithContext(ctx, http.MethodGet, offRosterServer.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest(off-roster) error = %v", err)
	}
	offResp, err := client.Do(offReq)
	if err == nil {
		_ = offResp.Body.Close()
		t.Fatal("Do(off-roster) error = nil; off-roster CA must NOT be accepted")
	}
	if !strings.Contains(err.Error(), "unknown authority") &&
		!strings.Contains(err.Error(), "x509") &&
		!strings.Contains(err.Error(), "certificate") {
		t.Fatalf("Do(off-roster) error = %v; want TLS verification error", err)
	}
}

func TestConductorServerNameStripsPort(t *testing.T) {
	got, err := conductorServerName("https://boss.example:8443")
	if err != nil {
		t.Fatalf("conductorServerName() error = %v", err)
	}
	if got != "boss.example" {
		t.Fatalf("conductorServerName() = %q, want boss.example", got)
	}
}

func TestBuildConductorTrustResolverLoadsPinnedRoster(t *testing.T) {
	dir := t.TempDir()
	remotePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rosterPath := filepath.Join(dir, "trust-roster.json")
	rootFingerprint := writeRuntimeTrustRoster(t, rosterPath, remotePub, "remote-kill-1", signing.PurposeRemoteKillSigning)

	resolver, err := buildConductorTrustResolver(config.Conductor{
		TrustRosterPath:            rosterPath,
		TrustRosterRootFingerprint: rootFingerprint,
	}, func() time.Time { return time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatalf("buildConductorTrustResolver() error = %v", err)
	}
	key, err := resolver("remote-kill-1")
	if err != nil {
		t.Fatalf("resolver(remote-kill-1) error = %v", err)
	}
	if key.KeyPurpose != signing.PurposeRemoteKillSigning {
		t.Fatalf("KeyPurpose = %q, want %q", key.KeyPurpose, signing.PurposeRemoteKillSigning)
	}
	if !key.NotBefore.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) || !key.NotAfter.IsZero() {
		t.Fatalf("key windows = not_before=%s not_after=%s", key.NotBefore, key.NotAfter)
	}
	if string(key.PublicKey) != string(remotePub) {
		t.Fatal("resolver returned wrong public key")
	}
	if _, err := resolver("missing"); !errors.Is(err, conductor.ErrSignatureVerification) {
		t.Fatalf("resolver(missing) error = %v, want ErrSignatureVerification", err)
	}
}

func TestBuildConductorRemoteKillPollerHonorsDisableWithoutRoster(t *testing.T) {
	dir := t.TempDir()
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	caPath := filepath.Join(dir, "boss-ca.pem")
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	writePrivateTestFile(t, caPath, clientPEM)
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	poller, err := buildConductorRemoteKillPoller(&config.Config{
		Conductor: config.Conductor{
			Enabled:               true,
			ConductorURL:          "https://conductor.example",
			OrgID:                 "org-main",
			FleetID:               "prod",
			InstanceID:            "pl-prod-1",
			TrustRosterPath:       filepath.Join(dir, "missing-roster.json"),
			ServerCAFile:          caPath,
			ClientCertPath:        clientCertPath,
			ClientKeyPath:         clientKeyPath,
			BundleCacheDir:        filepath.Join(dir, "bundles"),
			PollInterval:          "30s",
			HonorRemoteKillSwitch: false,
		},
	}, &testRuntimeKillSwitch{}, nil)
	if err != nil {
		t.Fatalf("buildConductorRemoteKillPoller() error = %v", err)
	}
	if poller == nil {
		t.Fatal("poller = nil, want disabled-mode poller for visible rejected messages")
	}
}

// TestBuildConductorBundlePollerRejectsBadRosterEvenWithHonorFalse proves the
// policy-bundle poller fails closed when the trust roster cannot be loaded,
// REGARDLESS of honor_remote_kill_switch. Unlike the remote-kill poller (which
// installs a reject-all resolver and keeps running when honor=false so it can
// log visible rejections), the bundle poller must have a real verified trust
// root before it can apply any signed bundle - so a missing/unreadable roster
// is a hard startup error.
func TestBuildConductorBundlePollerRejectsBadRosterEvenWithHonorFalse(t *testing.T) {
	dir := t.TempDir()
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	caPath := filepath.Join(dir, "boss-ca.pem")
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	writePrivateTestFile(t, caPath, clientPEM)
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	s := &Server{}
	_, err := s.buildConductorBundlePoller(&config.Config{
		Conductor: config.Conductor{
			Enabled:                    true,
			ConductorURL:               "https://conductor.example",
			OrgID:                      "org-main",
			FleetID:                    "prod",
			InstanceID:                 "pl-prod-1",
			TrustRosterPath:            filepath.Join(dir, "missing-roster.json"),
			TrustRosterRootFingerprint: strings.Repeat("a", 64),
			ServerCAFile:               caPath,
			ClientCertPath:             clientCertPath,
			ClientKeyPath:              clientKeyPath,
			BundleCacheDir:             filepath.Join(dir, "bundles"),
			DurableAuditQueueDir:       filepath.Join(dir, "audit-queue"),
			PollInterval:               "30s",
			HonorRemoteKillSwitch:      false, // the crux: honor=false must NOT skip roster verification
		},
	}, io.Discard)
	if err == nil {
		t.Fatal("buildConductorBundlePoller() with honor=false + missing roster: want error, got nil")
	}
	if !strings.Contains(err.Error(), "trust resolver") && !strings.Contains(err.Error(), "trust roster") {
		t.Fatalf("error = %v, want trust roster/resolver failure", err)
	}
}

func TestBuildConductorAuditTransportReleasesQueueOnConstructorFailure(t *testing.T) {
	dir := t.TempDir()
	queueDir := filepath.Join(dir, "audit-queue")
	caPath := filepath.Join(dir, "boss-ca.pem")
	writePrivateTestFile(t, caPath, []byte("not a PEM bundle"))

	cfg := &config.Config{
		Conductor: config.Conductor{
			Enabled:              true,
			ConductorURL:         "https://conductor.example",
			ServerCAFile:         caPath,
			ClientCertPath:       filepath.Join(dir, "missing-client.crt"),
			ClientKeyPath:        filepath.Join(dir, "missing-client.key"),
			DurableAuditQueueDir: queueDir,
		},
	}
	if _, _, err := buildConductorAuditTransport(cfg, nil); err == nil {
		t.Fatal("buildConductorAuditTransport() error = nil, want mTLS constructor failure")
	}
	reopened, err := auditbatcher.Open(auditbatcher.Config{Dir: queueDir})
	if err != nil {
		t.Fatalf("Open(queue after failed build) error = %v, want lock released", err)
	}
	defer func() { _ = reopened.Close() }()
}

// TestBuildConductorBundlePollerDisabled confirms the poller is a no-op (nil,
// nil) when conductor is not enabled.
func TestBuildConductorBundlePollerDisabled(t *testing.T) {
	s := &Server{}
	poller, err := s.buildConductorBundlePoller(&config.Config{Conductor: config.Conductor{Enabled: false}}, io.Discard)
	if err != nil {
		t.Fatalf("disabled buildConductorBundlePoller() error = %v", err)
	}
	if poller != nil {
		t.Fatal("disabled buildConductorBundlePoller() poller = non-nil, want nil")
	}
}

// TestBuildConductorBundlePollerErrorPaths covers the remaining fail-closed
// branches: an unreadable mTLS client certificate, and (with valid mTLS + a real
// signed roster) an unparseable poll interval. The trust-resolver branch is
// covered by TestBuildConductorBundlePollerRejectsBadRosterEvenWithHonorFalse.
func TestBuildConductorBundlePollerErrorPaths(t *testing.T) {
	dir := t.TempDir()
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	caPath := filepath.Join(dir, "boss-ca.pem")
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	rosterPath := filepath.Join(dir, "trust-roster.json")
	bundlePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rootFingerprint := writeRuntimeTrustRoster(t, rosterPath, bundlePub, "policy-signer-1", signing.PurposePolicyBundleSigning)
	writePrivateTestFile(t, caPath, clientPEM)
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	base := config.Conductor{
		Enabled:                    true,
		ConductorURL:               "https://conductor.example",
		OrgID:                      "org-main",
		FleetID:                    "prod",
		InstanceID:                 "pl-prod-1",
		TrustRosterPath:            rosterPath,
		TrustRosterRootFingerprint: rootFingerprint,
		ServerCAFile:               caPath,
		ClientCertPath:             clientCertPath,
		ClientKeyPath:              clientKeyPath,
		BundleCacheDir:             filepath.Join(dir, "bundles"),
		DurableAuditQueueDir:       filepath.Join(dir, "audit-queue"),
		PollInterval:               "30s",
		HonorRemoteKillSwitch:      false,
	}

	t.Run("mtls_client_error", func(t *testing.T) {
		cfg := base
		cfg.ClientCertPath = filepath.Join(dir, "missing-client.crt")
		s := &Server{}
		if _, err := s.buildConductorBundlePoller(&config.Config{Conductor: cfg}, io.Discard); err == nil ||
			!strings.Contains(err.Error(), "mTLS client") {
			t.Fatalf("error = %v, want mTLS client failure", err)
		}
	})

	t.Run("poll_interval_error", func(t *testing.T) {
		cfg := base
		cfg.PollInterval = "not-a-duration"
		s := &Server{}
		if _, err := s.buildConductorBundlePoller(&config.Config{Conductor: cfg}, io.Discard); err == nil ||
			!strings.Contains(err.Error(), "parsing conductor policy bundle poll interval") {
			t.Fatalf("error = %v, want poll interval parse failure", err)
		}
	})

	t.Run("valid_builds_poller", func(t *testing.T) {
		s := &Server{}
		poller, err := s.buildConductorBundlePoller(&config.Config{Conductor: base}, nil)
		if err != nil {
			t.Fatalf("valid config: %v", err)
		}
		if poller == nil {
			t.Fatal("poller = nil, want a poller for enabled conductor")
		}
	})
}

func TestBuildConductorRemoteKillPollerRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	caPath := filepath.Join(dir, "boss-ca.pem")
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	writePrivateTestFile(t, caPath, clientPEM)
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)
	base := config.Conductor{
		Enabled:                    true,
		ConductorURL:               "https://conductor.example",
		OrgID:                      "org-main",
		FleetID:                    "prod",
		InstanceID:                 "pl-prod-1",
		TrustRosterPath:            filepath.Join(dir, "missing-roster.json"),
		TrustRosterRootFingerprint: strings.Repeat("a", 64),
		ServerCAFile:               caPath,
		ClientCertPath:             clientCertPath,
		ClientKeyPath:              clientKeyPath,
		BundleCacheDir:             filepath.Join(dir, "bundles"),
		PollInterval:               "30s",
		HonorRemoteKillSwitch:      false,
	}
	tests := []struct {
		name string
		edit func(*config.Conductor)
		want string
	}{
		{
			name: "mtls_client_error",
			edit: func(c *config.Conductor) { c.ClientCertPath = filepath.Join(dir, "missing-client.crt") },
			want: "loading conductor mTLS client certificate",
		},
		{
			name: "trust_resolver_error",
			edit: func(c *config.Conductor) { c.HonorRemoteKillSwitch = true },
			want: "loading conductor trust roster",
		},
		{
			name: "poll_interval_error",
			edit: func(c *config.Conductor) { c.PollInterval = "not-a-duration" },
			want: "parsing conductor remote kill poll interval",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.edit(&cfg)
			_, err := buildConductorRemoteKillPoller(&config.Config{Conductor: cfg}, &testRuntimeKillSwitch{}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("buildConductorRemoteKillPoller() error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestBuildConductorRemoteKillPollerRestoresPersistedState(t *testing.T) {
	dir := t.TempDir()
	remotePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	trustPath := filepath.Join(dir, "trust-roster.json")
	rootFingerprint := writeRuntimeTrustRoster(t, trustPath, remotePub, "remote-kill-1", signing.PurposeRemoteKillSigning)
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	caPath := filepath.Join(dir, "boss-ca.pem")
	clientCertPath := filepath.Join(dir, "client.crt")
	clientKeyPath := filepath.Join(dir, "client.key")
	bundleCacheDir := filepath.Join(dir, "bundles")
	writePrivateTestFile(t, caPath, clientPEM)
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)
	statePath := filepath.Join(bundleCacheDir, "remote-kill-state.json")
	if err := os.MkdirAll(bundleCacheDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(bundle cache): %v", err)
	}
	writePrivateTestFile(t, statePath, []byte(`{
  "last_counter": 7,
  "last_message_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "state": "active",
  "reason": "persisted emergency stop",
  "applied_at": "2026-05-23T12:00:00Z"
}`))
	ks := &testRuntimeKillSwitch{}
	poller, err := buildConductorRemoteKillPoller(&config.Config{
		Conductor: config.Conductor{
			Enabled:                    true,
			ConductorURL:               "https://conductor.example",
			OrgID:                      "org-main",
			FleetID:                    "prod",
			InstanceID:                 "pl-prod-1",
			TrustRosterPath:            trustPath,
			TrustRosterRootFingerprint: rootFingerprint,
			ServerCAFile:               caPath,
			ClientCertPath:             clientCertPath,
			ClientKeyPath:              clientKeyPath,
			BundleCacheDir:             bundleCacheDir,
			PollInterval:               "30s",
			HonorRemoteKillSwitch:      true,
		},
	}, ks, io.Discard)
	if err != nil {
		t.Fatalf("buildConductorRemoteKillPoller() error = %v", err)
	}
	if poller == nil {
		t.Fatal("poller = nil")
	}
	if !ks.active || ks.message != "persisted emergency stop" {
		t.Fatalf("kill switch = active=%v message=%q, want restored active", ks.active, ks.message)
	}
}

func TestConductorRuntimeChanged(t *testing.T) {
	oldCfg := config.Defaults()
	newCfg := oldCfg.Clone()
	if conductorRuntimeChanged(oldCfg, newCfg) {
		t.Fatal("conductorRuntimeChanged(equal) = true, want false")
	}
	newCfg.Conductor.Enabled = true
	if !conductorRuntimeChanged(oldCfg, newCfg) {
		t.Fatal("conductorRuntimeChanged(changed) = false, want true")
	}

	// A reload that tries to weaken stale-fail-closed (flip after_grace from the
	// strict_deny_all default to continue_last_known_good) must be detected as a
	// conductor-runtime change, so the reload path preserves the original
	// conductor block instead of applying it. Conductor settings are restart-only;
	// an operator cannot hot-reload their way out of stale fail-closed.
	staleFlip := oldCfg.Clone()
	staleFlip.Conductor.StalePolicy.AfterGrace = config.ConductorStaleContinueLastKnownGood
	if !conductorRuntimeChanged(oldCfg, staleFlip) {
		t.Fatal("conductorRuntimeChanged(after_grace flip) = false, want true (stale policy is restart-only)")
	}
	graceFlip := oldCfg.Clone()
	graceFlip.Conductor.StalePolicy.GraceMultiplier = oldCfg.Conductor.StalePolicy.GraceMultiplier + 5
	if !conductorRuntimeChanged(oldCfg, graceFlip) {
		t.Fatal("conductorRuntimeChanged(grace_multiplier flip) = false, want true (stale policy is restart-only)")
	}
}

func TestBuildConductorApplyCacheRejectsInvalidDir(t *testing.T) {
	if cache, err := buildConductorApplyCache(nil); err != nil || cache != nil {
		t.Fatalf("buildConductorApplyCache(nil) = cache=%v err=%v, want nil nil", cache, err)
	}
	cfg := config.Defaults()
	if cache, err := buildConductorApplyCache(cfg); err != nil || cache != nil {
		t.Fatalf("buildConductorApplyCache(disabled) = cache=%v err=%v, want nil nil", cache, err)
	}
	dir := t.TempDir()
	filePath := filepath.Join(dir, "cache-file")
	if err := os.WriteFile(filePath, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("write cache file path: %v", err)
	}
	cfg.Conductor.Enabled = true
	cfg.Conductor.BundleCacheDir = filePath
	if _, err := buildConductorApplyCache(cfg); err == nil || !strings.Contains(err.Error(), "opening conductor apply cache") {
		t.Fatalf("buildConductorApplyCache(file dir) = %v, want wrapped cache error", err)
	}
}

// TestNewServer_WiresConductorBundlePoller proves the policy-bundle poller is
// constructed and stored on the Server when conductor.enabled with a valid
// signed roster, so server_lifecycle launches its poll loop alongside the audit
// transport and remote-kill poller.
func TestNewServer_WiresConductorBundlePoller(t *testing.T) {
	s, _ := newConductorApplyTestServer(t)
	if s.conductorBundle == nil {
		t.Fatal("conductor policy-bundle poller should be wired when conductor.enabled")
	}
}

func TestApplyConductorPolicyBundleReloadsAndActivates(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	// Enforcement-only bundle: policy bundles may carry only enforcement-policy
	// sections (default-deny allowlist), so flight_recorder/conductor/etc. are
	// NOT included here. The follower's existing flight_recorder + conductor
	// config must survive the reload for the apply to succeed.
	bundle := signedRuntimePolicyBundle(t, signer, "bundle-1", 1, "", strings.Join([]string{
		"mode: strict",
		"api_allowlist:",
		"  - api.example.com",
		"",
	}, "\n"))

	applied, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()})
	if err != nil {
		t.Fatalf("ApplyConductorPolicyBundle() error = %v", err)
	}
	if applied.Bundle.BundleID != "bundle-1" || applied.ReloadedConfigHash == "" {
		t.Fatalf("applied bundle = %q hash=%q, want bundle-1 with config hash", applied.Bundle.BundleID, applied.ReloadedConfigHash)
	}
	cache, _ := s.conductorApply.(*applycache.Cache)
	if cache == nil {
		t.Fatalf("conductorApply: want *applycache.Cache, got %T", s.conductorApply)
	}
	active, err := cache.Active()
	if err != nil {
		t.Fatalf("Active() error = %v", err)
	}
	if active.Bundle.BundleID != "bundle-1" || active.ConfigPath != applied.ConfigPath {
		t.Fatalf("active bundle = %q path=%q, want bundle-1 path=%q", active.Bundle.BundleID, active.ConfigPath, applied.ConfigPath)
	}
	if live := s.proxy.CurrentConfig(); live == nil || live.Mode != config.ModeStrict {
		t.Fatalf("live mode = %v, want strict", live)
	}
}

func TestApplyConductorPolicyBundleFailsClosed(t *testing.T) {
	if _, err := (*Server)(nil).ApplyConductorPolicyBundle(conductor.PolicyBundle{}, ConductorApplyOptions{}); err == nil {
		t.Fatal("nil server ApplyConductorPolicyBundle() = nil, want error")
	}
	if _, err := (&Server{}).ApplyConductorPolicyBundle(conductor.PolicyBundle{}, ConductorApplyOptions{}); !errors.Is(err, applycache.ErrCacheRequired) {
		t.Fatalf("missing cache ApplyConductorPolicyBundle() = %v, want ErrCacheRequired", err)
	}
	cache, err := applycache.Open(applycache.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("applycache.Open(): %v", err)
	}
	if _, err := (&Server{conductorApply: cache}).ApplyConductorPolicyBundle(conductor.PolicyBundle{}, ConductorApplyOptions{}); err == nil || !strings.Contains(err.Error(), "runtime config unavailable") {
		t.Fatalf("missing config ApplyConductorPolicyBundle() = %v, want runtime config error", err)
	}
}

type runtimePolicySigner struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newRuntimePolicySigner(t *testing.T) runtimePolicySigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	return runtimePolicySigner{id: "policy-signer-1", pub: pub, priv: priv}
}

func (s runtimePolicySigner) resolver() conductor.SignatureKeyResolver {
	return func(signerKeyID string) (conductor.SignatureKey, error) {
		if signerKeyID != s.id {
			return conductor.SignatureKey{}, conductor.ErrSignatureVerification
		}
		return conductor.SignatureKey{
			PublicKey:  s.pub,
			KeyPurpose: signing.PurposePolicyBundleSigning,
			NotBefore:  time.Now().Add(-time.Hour),
			NotAfter:   time.Now().Add(time.Hour),
		}, nil
	}
}

func newConductorApplyTestServer(t *testing.T) (*Server, runtimePolicySigner) {
	t.Helper()
	// conductor.enabled triggers the fleet-license gate; install a real
	// Enterprise token for the test so the production gate path is exercised.
	setTestFleetLicense(t)
	tmp, err := os.MkdirTemp(".", ".runtime-conductor-apply-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	tmp, err = filepath.Abs(tmp)
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	keyPath := filepath.Join(tmp, "recorder.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	clientPEM, clientKeyPEM := testTLSClientCert(t)
	trustPath := filepath.Join(tmp, "trust-roster.json")
	caPath := filepath.Join(tmp, "boss-ca.pem")
	clientCertPath := filepath.Join(tmp, "client.crt")
	clientKeyPath := filepath.Join(tmp, "client.key")
	// A real signed roster is mandatory whenever conductor.enabled, independent
	// of honor_remote_kill_switch: the policy-bundle poller must verify signed
	// bundles against a pinned trust root before applying them.
	bundleSigner := newRuntimePolicySigner(t)
	rootFingerprint := writeRuntimeTrustRoster(t, trustPath, bundleSigner.pub, bundleSigner.id, signing.PurposePolicyBundleSigning)
	writePrivateTestFile(t, caPath, clientPEM)
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	recorderDir := filepath.Join(tmp, "recorder")
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  dir: " + strconv.Quote(recorderDir),
		"  checkpoint_interval: 1",
		"  sign_checkpoints: true",
		"  signing_key_path: " + strconv.Quote(keyPath),
		"conductor:",
		"  enabled: true",
		"  conductor_url: https://conductor.example",
		"  org_id: org-main",
		"  fleet_id: prod",
		"  instance_id: pl-prod-1",
		"  trust_roster_path: " + strconv.Quote(trustPath),
		"  trust_roster_root_fingerprint: " + strconv.Quote(rootFingerprint),
		"  server_ca_file: " + strconv.Quote(caPath),
		"  client_cert_path: " + strconv.Quote(clientCertPath),
		"  client_key_path: " + strconv.Quote(clientKeyPath),
		"  bundle_cache_dir: " + strconv.Quote(filepath.Join(tmp, "bundles")),
		"  durable_audit_queue_dir: " + strconv.Quote(filepath.Join(tmp, "audit-queue")),
		"  audit_signing_key_id: audit-key-1",
		"  recorder_key_id: recorder-key-1",
		"  honor_remote_kill_switch: false",
		"",
	}, "\n"))

	buf := &syncBuffer{}
	server, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: buf, Stderr: buf})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { server.cleanup() })
	if server.conductorApply == nil {
		t.Fatal("conductor apply cache should be initialized")
	}
	return server, bundleSigner
}

func signedRuntimePolicyBundle(t *testing.T, signer runtimePolicySigner, id string, version uint64, previousHash, configYAML string) conductor.PolicyBundle {
	t.Helper()
	now := time.Now().UTC()
	payload := conductor.PolicyBundlePayload{ConfigYAML: configYAML}
	payloadHash, err := payload.PayloadHash()
	if err != nil {
		t.Fatalf("PayloadHash() error = %v", err)
	}
	policyHash, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash() error = %v", err)
	}
	bundle := conductor.PolicyBundle{
		SchemaVersion:      conductor.SchemaVersion,
		BundleID:           id,
		OrgID:              "org-main",
		FleetID:            "prod",
		Environment:        "prod",
		Audience:           conductor.Audience{InstanceIDs: []string{"pl-prod-1"}},
		Version:            version,
		PreviousBundleHash: previousHash,
		CreatedAt:          now.Add(-time.Minute),
		NotBefore:          now.Add(-time.Minute),
		ExpiresAt:          now.Add(time.Hour),
		MinPipelockVersion: "0.0.1",
		PolicyHash:         policyHash,
		PayloadSHA256:      payloadHash,
		Payload:            payload,
	}
	preimage, err := bundle.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage() error = %v", err)
	}
	bundle.Signatures = []conductor.SignatureProof{{
		SignerKeyID: signer.id,
		KeyPurpose:  signing.PurposePolicyBundleSigning,
		Algorithm:   conductor.SignatureAlgorithmEd25519,
		Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(signer.priv, preimage)),
	}}
	return bundle
}

func mustHostname(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%s) error = %v", raw, err)
	}
	host := u.Hostname()
	if host == "" {
		t.Fatalf("url %s has no host", raw)
	}
	return host
}

type testRuntimeKillSwitch struct {
	active  bool
	message string
}

func (t *testRuntimeKillSwitch) SetConductorRemote(active bool, message string) {
	t.active = active
	t.message = message
}

func writeRuntimeTrustRoster(t *testing.T, path string, pub ed25519.PublicKey, keyID string, purpose signing.KeyPurpose) string {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	rootFingerprint, err := signing.Fingerprint(rootPub)
	if err != nil {
		t.Fatalf("Fingerprint(root): %v", err)
	}
	body := contract.KeyRoster{
		SchemaVersion:  1,
		RosterSignedBy: "roster-root-1",
		DataClassRoot:  string(contract.DataClassInternal),
		Keys: []contract.KeyInfo{
			{
				KeyID:        "roster-root-1",
				KeyPurpose:   signing.PurposeRosterRoot.String(),
				PublicKeyHex: hex.EncodeToString(rootPub),
				ValidFrom:    "2026-01-01T00:00:00Z",
				Status:       contract.KeyStatusRoot,
			},
			{
				KeyID:        keyID,
				KeyPurpose:   purpose.String(),
				PublicKeyHex: hex.EncodeToString(pub),
				ValidFrom:    "2026-01-01T00:00:00Z",
				Status:       contract.KeyStatusActive,
			},
		},
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(roster): %v", err)
	}
	envelope := contract.RosterEnvelope{
		Body:      body,
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(rootPriv, preimage)),
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Marshal(roster): %v", err)
	}
	writePrivateTestFile(t, path, data)
	return rootFingerprint
}

// newTestTLSServer builds a single-leaf CA + server cert, starts an httptest
// server, and returns the CA PEM bundle plus the server. The CA is unique per
// call so two servers can't reuse the same chain.
func newTestTLSServer(t *testing.T) ([]byte, *httptest.Server) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(ca) error = %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          mustSerial(t),
		Subject:               pkix.Name{CommonName: "pipelock-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(ca) error = %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate(ca) error = %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(leaf) error = %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: mustSerial(t),
		Subject:      pkix.Name{CommonName: "pipelock-test-boss"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(leaf) error = %v", err)
	}
	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafKeyBytes, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyBytes})
	leafCert, err := tls.X509KeyPair(leafCertPEM, leafKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair(leaf) error = %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{leafCert},
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	return caPEM, srv
}
