//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestServeCmd_NoFleetLicenseFailsClosed(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := Cmd()
	cmd.SetArgs([]string{"serve"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("conductor serve without fleet license: want error, got nil")
	}
	if !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("want ErrFleetLicenseRequired, got %v", err)
	}
}

func TestBuildServeHandlerWiresControlPlane(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "publisher-token")
	if err := os.WriteFile(tokenPath, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(token): %v", err)
	}
	auditorTokenPath := filepath.Join(dir, "auditor-token")
	if err := os.WriteFile(auditorTokenPath, []byte("auditor-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(auditor token): %v", err)
	}
	adminTokenPath := filepath.Join(dir, "admin-token")
	if err := os.WriteFile(adminTokenPath, []byte("admin-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(admin token): %v", err)
	}
	caPath := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(caPath, testCAPEM(t), 0o600); err != nil {
		t.Fatalf("WriteFile(ca): %v", err)
	}

	handler, probeHandler, tlsConfig, err := buildServeHandler(context.Background(), serveOptions{
		listen:              defaultListen,
		storageDir:          filepath.Join(dir, "store"),
		conductorID:         "conductor-test",
		followerTrustDomain: defaultTrustDomain,
		publisherTokenFile:  tokenPath,
		auditorTokenFile:    auditorTokenPath,
		adminTokenFile:      adminTokenPath,
		auditorOrgID:        "org-main",
		adminOrgID:          "org-main",
		trustedAuditKeys: []string{
			"id=audit-key-1,inline=" + signing.EncodePublicKey(pub) + ",org=org-main",
		},
		trustedControlKeys: []string{
			"id=remote-key-1,purpose=remote-kill-signing,inline=" + signing.EncodePublicKey(pub),
			"id=rollback-key-1,purpose=policy-bundle-rollback,inline=" + signing.EncodePublicKey(pub),
		},
		tlsCert:  filepath.Join(dir, "server.pem"),
		tlsKey:   filepath.Join(dir, "server.key"),
		clientCA: caPath,
	})
	if err != nil {
		t.Fatalf("buildServeHandler() error = %v", err)
	}
	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLS config = %+v", tlsConfig)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, conductorcore.CapabilitiesPath, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d body=%s, want 200", w.Code, w.Body.String())
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, controlplane.ReadyzPath, nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("main ready status = %d body=%s, want 404", w.Code, w.Body.String())
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, controlplane.ReadyzPath, nil)
	w = httptest.NewRecorder()
	probeHandler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"audit_query_supported":true`) {
		t.Fatalf("ready status = %d body=%s, want audit query support", w.Code, w.Body.String())
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, controlplane.MetricsPath, nil)
	w = httptest.NewRecorder()
	probeHandler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "pipelock_conductor_server_requests_total") {
		t.Fatalf("metrics status = %d body=%s, want conductor metrics", w.Code, w.Body.String())
	}
}

func TestBuildServeHandlerFleetSkewOverrideUsesAdminCredential(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	storageDir := filepath.Join(dir, "store")
	enrollments, err := controlplane.OpenFileEnrollmentStore(filepath.Join(storageDir, "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore: %v", err)
	}
	identity := controlplane.FollowerIdentity{OrgID: testOrg, FleetID: testFleet, InstanceID: "pl-prod-1", Environment: testEnv}
	issued, err := enrollments.CreateEnrollmentToken(context.Background(), controlplane.EnrollmentTokenSpec{
		TokenID:  "tok-main-1",
		Identity: identity,
		Expires:  time.Now().UTC().Add(time.Hour),
		Now:      time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	if _, err := enrollments.ConsumeEnrollmentToken(context.Background(), controlplane.ConsumeEnrollmentTokenRequest{
		Token:      issued.Token,
		AuditKeyID: "audit-key-main-1",
		AuditKey: conductorcore.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		Now: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("ConsumeEnrollmentToken: %v", err)
	}
	now := time.Now().UTC()
	if _, err := enrollments.UpsertFollowerRuntimeStatus(context.Background(), controlplane.FollowerRuntimeStatus{
		OrgID:               identity.OrgID,
		FleetID:             identity.FleetID,
		InstanceID:          identity.InstanceID,
		Environment:         identity.Environment,
		SchemaVersion:       conductorcore.SchemaVersion,
		PipelockVersion:     "1.0.0",
		GitCommit:           "abc123",
		ActiveBundleID:      "bundle-old",
		ActiveBundleVersion: 1,
		ActiveBundleHash:    strings.Repeat("a", 64),
		LastSeenAt:          now,
		LastPolicyPollAt:    now,
	}); err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus: %v", err)
	}

	publisherTokenPath := writeFile(t, dir, "publisher-token", "publisher-token\n")
	auditorTokenPath := writeFile(t, dir, "auditor-token", "auditor-token\n")
	adminTokenPath := writeFile(t, dir, "admin-token", "admin-token\n")
	caPath := writeFile(t, dir, "client-ca.pem", string(testCAPEM(t)))
	handler, _, _, err := buildServeHandler(context.Background(), serveOptions{
		listen:              defaultListen,
		storageDir:          storageDir,
		conductorID:         "conductor-test",
		followerTrustDomain: defaultTrustDomain,
		publisherTokenFile:  publisherTokenPath,
		auditorTokenFile:    auditorTokenPath,
		adminTokenFile:      adminTokenPath,
		auditorOrgID:        testOrg,
		adminOrgID:          testOrg,
		adminFleetID:        testFleet,
		trustedControlKeys: []string{
			"id=remote-key-1,purpose=remote-kill-signing,inline=" + signing.EncodePublicKey(pub),
			"id=rollback-key-1,purpose=policy-bundle-rollback,inline=" + signing.EncodePublicKey(pub),
		},
		tlsCert:  filepath.Join(dir, "server.pem"),
		tlsKey:   filepath.Join(dir, "server.key"),
		clientCA: caPath,
	})
	if err != nil {
		t.Fatalf("buildServeHandler: %v", err)
	}

	keyPath, _ := writePolicyKeyFile(t, dir, wantPurposeFlag, "policy-key-override")
	cfgPath := writeFile(t, dir, "policy.yaml", testConfigYAML)
	bundle, _, priv, err := buildSignedBundle(publishOptions{
		configFile:   cfgPath,
		orgID:        testOrg,
		fleetID:      testFleet,
		environment:  testEnv,
		audience:     []string{"*"},
		version:      1,
		validity:     time.Hour,
		minVersion:   "1.2.3",
		signingKey:   keyPath,
		publisherTok: publisherTokenPath,
	})
	if err != nil {
		t.Fatalf("buildSignedBundle: %v", err)
	}
	zeroizeKey(priv)
	body, err := json.Marshal(struct {
		Bundle          conductorcore.PolicyBundle `json:"bundle"`
		AllowFleetSkew  bool                       `json:"allow_fleet_skew"`
		FleetSkewReason string                     `json:"fleet_skew_reason"`
	}{
		Bundle:          bundle,
		AllowFleetSkew:  true,
		FleetSkewReason: "operator break glass",
	})
	if err != nil {
		t.Fatalf("marshal publish request: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, controlplane.PublishPolicyBundlePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer publisher-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("publisher override code = %d body=%s, want 403", w.Code, w.Body.String())
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodPut, controlplane.PublishPolicyBundlePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-token")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("admin override code = %d body=%s, want 201", w.Code, w.Body.String())
	}
}

func TestBuildServeHandlerRequiresAuthInputs(t *testing.T) {
	_, _, _, err := buildServeHandler(context.Background(), serveOptions{
		storageDir: "/tmp/store",
		tlsCert:    "server.pem",
		tlsKey:     "server.key",
	})
	if err == nil || err.Error() != "--client-ca is required" {
		t.Fatalf("buildServeHandler() error = %v, want --client-ca required", err)
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(caPath, testCAPEM(t), 0o600); err != nil {
		t.Fatalf("WriteFile(ca): %v", err)
	}
	tokenPath := filepath.Join(dir, "publisher-token")
	if err := os.WriteFile(tokenPath, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(token): %v", err)
	}
	_, _, _, err = buildServeHandler(context.Background(), serveOptions{
		storageDir:          filepath.Join(dir, "store"),
		followerTrustDomain: defaultTrustDomain,
		tlsCert:             "server.pem",
		tlsKey:              "server.key",
		clientCA:            caPath,
		publisherTokenFile:  tokenPath,
	})
	if err == nil || err.Error() != "--auditor-token-file is required" {
		t.Fatalf("buildServeHandler() error = %v, want --auditor-token-file required", err)
	}
	auditorTokenPath := filepath.Join(dir, "auditor-token")
	if err := os.WriteFile(auditorTokenPath, []byte("auditor-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(auditor token): %v", err)
	}
	_, _, _, err = buildServeHandler(context.Background(), serveOptions{
		storageDir:          filepath.Join(dir, "store"),
		followerTrustDomain: defaultTrustDomain,
		tlsCert:             "server.pem",
		tlsKey:              "server.key",
		clientCA:            caPath,
		publisherTokenFile:  tokenPath,
		auditorTokenFile:    auditorTokenPath,
	})
	if err == nil || err.Error() != "--admin-token-file is required" {
		t.Fatalf("buildServeHandler() error = %v, want --admin-token-file required", err)
	}
	adminTokenPath := filepath.Join(dir, "admin-token")
	if err := os.WriteFile(adminTokenPath, []byte("admin-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(admin token): %v", err)
	}
	_, _, _, err = buildServeHandler(context.Background(), serveOptions{
		storageDir:          filepath.Join(dir, "store"),
		followerTrustDomain: defaultTrustDomain,
		tlsCert:             "server.pem",
		tlsKey:              "server.key",
		clientCA:            caPath,
		publisherTokenFile:  tokenPath,
		auditorTokenFile:    auditorTokenPath,
		adminTokenFile:      adminTokenPath,
	})
	if err == nil || err.Error() != "--auditor-org is required" {
		t.Fatalf("buildServeHandler(missing auditor org) error = %v, want --auditor-org required", err)
	}
	_, _, _, err = buildServeHandler(context.Background(), serveOptions{
		storageDir:          filepath.Join(dir, "store"),
		followerTrustDomain: defaultTrustDomain,
		tlsCert:             "server.pem",
		tlsKey:              "server.key",
		clientCA:            caPath,
		publisherTokenFile:  tokenPath,
		auditorTokenFile:    auditorTokenPath,
		adminTokenFile:      adminTokenPath,
		auditorOrgID:        "org-main",
	})
	if err == nil || err.Error() != "--admin-org is required" {
		t.Fatalf("buildServeHandler(missing admin org) error = %v, want --admin-org required", err)
	}
	_, _, _, err = buildServeHandler(context.Background(), serveOptions{
		storageDir:          filepath.Join(dir, "store"),
		followerTrustDomain: defaultTrustDomain,
		tlsCert:             "server.pem",
		tlsKey:              "server.key",
		clientCA:            caPath,
		publisherTokenFile:  tokenPath,
		auditorTokenFile:    auditorTokenPath,
		adminTokenFile:      adminTokenPath,
		auditorOrgID:        "org-main",
		adminOrgID:          "org-main",
	})
	if err == nil || !errors.Is(err, controlplane.ErrEmergencyKeyRequired) {
		t.Fatalf("buildServeHandler(no trusted control keys) error = %v, want ErrEmergencyKeyRequired", err)
	}
	pub, _, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		t.Fatalf("GenerateKey(control): %v", genErr)
	}
	_, _, _, err = buildServeHandler(context.Background(), serveOptions{
		storageDir:          filepath.Join(dir, "store"),
		followerTrustDomain: defaultTrustDomain,
		tlsCert:             "server.pem",
		tlsKey:              "server.key",
		clientCA:            caPath,
		publisherTokenFile:  tokenPath,
		auditorTokenFile:    auditorTokenPath,
		adminTokenFile:      adminTokenPath,
		auditorOrgID:        "org-main",
		adminOrgID:          "org-main",
		trustedControlKeys: []string{
			"id=remote-key-1,purpose=remote-kill-signing,inline=" + signing.EncodePublicKey(pub),
			"id=rollback-key-1,purpose=policy-bundle-rollback,inline=" + signing.EncodePublicKey(pub),
		},
	})
	if err != nil {
		t.Fatalf("buildServeHandler(no trusted audit keys) error = %v, want nil", err)
	}
}

func TestBuildServeHandlerRejectsNegativeAuditRetention(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "publisher-token")
	if err := os.WriteFile(tokenPath, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(token): %v", err)
	}
	auditorTokenPath := filepath.Join(dir, "auditor-token")
	if err := os.WriteFile(auditorTokenPath, []byte("auditor-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(auditor token): %v", err)
	}
	adminTokenPath := filepath.Join(dir, "admin-token")
	if err := os.WriteFile(adminTokenPath, []byte("admin-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(admin token): %v", err)
	}
	caPath := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(caPath, testCAPEM(t), 0o600); err != nil {
		t.Fatalf("WriteFile(ca): %v", err)
	}
	_, _, _, err = buildServeHandler(context.Background(), serveOptions{
		storageDir:          filepath.Join(dir, "store"),
		followerTrustDomain: defaultTrustDomain,
		tlsCert:             "server.pem",
		tlsKey:              "server.key",
		clientCA:            caPath,
		publisherTokenFile:  tokenPath,
		auditorTokenFile:    auditorTokenPath,
		adminTokenFile:      adminTokenPath,
		auditRetention:      -time.Second,
		trustedAuditKeys: []string{
			"id=audit-key-1,inline=" + signing.EncodePublicKey(pub) + ",org=org-main",
		},
	})
	if err == nil || err.Error() != "--audit-retention must be non-negative" {
		t.Fatalf("buildServeHandler(negative retention) error = %v, want --audit-retention error", err)
	}
}

func TestBuildServeHandlerPrunesAuditRetention(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "publisher-token")
	if err := os.WriteFile(tokenPath, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(token): %v", err)
	}
	auditorTokenPath := filepath.Join(dir, "auditor-token")
	if err := os.WriteFile(auditorTokenPath, []byte("auditor-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(auditor token): %v", err)
	}
	adminTokenPath := filepath.Join(dir, "admin-token")
	if err := os.WriteFile(adminTokenPath, []byte("admin-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(admin token): %v", err)
	}
	caPath := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(caPath, testCAPEM(t), 0o600); err != nil {
		t.Fatalf("WriteFile(ca): %v", err)
	}
	var logs strings.Builder
	handler, _, _, err := buildServeHandler(context.Background(), serveOptions{
		storageDir:          filepath.Join(dir, "store"),
		followerTrustDomain: defaultTrustDomain,
		tlsCert:             "server.pem",
		tlsKey:              "server.key",
		clientCA:            caPath,
		publisherTokenFile:  tokenPath,
		auditorTokenFile:    auditorTokenPath,
		adminTokenFile:      adminTokenPath,
		auditorOrgID:        "org-main",
		adminOrgID:          "org-main",
		auditRetention:      time.Hour,
		logWriter:           &logs,
		trustedControlKeys: []string{
			"id=remote-key-1,purpose=remote-kill-signing,inline=" + signing.EncodePublicKey(pub),
			"id=rollback-key-1,purpose=policy-bundle-rollback,inline=" + signing.EncodePublicKey(pub),
		},
	})
	if err != nil {
		t.Fatalf("buildServeHandler(retention) error = %v", err)
	}
	if handler == nil {
		t.Fatal("buildServeHandler(retention) handler = nil")
	}
	if logs.Len() != 0 {
		t.Fatalf("retention logs = %q, want empty for zero pruned rows", logs.String())
	}
}

func TestLogAuditPruneResult(t *testing.T) {
	var buf strings.Builder
	logAuditPruneResult(&buf, controlplane.AuditPruneResult{
		Deleted: 3,
		Before:  time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
	})
	want := "pipelock: conductor pruned 3 audit batches received before 2026-05-23T12:00:00Z\n"
	if buf.String() != want {
		t.Fatalf("logAuditPruneResult() = %q, want %q", buf.String(), want)
	}

	buf.Reset()
	logAuditPruneResult(&buf, controlplane.AuditPruneResult{Before: time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)})
	if buf.Len() != 0 {
		t.Fatalf("logAuditPruneResult(zero deleted) = %q, want empty", buf.String())
	}
}

func TestRunServeReturnsTLSLoadError(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "publisher-token")
	if err := os.WriteFile(tokenPath, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(token): %v", err)
	}
	auditorTokenPath := filepath.Join(dir, "auditor-token")
	if err := os.WriteFile(auditorTokenPath, []byte("auditor-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(auditor token): %v", err)
	}
	adminTokenPath := filepath.Join(dir, "admin-token")
	if err := os.WriteFile(adminTokenPath, []byte("admin-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(admin token): %v", err)
	}
	caPath := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(caPath, testCAPEM(t), 0o600); err != nil {
		t.Fatalf("WriteFile(ca): %v", err)
	}
	cmd := serveCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	err = runServe(cmd, serveOptions{
		listen:              "127.0.0.1:0",
		storageDir:          filepath.Join(dir, "store"),
		conductorID:         "conductor-test",
		followerTrustDomain: defaultTrustDomain,
		publisherTokenFile:  tokenPath,
		auditorTokenFile:    auditorTokenPath,
		adminTokenFile:      adminTokenPath,
		auditorOrgID:        "org-main",
		adminOrgID:          "org-main",
		trustedAuditKeys: []string{
			"id=audit-key-1,inline=" + signing.EncodePublicKey(pub) + ",org=org-main",
		},
		trustedControlKeys: []string{
			"id=remote-key-1,purpose=remote-kill-signing,inline=" + signing.EncodePublicKey(pub),
			"id=rollback-key-1,purpose=policy-bundle-rollback,inline=" + signing.EncodePublicKey(pub),
		},
		tlsCert:  filepath.Join(dir, "missing-server.pem"),
		tlsKey:   filepath.Join(dir, "missing-server.key"),
		clientCA: caPath,
	})
	if err == nil || !strings.Contains(err.Error(), "missing-server.pem") {
		t.Fatalf("runServe() error = %v, want missing TLS cert error", err)
	}
	if out.String() != "" {
		t.Fatalf("runServe() output = %q, want no listening claim before TLS identity validation", out.String())
	}
}

func TestParseAuditKeySpec(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		spec, err := parseAuditKeySpec("id=k1,inline=abc,org=o,fleet=f,instance=i")
		if err != nil {
			t.Fatalf("parseAuditKeySpec() error = %v", err)
		}
		if spec.id != "k1" || spec.inline != "abc" || spec.orgID != "o" || spec.fleetID != "f" || spec.instanceID != "i" {
			t.Fatalf("spec = %+v", spec)
		}
	})

	rejections := []struct {
		name   string
		input  string
		errSub string
	}{
		{"missing id", "inline=abc,org=o", "id= required"},
		{"missing org", "id=k1,inline=abc", "org= required"},
		{"missing material", "id=k1,org=o", "exactly one of inline= or file="},
		{"both inline and file", "id=k1,inline=abc,file=/tmp/x,org=o", "exactly one of inline= or file="},
		{"duplicate field", "id=k1,id=k2,inline=abc,org=o", "duplicate key"},
		{"unknown field", "id=k1,inline=abc,org=o,bogus=x", "unknown field"},
		{"empty input", "", "empty"},
		{"no equals", "id-k1,inline=abc", "expected k=v pairs"},
	}
	for _, c := range rejections {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseAuditKeySpec(c.input)
			if err == nil {
				t.Fatalf("parseAuditKeySpec(%q) error = nil, want %q", c.input, c.errSub)
			}
			if !strings.Contains(err.Error(), c.errSub) {
				t.Fatalf("parseAuditKeySpec(%q) error = %v, want substring %q", c.input, err, c.errSub)
			}
		})
	}
}

func TestParseControlKeySpec(t *testing.T) {
	spec, err := parseControlKeySpec("id=k1,purpose=remote-kill-signing,inline=abc")
	if err != nil {
		t.Fatalf("parseControlKeySpec() error = %v", err)
	}
	if spec.id != "k1" || spec.inline != "abc" || spec.purpose != signing.PurposeRemoteKillSigning {
		t.Fatalf("spec = %+v", spec)
	}

	rejections := []struct {
		name   string
		input  string
		errSub string
	}{
		{"missing id", "purpose=remote-kill-signing,inline=abc", "id= required"},
		{"missing material", "id=k1,purpose=remote-kill-signing", "exactly one of inline= or file="},
		{"both inline and file", "id=k1,purpose=remote-kill-signing,inline=abc,file=/tmp/x", "exactly one of inline= or file="},
		{"invalid purpose", "id=k1,purpose=policy-bundle-signing,inline=abc", "purpose= must be"},
		{"duplicate field", "id=k1,id=k2,purpose=remote-kill-signing,inline=abc", "duplicate key"},
		{"unknown field", "id=k1,purpose=remote-kill-signing,inline=abc,org=o", "unknown field"},
		{"empty input", "", "empty"},
		{"no equals", "id-k1,inline=abc", "expected k=v pairs"},
	}
	for _, c := range rejections {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseControlKeySpec(c.input)
			if err == nil {
				t.Fatalf("parseControlKeySpec(%q) error = nil, want %q", c.input, c.errSub)
			}
			if !strings.Contains(err.Error(), c.errSub) {
				t.Fatalf("parseControlKeySpec(%q) error = %v, want substring %q", c.input, err, c.errSub)
			}
		})
	}
}

func TestBuildKeyResolversLoadTrustedKeys(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "control.pub")
	if err := os.WriteFile(keyPath, []byte(signing.EncodePublicKey(pub)), 0o600); err != nil {
		t.Fatalf("WriteFile(control key): %v", err)
	}

	controlResolver, err := buildControlKeyResolver([]string{
		"id=remote-key,purpose=remote-kill-signing,file=" + keyPath,
		"id=rollback-key,purpose=policy-bundle-rollback,inline=" + signing.EncodePublicKey(pub),
	})
	if err != nil {
		t.Fatalf("buildControlKeyResolver() error = %v", err)
	}
	remoteKey, err := controlResolver("remote-key")
	if err != nil {
		t.Fatalf("controlResolver(remote-key) error = %v", err)
	}
	if remoteKey.KeyPurpose != signing.PurposeRemoteKillSigning || !bytes.Equal(remoteKey.PublicKey, pub) {
		t.Fatalf("remote key = %+v, want remote kill key", remoteKey)
	}
	if _, err := controlResolver("missing-key"); !errors.Is(err, conductorcore.ErrSignatureVerification) {
		t.Fatalf("controlResolver(missing) error = %v, want ErrSignatureVerification", err)
	}
	if _, err := buildControlKeyResolver(nil); !errors.Is(err, controlplane.ErrEmergencyKeyRequired) {
		t.Fatalf("buildControlKeyResolver(empty) error = %v, want ErrEmergencyKeyRequired", err)
	}
	if _, err := buildControlKeyResolver([]string{
		"id=dup,purpose=remote-kill-signing,inline=" + signing.EncodePublicKey(pub),
		"id=dup,purpose=policy-bundle-rollback,inline=" + signing.EncodePublicKey(pub),
	}); err == nil || !strings.Contains(err.Error(), "duplicate --trusted-control-key id") {
		t.Fatalf("buildControlKeyResolver(duplicate) error = %v, want duplicate id", err)
	}

	auditResolver, err := buildAuditKeyResolver([]string{
		"id=audit-key,file=" + keyPath + ",org=org-main,fleet=prod,instance=pl-prod-1",
	})
	if err != nil {
		t.Fatalf("buildAuditKeyResolver() error = %v", err)
	}
	auditKey, err := auditResolver(controlplane.FollowerIdentity{
		OrgID:      "org-main",
		FleetID:    "prod",
		InstanceID: "pl-prod-1",
	}, "audit-key")
	if err != nil {
		t.Fatalf("auditResolver(audit-key) error = %v", err)
	}
	if auditKey.KeyPurpose != signing.PurposeAuditBatchSigning || !bytes.Equal(auditKey.PublicKey, pub) {
		t.Fatalf("audit key = %+v, want audit batch key", auditKey)
	}
	if _, err := buildAuditKeyResolver(nil); !errors.Is(err, controlplane.ErrAuditKeyRequired) {
		t.Fatalf("buildAuditKeyResolver(empty) error = %v, want ErrAuditKeyRequired", err)
	}
}

func TestLoadTokenFileRejectsMissingAndEmpty(t *testing.T) {
	if _, err := loadTokenFile("--token-file", ""); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("loadTokenFile(empty path) error = %v, want required", err)
	}
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("  \n\t"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadTokenFile("--token-file", empty); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("loadTokenFile(whitespace) error = %v, want empty", err)
	}
	tok := filepath.Join(dir, "tok")
	if err := os.WriteFile(tok, []byte("  hello-token  \n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := loadTokenFile("--token-file", tok)
	if err != nil {
		t.Fatalf("loadTokenFile() error = %v", err)
	}
	if got != "hello-token" {
		t.Fatalf("loadTokenFile() = %q, want trimmed token", got)
	}
}

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(CA): %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test client CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// requireModeKeys builds a root keypair, an intermediate cert + key, and the
// signed fresh CRL file used by the require-intermediate env-only command tests.
func requireModeKeys(t *testing.T) (rootPubHex, crlPath, intPath string, rootPriv, intPriv ed25519.PrivateKey) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("root keygen: %v", err)
	}
	intPub, intPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("int keygen: %v", err)
	}
	now := time.Now()
	cert, err := license.SignIntermediate(license.IntermediatePayload{
		Serial:    "int-test-001",
		Purpose:   license.PurposeLicenseSigning,
		Algorithm: license.AlgorithmEd25519,
		PublicKey: hexEncode(intPub),
		NotBefore: now.Add(-time.Hour).Unix(),
		NotAfter:  now.Add(30 * 24 * time.Hour).Unix(),
		IssuedAt:  now.Add(-time.Hour).Unix(),
	}, rootPriv)
	if err != nil {
		t.Fatalf("SignIntermediate: %v", err)
	}
	certBytes, err := cert.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal cert: %v", err)
	}
	dir := t.TempDir()
	intPath = filepath.Join(dir, "intermediate.json")
	if err := os.WriteFile(intPath, certBytes, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	crl, err := license.SignCRL(license.CRLPayload{
		Version:    license.CRLVersion,
		Generation: 1,
		IssuedAt:   now.Add(-time.Hour).Unix(),
		ExpiresAt:  now.Add(7 * 24 * time.Hour).Unix(),
	}, rootPriv)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	crlBytes, err := crl.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal CRL: %v", err)
	}
	crlPath = filepath.Join(dir, "crl.json")
	if err := os.WriteFile(crlPath, crlBytes, 0o600); err != nil {
		t.Fatalf("write CRL: %v", err)
	}
	return hexEncode(rootPub), crlPath, intPath, rootPriv, intPriv
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

func issueFleetToken(t *testing.T, signer ed25519.PrivateKey, id string) string {
	t.Helper()
	tok, err := license.Issue(license.License{
		ID:       id,
		Email:    "ops@example.test",
		IssuedAt: time.Now().Add(-time.Hour).Unix(),
		Features: []string{license.FeatureFleet},
	}, signer)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return tok
}

// TestEnvOnlyCommand_RequireIntermediateHonored proves the require-intermediate
// knob is honored on a real env-only conductor CLI command (`kill status`),
// which resolves its entire license from the environment via
// VerifyFleetWithOptions. This is the actual round-1 fail-open path: ~18
// commands called VerifyFleet("","",crl) directly, ignoring require mode.
func TestEnvOnlyCommand_RequireIntermediateHonored(t *testing.T) {
	if license.EmbeddedPublicKey() != nil {
		t.Skip("embedded license key present; env public key override is ignored")
	}
	rootPubHex, crlPath, intPath, rootPriv, intPriv := requireModeKeys(t)

	run := func(t *testing.T, token string) error {
		t.Setenv(license.EnvLicenseKey, token)
		t.Setenv(license.EnvLicensePublicKey, rootPubHex)
		t.Setenv(license.EnvLicenseCRLFile, crlPath)
		t.Setenv(license.EnvLicenseIntermediateFile, intPath)
		t.Setenv(license.EnvLicenseRequireIntermediate, "true")
		cmd := Cmd()
		// kill status: license gate first, then "--org-id is required".
		cmd.SetArgs([]string{"kill", "status"})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		return cmd.Execute()
	}

	t.Run("root_signed_token_rejected_under_require", func(t *testing.T) {
		err := run(t, issueFleetToken(t, rootPriv, "lic_root"))
		if !errors.Is(err, license.ErrFleetLicenseRequired) {
			t.Fatalf("root-signed token under require must be rejected at the license gate, got %v", err)
		}
	})

	t.Run("intermediate_signed_token_passes_gate", func(t *testing.T) {
		err := run(t, issueFleetToken(t, intPriv, "lic_int"))
		// The gate passes; the command then fails for a non-license reason
		// (--org-id is required). Assert the gate did NOT reject it.
		if errors.Is(err, license.ErrFleetLicenseRequired) {
			t.Fatalf("intermediate-signed token must pass the require gate, got fleet-required: %v", err)
		}
		if err == nil || !strings.Contains(err.Error(), "org-id") {
			t.Fatalf("expected post-gate --org-id error, got %v", err)
		}
	})
}
