//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/enrollmentclient"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

type conductorEnrollmentStubClient struct {
	mu     sync.Mutex
	status int
	body   string
	paths  []string
	bodies []string
}

func (c *conductorEnrollmentStubClient) Do(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.paths = append(c.paths, req.URL.Path)
	c.bodies = append(c.bodies, string(body))
	status := c.status
	respBody := c.body
	c.mu.Unlock()
	if status == 0 {
		status = http.StatusCreated
	}
	if respBody == "" {
		respBody = `{"org_id":"org-main","fleet_id":"prod","instance_id":"pl-prod-1","environment":"prod","audit_key_id":"audit-key-1","enrolled_at":"2026-06-11T12:00:00Z"}`
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(respBody)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func (c *conductorEnrollmentStubClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.paths)
}

func TestRunConductorAutoEnrollHappyPathPersistsMarkerAndSkipsSecondStart(t *testing.T) {
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	cfg := conductorEnrollmentTestConfig(t)
	client := &conductorEnrollmentStubClient{}
	enrolled, err := runConductorAutoEnroll(t.Context(), cfg, priv, client)
	if err != nil {
		t.Fatalf("runConductorAutoEnroll(first) error = %v", err)
	}
	if !enrolled {
		t.Fatal("runConductorAutoEnroll(first) enrolled=false, want true")
	}
	if client.count() != 1 {
		t.Fatalf("request count after first start = %d, want 1", client.count())
	}
	var req enrollmentclient.Request
	if err := json.Unmarshal([]byte(client.bodies[0]), &req); err != nil {
		t.Fatalf("decode enroll request: %v", err)
	}
	if req.Token != "pl_enroll_test" || req.AuditKeyID != "audit-key-1" || req.AuditPublicKey == "" {
		t.Fatalf("enroll request = %+v", req)
	}
	if _, err := signing.ParsePublicKey(req.AuditPublicKey); err != nil {
		t.Fatalf("enroll request audit_public_key does not parse: %v", err)
	}
	// The enrolled public key must be the recorder/audit-signer key's public
	// half: the leader verifies the follower's audit batches against exactly
	// this key, so a mismatch would silently break audit ingest.
	if got, want := req.AuditPublicKey, signing.EncodePublicKey(pub); got != want {
		t.Fatalf("enroll request audit_public_key = %q, want recorder public key %q", got, want)
	}
	markerPath := filepath.Join(cfg.Conductor.BundleCacheDir, conductorEnrolledStateFileName)
	info, err := os.Stat(markerPath)
	if err != nil {
		t.Fatalf("stat enrollment marker: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("marker mode = %v, want 0600", got)
	}

	enrolled, err = runConductorAutoEnroll(t.Context(), cfg, priv, client)
	if err != nil {
		t.Fatalf("runConductorAutoEnroll(second) error = %v", err)
	}
	if enrolled {
		t.Fatal("runConductorAutoEnroll(second) enrolled=true, want false")
	}
	if client.count() != 1 {
		t.Fatalf("request count after second start = %d, want still 1", client.count())
	}
}

func TestRunConductorAutoEnrollNoTokenConfiguredDoesNotPost(t *testing.T) {
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	cfg := conductorEnrollmentTestConfig(t)
	cfg.Conductor.EnrollmentTokenPath = ""
	client := &conductorEnrollmentStubClient{}
	enrolled, err := runConductorAutoEnroll(t.Context(), cfg, priv, client)
	if err != nil {
		t.Fatalf("runConductorAutoEnroll(no token) error = %v", err)
	}
	if enrolled {
		t.Fatal("runConductorAutoEnroll(no token) enrolled=true, want false")
	}
	if client.count() != 0 {
		t.Fatalf("request count = %d, want 0", client.count())
	}
}

func TestRunConductorAutoEnrollExistingMarkerSkipsPost(t *testing.T) {
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	cfg := conductorEnrollmentTestConfig(t)
	if err := os.WriteFile(filepath.Join(cfg.Conductor.BundleCacheDir, conductorEnrolledStateFileName), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	client := &conductorEnrollmentStubClient{}
	enrolled, err := runConductorAutoEnroll(t.Context(), cfg, priv, client)
	if err != nil {
		t.Fatalf("runConductorAutoEnroll(existing marker) error = %v", err)
	}
	if enrolled {
		t.Fatal("runConductorAutoEnroll(existing marker) enrolled=true, want false")
	}
	if client.count() != 0 {
		t.Fatalf("request count = %d, want 0", client.count())
	}
}

func TestInitConductorEnrollmentFailureDoesNotBlockStartup(t *testing.T) {
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	cfg := conductorEnrollmentTestConfig(t)
	client := &conductorEnrollmentStubClient{status: http.StatusUnauthorized, body: `{"error":"bad token"}`}
	old := newConductorEnrollmentHTTPClient
	newConductorEnrollmentHTTPClient = func(config.Conductor) (enrollmentclient.HTTPDoer, error) {
		return client, nil
	}
	t.Cleanup(func() { newConductorEnrollmentHTTPClient = old })

	var stderr bytes.Buffer
	if err := (&Server{}).initConductorEnrollment(cfg, priv, &stderr); err != nil {
		t.Fatalf("initConductorEnrollment() error = %v, want nil", err)
	}
	if !strings.Contains(stderr.String(), "conductor enrollment failed (continuing") {
		t.Fatalf("stderr = %q, want non-blocking warning", stderr.String())
	}
	if client.count() != 1 {
		t.Fatalf("request count = %d, want 1", client.count())
	}
	if _, err := os.Stat(filepath.Join(cfg.Conductor.BundleCacheDir, conductorEnrolledStateFileName)); !os.IsNotExist(err) {
		t.Fatalf("marker stat err = %v, want not exist", err)
	}
}

func TestRunConductorAutoEnrollNilRecorderKeyErrors(t *testing.T) {
	cfg := conductorEnrollmentTestConfig(t)
	client := &conductorEnrollmentStubClient{}
	// A nil recorder/flight-recorder key fails closed before any enroll POST:
	// the follower has no audit public key to register.
	_, err := runConductorAutoEnroll(t.Context(), cfg, nil, client)
	if err == nil || !strings.Contains(err.Error(), "flight recorder signing key") {
		t.Fatalf("runConductorAutoEnroll(nil key) error = %v, want recorder key required", err)
	}
	if client.count() != 0 {
		t.Fatalf("request count = %d, want 0 (no POST before key check)", client.count())
	}
}

func TestRunConductorAutoEnrollTokenReadError(t *testing.T) {
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	cfg := conductorEnrollmentTestConfig(t)
	// Point at a token path that does not exist so the read fails.
	cfg.Conductor.EnrollmentTokenPath = filepath.Join(t.TempDir(), "absent-token")
	client := &conductorEnrollmentStubClient{}
	_, err = runConductorAutoEnroll(t.Context(), cfg, priv, client)
	if err == nil || !strings.Contains(err.Error(), "read conductor enrollment token") {
		t.Fatalf("runConductorAutoEnroll(token read error) error = %v, want read error", err)
	}
	if client.count() != 0 {
		t.Fatalf("request count = %d, want 0", client.count())
	}
}

func TestRunConductorAutoEnrollBuildsClientWhenNil(t *testing.T) {
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	cfg := conductorEnrollmentTestConfig(t)
	client := &conductorEnrollmentStubClient{}
	// When the caller passes a nil HTTPDoer, runConductorAutoEnroll builds one
	// via newConductorEnrollmentHTTPClient. Stub that constructor.
	old := newConductorEnrollmentHTTPClient
	newConductorEnrollmentHTTPClient = func(config.Conductor) (enrollmentclient.HTTPDoer, error) {
		return client, nil
	}
	t.Cleanup(func() { newConductorEnrollmentHTTPClient = old })

	enrolled, err := runConductorAutoEnroll(t.Context(), cfg, priv, nil)
	if err != nil {
		t.Fatalf("runConductorAutoEnroll(nil client) error = %v", err)
	}
	if !enrolled {
		t.Fatal("runConductorAutoEnroll(nil client) enrolled=false, want true")
	}
	if client.count() != 1 {
		t.Fatalf("request count = %d, want 1", client.count())
	}
}

func TestReadConductorEnrollmentToken(t *testing.T) {
	t.Run("unreadable path", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "no-such-token")
		if _, err := readConductorEnrollmentToken(missing); err == nil ||
			!strings.Contains(err.Error(), "read conductor enrollment token") {
			t.Fatalf("readConductorEnrollmentToken(missing) error = %v, want read error", err)
		}
	})

	t.Run("empty contents", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "blank-token")
		if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
			t.Fatalf("write blank token: %v", err)
		}
		if _, err := readConductorEnrollmentToken(path); err == nil ||
			!strings.Contains(err.Error(), "token file is empty") {
			t.Fatalf("readConductorEnrollmentToken(blank) error = %v, want empty", err)
		}
	})

	t.Run("trims and returns", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		token := "pl_" + "enroll_runtime"
		if err := os.WriteFile(path, []byte("  "+token+"\n"), 0o600); err != nil {
			t.Fatalf("write token: %v", err)
		}
		got, err := readConductorEnrollmentToken(path)
		if err != nil {
			t.Fatalf("readConductorEnrollmentToken() error = %v", err)
		}
		if got != token {
			t.Fatalf("readConductorEnrollmentToken() = %q, want %q", got, token)
		}
	})
}

func conductorEnrollmentTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "enrollment-token")
	if err := os.WriteFile(tokenPath, []byte("pl_enroll_test\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return &config.Config{Conductor: config.Conductor{
		Enabled:             true,
		ConductorURL:        "https://conductor.example",
		BundleCacheDir:      dir,
		EnrollmentTokenPath: tokenPath,
		AuditSigningKeyID:   "audit-key-1",
		PollInterval:        time.Second.String(),
	}}
}
