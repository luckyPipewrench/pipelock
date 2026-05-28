//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/emergency"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestNewServer_ConductorAuditProducerFromConfig(t *testing.T) {
	setTestFleetLicense(t)
	tmp, err := os.MkdirTemp(".", ".runtime-conductor-*")
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
	writePrivateTestFile(t, trustPath, []byte(`{"keys":[]}`))
	writePrivateTestFile(t, caPath, clientPEM)
	writePrivateTestFile(t, clientCertPath, clientPEM)
	writePrivateTestFile(t, clientKeyPath, clientKeyPEM)

	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  dir: " + strconv.Quote(filepath.Join(tmp, "recorder")),
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
	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: buf, Stderr: buf})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })

	if s.conductorAudit == nil {
		t.Fatal("conductor audit transport should be initialized")
	}
	if s.conductorProducer == nil {
		t.Fatal("conductor audit producer should be initialized")
	}
	for _, want := range []string{"Recorder:", "Conductor: audit producer enabled"} {
		if !buf.contains(want) {
			t.Fatalf("stderr missing %q:\n%s", want, buf.String())
		}
	}
}

func TestConductorRecorderPublicKey(t *testing.T) {
	if _, err := conductorRecorderPublicKey(nil); err == nil || !strings.Contains(err.Error(), "flight recorder signing key") {
		t.Fatalf("nil key error = %v, want signing key error", err)
	}
	if _, err := conductorRecorderPublicKey(ed25519.PrivateKey("short")); err == nil || !strings.Contains(err.Error(), "flight recorder signing key") {
		t.Fatalf("short key error = %v, want signing key error", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	got, err := conductorRecorderPublicKey(priv)
	if err != nil {
		t.Fatalf("conductorRecorderPublicKey(valid): %v", err)
	}
	if string(got) != string(pub) {
		t.Fatal("public key mismatch")
	}
}

type serverRemoteKillNoopClient struct{}

func (serverRemoteKillNoopClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestServer_StartRunsConductorRemoteKillPoller(t *testing.T) {
	s, buf := newTestServer(t, func(o *ServerOpts) {
		o.Listen = newServerTestFreePort(t)
		o.ListenChanged = true
	})
	poller, err := emergency.NewRemoteKillPoller(emergency.RemoteKillPollerConfig{
		BaseURL:      "https://conductor.example",
		Client:       serverRemoteKillNoopClient{},
		Applier:      &emergency.RemoteKillApplier{},
		PollInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("NewRemoteKillPoller: %v", err)
	}
	s.conductorRemoteKill = poller
	s.cfg.Conductor.ConductorURL = "https://conductor.example"

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		errCh <- s.Start(ctx)
	}()

	waitForServerCancel(t, s)
	waitForServerOutput(t, buf, "Conductor: remote kill polling enabled -> https://conductor.example")

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned error after Shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return within 5s of Shutdown")
	}
}
