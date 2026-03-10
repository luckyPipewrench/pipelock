//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	_ "github.com/luckyPipewrench/pipelock/enterprise/testinit"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

// testLicenseToken generates a valid signed license token and hex public key for tests.
func testLicenseToken(t *testing.T) (token, pubKeyHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lic := license.License{
		ID:        "lic_test",
		Email:     "test@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	tok, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tok, hex.EncodeToString(pub)
}

func TestRunCmd_AgentListenerBinding(t *testing.T) {
	mainAddr := freePort(t)
	agentAddr := freePort(t)
	licToken, licPubHex := testLicenseToken(t)

	cfgYAML := fmt.Sprintf(`version: 1
mode: balanced
license_key: %s
license_public_key: %s
fetch_proxy:
  listen: %q
  timeout_seconds: 5
  max_response_mb: 1
agents:
  test-agent:
    listeners:
      - %q
logging:
  format: json
  output: stdout
`, licToken, licPubHex, mainAddr, agentAddr)

	tmpFile, err := os.CreateTemp(t.TempDir(), "pipelock-*.yaml")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	if _, err := tmpFile.WriteString(cfgYAML); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_ = tmpFile.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := runCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--config", tmpFile.Name()})
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetOut(&stderr)

	cmdErr := make(chan error, 1)
	go func() {
		cmdErr <- cmd.Execute()
	}()

	// Wait for both ports.
	waitForPort(t, mainAddr)
	waitForPort(t, agentAddr)

	client := &http.Client{Timeout: 2 * time.Second}

	// Main port: /health should work.
	resp := doGet(t, client, "http://"+mainAddr+"/health")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("main /health: want 200, got %d", resp.StatusCode)
	}

	// Agent port: /health should also work (same handler, different context).
	resp = doGet(t, client, "http://"+agentAddr+"/health")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("agent /health: want 200, got %d", resp.StatusCode)
	}

	// Agent port: /fetch should respond (validates handler is wired).
	// Without a URL param, it should return 400 (bad request).
	resp = doGet(t, client, "http://"+agentAddr+"/fetch")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("agent /fetch without url: want 400, got %d", resp.StatusCode)
	}

	// Shut down.
	cancel()
	select {
	case err := <-cmdErr:
		if err != nil {
			t.Errorf("runCmd returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runCmd did not exit within 5s")
	}

	// Verify startup output contains agent listener messages.
	output := stderr.String()
	if !bytes.Contains([]byte(output), []byte("test-agent")) {
		t.Errorf("expected 'test-agent' in startup output, got:\n%s", output)
	}
	if !bytes.Contains([]byte(output), []byte(agentAddr)) {
		t.Errorf("expected agent addr %q in startup output, got:\n%s", agentAddr, output)
	}
}

func TestRunCmd_AgentListenerExpiryShutdown(t *testing.T) {
	mainAddr := freePort(t)
	agentAddr := freePort(t)

	// Issue a license that expires in 2 seconds.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lic := license.License{
		ID:        "lic_expiry_test",
		Email:     "test@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(2 * time.Second).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	tok, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)

	cfgYAML := fmt.Sprintf(`version: 1
mode: balanced
license_key: %s
license_public_key: %s
fetch_proxy:
  listen: %q
  timeout_seconds: 5
  max_response_mb: 1
agents:
  test-agent:
    listeners:
      - %q
logging:
  format: json
  output: stdout
`, tok, pubHex, mainAddr, agentAddr)

	tmpFile, err := os.CreateTemp(t.TempDir(), "pipelock-*.yaml")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	if _, err := tmpFile.WriteString(cfgYAML); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_ = tmpFile.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := runCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--config", tmpFile.Name()})
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetOut(&stderr)

	cmdErr := make(chan error, 1)
	go func() {
		cmdErr <- cmd.Execute()
	}()

	// Wait for both ports to come up.
	waitForPort(t, mainAddr)
	waitForPort(t, agentAddr)

	client := &http.Client{Timeout: 2 * time.Second}

	// Agent port should work before expiry.
	resp := doGet(t, client, "http://"+agentAddr+"/health")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("agent /health before expiry: want 200, got %d", resp.StatusCode)
	}

	// Wait for the license to expire + watchdog to shut down agent listeners.
	// License expires in 2s, give 1.5s grace for the shutdown.
	time.Sleep(3500 * time.Millisecond)

	// Agent port should be closed now.
	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	conn, dialErr := dialer.DialContext(context.Background(), "tcp4", agentAddr)
	if dialErr == nil {
		_ = conn.Close()
		t.Error("expected agent port to be closed after license expiry, but dial succeeded")
	}

	// Main port should still be running.
	resp = doGet(t, client, "http://"+mainAddr+"/health")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("main /health after expiry: want 200, got %d", resp.StatusCode)
	}

	// Shut down the server, THEN read stderr to avoid data races with
	// background goroutines writing to the shared buffer.
	cancel()
	select {
	case err := <-cmdErr:
		if err != nil {
			t.Errorf("runCmd returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runCmd did not exit within 5s")
	}

	// Verify the expiry message was logged (safe to read after command exited).
	if !bytes.Contains(stderr.Bytes(), []byte("license expired")) {
		t.Errorf("expected 'license expired' in stderr, got:\n%s", stderr.String())
	}
}

func TestRunCmd_AgentListenerMultipleAgents(t *testing.T) {
	mainAddr := freePort(t)
	agentAAddr := freePort(t)
	agentBAddr := freePort(t)
	licToken, licPubHex := testLicenseToken(t)

	cfgYAML := fmt.Sprintf(`version: 1
mode: balanced
license_key: %s
license_public_key: %s
fetch_proxy:
  listen: %q
  timeout_seconds: 5
  max_response_mb: 1
agents:
  agent-a:
    listeners:
      - %q
  agent-b:
    listeners:
      - %q
logging:
  format: json
  output: stdout
`, licToken, licPubHex, mainAddr, agentAAddr, agentBAddr)

	tmpFile, err := os.CreateTemp(t.TempDir(), "pipelock-*.yaml")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	if _, err := tmpFile.WriteString(cfgYAML); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_ = tmpFile.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := runCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--config", tmpFile.Name()})
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetOut(&stderr)

	cmdErr := make(chan error, 1)
	go func() {
		cmdErr <- cmd.Execute()
	}()

	// Wait for all three ports.
	waitForPort(t, mainAddr)
	waitForPort(t, agentAAddr)
	waitForPort(t, agentBAddr)

	client := &http.Client{Timeout: 2 * time.Second}

	// All three ports should serve /health.
	for _, addr := range []string{mainAddr, agentAAddr, agentBAddr} {
		resp := doGet(t, client, "http://"+addr+"/health")
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("/health on %s: want 200, got %d", addr, resp.StatusCode)
		}
	}

	// Shut down.
	cancel()
	select {
	case err := <-cmdErr:
		if err != nil {
			t.Errorf("runCmd returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runCmd did not exit within 5s")
	}
}
