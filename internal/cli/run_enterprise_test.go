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

// TestRunCmd_ReloadAgentLifecycleRespected verifies that when a config
// reload causes EnforceLicenseGate to disable agents, listener preservation
// does not resurrect them. The license gate decision must be final.
func TestRunCmd_ReloadAgentLifecycleRespected(t *testing.T) {
	mainAddr := freePort(t)
	agentAddr := freePort(t)
	licToken, licPubHex := testLicenseToken(t)

	// Start with valid license + agent with listener.
	cfgYAML := fmt.Sprintf(`version: 1
mode: balanced
license_key: %s
license_public_key: %s
fetch_proxy:
  listen: %q
  timeout_seconds: 5
  max_response_mb: 1
agents:
  secured-agent:
    listeners:
      - %q
    mode: strict
    api_allowlist:
      - "api.example.com"
logging:
  format: json
  output: stdout
`, licToken, licPubHex, mainAddr, agentAddr)

	dir := t.TempDir()
	cfgPath := dir + "/test.yaml"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := runCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--config", cfgPath})
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetOut(&stderr)

	cmdErr := make(chan error, 1)
	go func() {
		cmdErr <- cmd.Execute()
	}()

	// Wait for both ports to be serving.
	waitForPort(t, mainAddr)
	waitForPort(t, agentAddr)

	client := &http.Client{Timeout: 2 * time.Second}

	// Confirm agent listener is working before reload.
	resp := doGet(t, client, "http://"+agentAddr+"/health")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("agent /health before reload: want 200, got %d", resp.StatusCode)
	}

	// Hot-reload: remove license_key. EnforceLicenseGate should
	// disable agents, and they must stay disabled.
	reloadedCfg := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: %q
  timeout_seconds: 5
  max_response_mb: 1
agents:
  secured-agent:
    listeners:
      - %q
    mode: strict
    api_allowlist:
      - "api.example.com"
logging:
  format: json
  output: stdout
`, mainAddr, agentAddr)
	if err := os.WriteFile(cfgPath, []byte(reloadedCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// Wait for reload to process (fsnotify debounce is 100ms)
	// plus agent listener shutdown (5s graceful timeout max).
	time.Sleep(800 * time.Millisecond)

	// Agent port must be closed after license revocation on reload.
	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	conn, dialErr := dialer.DialContext(context.Background(), "tcp4", agentAddr)
	if dialErr == nil {
		_ = conn.Close()
		t.Error("expected agent port to be closed after license revocation on reload, but dial succeeded")
	}

	// Main port must still be running.
	resp = doGet(t, client, "http://"+mainAddr+"/health")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("main /health after reload: want 200, got %d", resp.StatusCode)
	}

	// Shut down the server, THEN read stderr to avoid data races.
	cancel()
	select {
	case err := <-cmdErr:
		if err != nil {
			t.Errorf("runCmd returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runCmd did not exit within 5s")
	}

	output := stderr.String()

	// Verify agent listeners were shut down via the revocation path.
	// The revocation branch (agentsRevokedByLicense) takes priority over
	// the license-inputs-changed branch in the if/else-if chain, so the
	// "license key inputs changed" warning does not appear here.
	if !bytes.Contains([]byte(output), []byte("shutting down agent listeners")) {
		t.Errorf("expected agent listener shutdown message after reload, got:\n%s", output)
	}

	// Listener preservation must not override the license gate.
	if bytes.Contains([]byte(output), []byte("ignoring listener changes")) {
		t.Error("listener preservation should not run when license gate disabled agents")
	}
}

// TestRunCmd_ReloadLicenseAddedNoActivation verifies that adding a valid
// license via reload does NOT activate agent features. The old agent state
// (nil) must be preserved; the operator must restart for the license to
// take effect. This prevents partial activation with a stale
// LicenseExpiresAt=0 (perpetual).
func TestRunCmd_ReloadLicenseAddedNoActivation(t *testing.T) {
	mainAddr := freePort(t)
	licToken, licPubHex := testLicenseToken(t)

	// Start with NO license — agents section present but will be gated.
	initialCfg := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: %q
  timeout_seconds: 5
agents:
  header-agent:
    source_cidrs:
      - "10.0.0.0/8"
`, mainAddr)

	dir := t.TempDir()
	cfgPath := dir + "/pipelock.yaml"
	if err := os.WriteFile(cfgPath, []byte(initialCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := runCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--config", cfgPath})
	var stderr bytes.Buffer
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&stderr)

	errCh := make(chan error, 1)
	go func() { errCh <- cmd.Execute() }()

	// Wait for healthy.
	waitForPort(t, mainAddr)

	// Reload: add a valid license. EnforceLicenseGate in Load() will
	// verify it and set Agents non-nil, but the reload handler must
	// preserve old (nil) agents and warn.
	reloadCfg := fmt.Sprintf(`version: 1
mode: balanced
license_key: %s
license_public_key: %s
fetch_proxy:
  listen: %q
  timeout_seconds: 5
agents:
  header-agent:
    source_cidrs:
      - "10.0.0.0/8"
`, licToken, licPubHex, mainAddr)
	if err := os.WriteFile(cfgPath, []byte(reloadCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// Wait for reload.
	time.Sleep(500 * time.Millisecond)

	cancel()
	select {
	case cmdErr := <-errCh:
		if cmdErr != nil {
			t.Errorf("unexpected error: %v", cmdErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not shut down")
	}

	output := stderr.String()

	// Must warn about license inputs changing.
	if !bytes.Contains([]byte(output), []byte("license key inputs changed")) {
		t.Errorf("expected license change warning, got:\n%s", output)
	}

	// Must NOT have activated agents (no "agent listener bound"
	// means they were never started, which is correct).
	if bytes.Contains([]byte(output), []byte("agent listener bound")) {
		t.Error("agents should not have been activated on reload without restart")
	}
}

// TestRunCmd_ReloadLicenseTwoStepBypass verifies that a license staged on
// one reload cannot sneak through on a second unrelated reload. The old
// license input fields must be preserved in the live config so that
// licenseInputsChanged remains true across subsequent reloads.
func TestRunCmd_ReloadLicenseTwoStepBypass(t *testing.T) {
	mainAddr := freePort(t)
	licToken, licPubHex := testLicenseToken(t)

	// Start with NO license.
	initialCfg := fmt.Sprintf(`version: 1
mode: balanced
fetch_proxy:
  listen: %q
  timeout_seconds: 5
agents:
  header-agent:
    source_cidrs:
      - "10.0.0.0/8"
`, mainAddr)

	dir := t.TempDir()
	cfgPath := dir + "/pipelock.yaml"
	if err := os.WriteFile(cfgPath, []byte(initialCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := runCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--config", cfgPath})
	var stderr bytes.Buffer
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&stderr)

	errCh := make(chan error, 1)
	go func() { errCh <- cmd.Execute() }()

	waitForPort(t, mainAddr)

	// Reload 1: add a valid license. Should warn and preserve old state.
	reload1 := fmt.Sprintf(`version: 1
mode: balanced
license_key: %s
license_public_key: %s
fetch_proxy:
  listen: %q
  timeout_seconds: 5
agents:
  header-agent:
    source_cidrs:
      - "10.0.0.0/8"
`, licToken, licPubHex, mainAddr)
	if err := os.WriteFile(cfgPath, []byte(reload1), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)

	// Reload 2: unrelated change (mode). License inputs stay the same in
	// the config file. If the fix is correct, the live config still has the
	// OLD (empty) license inputs, so this reload also detects the mismatch.
	reload2 := fmt.Sprintf(`version: 1
mode: audit
license_key: %s
license_public_key: %s
fetch_proxy:
  listen: %q
  timeout_seconds: 5
agents:
  header-agent:
    source_cidrs:
      - "10.0.0.0/8"
`, licToken, licPubHex, mainAddr)
	if err := os.WriteFile(cfgPath, []byte(reload2), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)

	cancel()
	select {
	case cmdErr := <-errCh:
		if cmdErr != nil {
			t.Errorf("unexpected error: %v", cmdErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not shut down")
	}

	output := stderr.String()

	// The license change warning must appear TWICE: once per reload.
	// If it only appears once, the second reload silently applied the
	// staged license (the two-step bypass bug).
	count := bytes.Count([]byte(output), []byte("license key inputs changed"))
	if count < 2 {
		t.Errorf("expected license change warning on BOTH reloads, got %d occurrence(s):\n%s", count, output)
	}

	// Agents must never have been activated.
	if bytes.Contains([]byte(output), []byte("agent listener bound")) {
		t.Error("agents should not have been activated across two reloads without restart")
	}
}
