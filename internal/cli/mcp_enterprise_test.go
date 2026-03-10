//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"

	_ "github.com/luckyPipewrench/pipelock/enterprise/testinit"
)

func TestMcpProxyCmd_AgentResolvesProfile(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("echo subprocess test requires unix")
	}

	// Config with an agent profile "strict-bot" that sets mode: strict.
	// The base config defaults to balanced, so the resolved config should be strict.
	// Strict mode requires an api_allowlist, so we include one.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lic := license.License{
		ID: "lic_mcp_test", Email: "test@example.com",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Features: []string{license.FeatureAgents},
	}
	licToken, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)
	cfgContent := "license_key: " + licToken + "\nlicense_public_key: " + pubHex + "\nagents:\n  strict-bot:\n    mode: strict\n    api_allowlist:\n      - example.com\n"
	cfgFile := t.TempDir() + "/agent.yaml"
	if err := os.WriteFile(cfgFile, []byte(cfgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cleanJSON := testSafeReply

	cmd := rootCmd()
	cmd.SetArgs([]string{"mcp", "proxy", "--config", cfgFile, "--agent", "strict-bot", "--", "echo", cleanJSON})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(&strings.Builder{})
	cmd.SetIn(bytes.NewReader(nil))

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the clean response was forwarded (proxy ran successfully with the resolved profile).
	output := strings.TrimSpace(buf.String())
	if output != cleanJSON {
		t.Errorf("expected clean response forwarded, got: %s", output)
	}
}
