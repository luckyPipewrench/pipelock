// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

// unsignedAgentCardRPC is a JSON-RPC envelope whose result is an Agent Card
// with skills + supportedInterfaces (the shape ScanResponseA2A recognizes) and
// no signatures. Generic MCP response scanning treats this as clean text.
func unsignedAgentCardRPC() string {
	return `{"jsonrpc":"2.0","id":1,"result":{` +
		`"name":"Vendor Agent","description":"does things","version":"1.0.0",` +
		`"skills":[{"id":"s1","name":"search","description":"ok"}],` +
		`"supportedInterfaces":[{"url":"https://agent.example.com/a2a","protocolBinding":"jsonrpc"}]` +
		`}}`
}

func requireSignedBlockCfg(t *testing.T) *config.A2AScanning {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return sigScanCfg(pub, true)
}

func forwardA2AResponse(t *testing.T, line string, opts MCPProxyOpts) (out, logs string, found bool) {
	t.Helper()
	if opts.Scanner == nil {
		opts.Scanner = testScannerWithAction(t, config.ActionBlock)
	}
	var outBuf, logBuf bytes.Buffer
	found, err := ForwardScanned(
		transport.NewStdioReader(strings.NewReader(line+"\n")),
		transport.NewStdioWriter(&outBuf),
		&logBuf,
		nil,
		opts,
	)
	if err != nil {
		t.Fatalf("ForwardScanned: %v", err)
	}
	return outBuf.String(), logBuf.String(), found
}

func assertMCPResponseBlocked(t *testing.T, out, logs string, found bool) {
	t.Helper()
	if !found {
		t.Fatal("expected a security finding, got none")
	}
	if strings.Contains(out, `"result"`) && !strings.Contains(out, `"error"`) {
		t.Fatalf("blocked response still forwarded the upstream result: %s", out)
	}
	if !strings.Contains(out, "pipelock") {
		t.Fatalf("blocked response missing pipelock error envelope: %s", out)
	}
	if !strings.Contains(out, `"error"`) {
		t.Fatalf("blocked response missing JSON-RPC error: %s", out)
	}
	_ = logs
}

func assertMCPResponseAllowed(t *testing.T, out string, found bool, wantSnippet string) {
	t.Helper()
	if found {
		t.Fatalf("ordinary/disabled path reported a finding; output=%s", out)
	}
	if !strings.Contains(out, wantSnippet) {
		t.Fatalf("expected forwarded payload containing %q, got %s", wantSnippet, out)
	}
	if strings.Contains(out, `"error"`) && strings.Contains(out, "pipelock") {
		t.Fatalf("payload was blocked: %s", out)
	}
}

// TestForwardScanned_A2AUnsignedAgentCardBlocks is the reproduction for the
// MCP transport-parity hole: operator-enabled block-mode Agent Card signature
// enforcement must deny an unsigned card on the shared ForwardScanned path.
// Before the wiring, generic ScanResponse allows this payload.
func TestForwardScanned_A2AUnsignedAgentCardBlocks(t *testing.T) {
	out, logs, found := forwardA2AResponse(t, unsignedAgentCardRPC(), MCPProxyOpts{
		A2ACfg: requireSignedBlockCfg(t),
	})
	assertMCPResponseBlocked(t, out, logs, found)
}

func TestForwardScanned_A2ADisabledAllowsUnsignedAgentCard(t *testing.T) {
	cfg := requireSignedBlockCfg(t)
	cfg.Enabled = false
	out, _, found := forwardA2AResponse(t, unsignedAgentCardRPC(), MCPProxyOpts{
		A2ACfg: cfg,
	})
	assertMCPResponseAllowed(t, out, found, `"Vendor Agent"`)
}

func TestForwardScanned_A2AEnabledLeavesOrdinaryMCPClean(t *testing.T) {
	line := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello from tools/call"}]}}`
	out, _, found := forwardA2AResponse(t, line, MCPProxyOpts{
		A2ACfg: requireSignedBlockCfg(t),
	})
	assertMCPResponseAllowed(t, out, found, `hello from tools/call`)
}

func TestHTTPListener_A2AUnsignedAgentCardBlocks(t *testing.T) {
	card := unsignedAgentCardRPC()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, card)
	}))
	t.Cleanup(upstream.Close)

	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner: testScannerForHTTP(t),
		A2ACfg:  requireSignedBlockCfg(t),
	})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"GetExtendedAgentCard","params":{}}`,
	))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if bytes.Contains(body, []byte(`"Vendor Agent"`)) && !bytes.Contains(body, []byte(`"error"`)) {
		t.Fatalf("HTTP listener forwarded unsigned Agent Card: %s", body)
	}
	var rpc struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &rpc) != nil || len(rpc.Error) == 0 || string(rpc.Error) == "null" {
		t.Fatalf("expected JSON-RPC error for unsigned Agent Card, got: %s", body)
	}
}
