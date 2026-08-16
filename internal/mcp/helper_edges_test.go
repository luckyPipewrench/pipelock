// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestContentScanAttributionRoutes(t *testing.T) {
	t.Parallel()

	layer, pattern, severity := contentScanAttribution(InputVerdict{
		Matches: []scanner.TextDLPMatch{{PatternName: "AWS Access ID"}},
	})
	if layer != mcpReceiptLayerInput || pattern != "AWS Access ID" || severity != config.SeverityHigh {
		t.Fatalf("empty-severity DLP = %q %q %q", layer, pattern, severity)
	}

	layer, pattern, severity = contentScanAttribution(InputVerdict{
		Inject: []scanner.ResponseMatch{{PatternName: "Prompt Injection"}},
	})
	if layer != mcpReceiptLayerInput || pattern != "Prompt Injection" || severity != config.SeverityHigh {
		t.Fatalf("inject = %q %q %q", layer, pattern, severity)
	}

	layer, pattern, severity = contentScanAttribution(InputVerdict{
		URLFindings: []scanner.Result{{Scanner: scanner.ScannerSSRF}},
	})
	if layer != mcpReceiptLayerInput || pattern != "url:"+scanner.ScannerSSRF || severity != config.SeverityHigh {
		t.Fatalf("url = %q %q %q", layer, pattern, severity)
	}

	layer, pattern, severity = contentScanAttribution(InputVerdict{
		AddressFindings: []addressprotect.Finding{{Explanation: "wallet"}},
	})
	if layer != mcpReceiptLayerInput || pattern != "address:wallet" || severity != config.SeverityHigh {
		t.Fatalf("address = %q %q %q", layer, pattern, severity)
	}

	layer, pattern, severity = contentScanAttribution(InputVerdict{Error: "invalid JSON"})
	if layer != mcpReceiptLayerInput || pattern != "invalid JSON" || severity != config.SeverityHigh {
		t.Fatalf("error = %q %q %q", layer, pattern, severity)
	}

	layer, pattern, severity = contentScanAttribution(InputVerdict{})
	if layer != "" || pattern != "" || severity != "" {
		t.Fatalf("empty = %q %q %q, want blank", layer, pattern, severity)
	}
}

func TestDecorateMCPToolMessageSkipsEmptyActionID(t *testing.T) {
	t.Parallel()

	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://api.vendor.example"}}}`)
	em := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: "test-hash"})
	got, err := decorateMCPToolMessage(msg, em, "", methodToolsCall, "fetch", config.ActionAllow, taintDecision{})
	if err != nil {
		t.Fatalf("decorateMCPToolMessage: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("empty action id still mutated the message: %s", got)
	}
	if bytes.Contains(got, []byte(envelope.MCPMetaKey)) {
		t.Fatal("empty action id still injected a mediation envelope")
	}
}

func TestResolvedDoWTrustAndAttributionDefaults(t *testing.T) {
	t.Parallel()

	if got := resolvedDoWTrust(config.DoWTrustAgent.String()); got != config.DoWTrustAgent.String() {
		t.Fatalf("known trust = %q", got)
	}
	if got := resolvedDoWTrust("not-a-trust"); got != dowSubjectTrustDefault {
		t.Fatalf("unknown trust = %q, want %q", got, dowSubjectTrustDefault)
	}

	agent, attr := resolvedDoWAttribution(MCPProxyOpts{})
	if agent != metrics.DoWAgentDefault {
		t.Fatalf("empty agent = %q, want %q", agent, metrics.DoWAgentDefault)
	}
	if attr.SubjectKey != dowSubjectKeyDefault {
		t.Fatalf("empty subject = %q, want %q", attr.SubjectKey, dowSubjectKeyDefault)
	}
	if attr.Trust != dowSubjectTrustDefault {
		t.Fatalf("empty trust = %q, want %q", attr.Trust, dowSubjectTrustDefault)
	}
}

func TestMCPDoWAuditContextUsesFallbackTarget(t *testing.T) {
	t.Parallel()

	ctx := mcpDoWAuditContext(nil, "unused", MCPProxyOpts{}, func(method, resource, agent string) (audit.LogContext, error) {
		return audit.LogContext{}, errors.New("context rejected")
	})
	if ctx.Resource() != dowAuditFallbackTarget {
		t.Fatalf("fallback resource = %q, want %q", ctx.Resource(), dowAuditFallbackTarget)
	}
}

func TestNewContractLoaderFromConfigDisabled(t *testing.T) {
	t.Parallel()

	loader, err := NewContractLoaderFromConfig(nil)
	if loader != nil || err != nil {
		t.Fatalf("nil cfg = (%v, %v), want nil loader", loader, err)
	}

	cfg := config.Defaults()
	cfg.LearnLock.Enabled = false
	loader, err = NewContractLoaderFromConfig(cfg)
	if loader != nil || err != nil {
		t.Fatalf("disabled learn-lock = (%v, %v), want nil loader", loader, err)
	}
}

func TestMCPWithContractReceiptSkipsEmptyGate(t *testing.T) {
	t.Parallel()

	opts := receipt.EmitOpts{Target: "fetch_url", ContractHash: "keep-hash"}
	got := mcpWithContractReceipt(opts, mcpContractGateOutput{})
	if got.ContractHash != "keep-hash" {
		t.Fatalf("empty gate overwrote hash = %q", got.ContractHash)
	}

	got = mcpWithContractReceipt(opts, mcpContractGateOutput{
		WinningSource: "contract",
		LiveVerdict:   config.ActionBlock,
		ContractHash:  "new-hash",
		SelectorID:    "sel-1",
	})
	if got.ContractHash != "new-hash" || got.ContractSelectorID != "sel-1" {
		t.Fatalf("filled gate = %+v", got)
	}
}

func TestMCPContractBlockRequestUsesFallbackMessage(t *testing.T) {
	t.Parallel()

	br := mcpContractBlockRequest(json.RawMessage(`1`), mcpContractGateOutput{}, "custom contract deny")
	if br.ErrorMessage != "custom contract deny" || br.LogMessage != "custom contract deny" {
		t.Fatalf("fallback message not used: %+v", br)
	}
	if br.ErrorCode != -32006 {
		t.Fatalf("error code = %d, want -32006", br.ErrorCode)
	}
}

func TestJSONRPCErrorCodeForInputError(t *testing.T) {
	t.Parallel()

	if got := jsonRPCErrorCodeForInputError("invalid JSON: unexpected EOF"); got != -32700 {
		t.Fatalf("invalid JSON code = %d, want -32700", got)
	}
	if got := jsonRPCErrorCodeForInputError("invalid JSON batch"); got != -32700 {
		t.Fatalf("invalid JSON batch code = %d, want -32700", got)
	}
	if got := jsonRPCErrorCodeForInputError("duplicate key"); got != -32600 {
		t.Fatalf("other parse code = %d, want -32600", got)
	}
}

func TestJoinInputVerdictReasonsFallback(t *testing.T) {
	t.Parallel()

	if got := joinInputVerdictReasons(InputVerdict{}); got != "input scanning" {
		t.Fatalf("empty reasons = %q, want input scanning", got)
	}
	got := joinInputVerdictReasons(InputVerdict{
		Matches: []scanner.TextDLPMatch{{PatternName: "AWS Access ID"}},
		Error:   "invalid JSON",
	})
	if got != "AWS Access ID\ninvalid JSON" {
		t.Fatalf("joined reasons = %q", got)
	}
}

func TestExtractToolCallFieldsNonCallableAndNullA2A(t *testing.T) {
	t.Parallel()

	name, args := extractToolCallFields([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if name != "" || args != "" {
		t.Fatalf("non-callable = %q %q, want empty", name, args)
	}

	name, args = extractToolCallFields([]byte(`{"jsonrpc":"2.0","id":1,"method":"sendmessage","params":null}`))
	if name != "SendMessage" || args != "{}" {
		t.Fatalf("null A2A params = %q %q, want SendMessage {}", name, args)
	}
}
