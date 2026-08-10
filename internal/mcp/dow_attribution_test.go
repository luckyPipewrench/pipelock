// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

func TestDoWObservabilityDoesNotChangeTransportVerdicts(t *testing.T) {
	for _, action := range []string{config.ActionBlock, config.ActionWarn} {
		t.Run("stdio_"+action, func(t *testing.T) {
			without := runStdioDoWVerdict(t, action, false)
			with := runStdioDoWVerdict(t, action, true)
			if without != with {
				t.Fatalf("stdio verdict changed with observability: without=%+v with=%+v", without, with)
			}
			if action == config.ActionBlock && (!with.blocked || with.forwarded) {
				t.Fatalf("block verdict = %+v, want blocked and not forwarded", with)
			}
			if action == config.ActionWarn && (with.blocked || !with.forwarded) {
				t.Fatalf("warn verdict = %+v, want forwarded and not blocked", with)
			}
		})

		t.Run("http_"+action, func(t *testing.T) {
			without := runHTTPDoWVerdict(t, action, false)
			with := runHTTPDoWVerdict(t, action, true)
			if without != with {
				t.Fatalf("HTTP verdict changed with observability: without=%+v with=%+v", without, with)
			}
			if action == config.ActionBlock && !with.blocked {
				t.Fatal("HTTP block action was not blocked")
			}
			if action == config.ActionWarn && with.blocked {
				t.Fatal("HTTP warn action was blocked")
			}
		})
	}
}

func TestResolvedDoWAttributionDoesNotTrustSelfDeclaredAgent(t *testing.T) {
	agent, attribution := resolvedDoWAttribution(MCPProxyOpts{
		DoWSubjectAgent:     "self-declared-agent",
		DoWSubjectAgentAuth: envelope.ActorAuthSelfDeclared,
	})
	if agent != metricAgentDefault {
		t.Fatalf("resolved agent = %q, want %q", agent, metricAgentDefault)
	}
	if attribution.SubjectKey != dowSubjectKeyDefault || attribution.Trust != dowSubjectTrustDefault {
		t.Fatalf("default attribution = %+v, want subject=%q trust=%q", attribution, dowSubjectKeyDefault, dowSubjectTrustDefault)
	}
}

func TestResolvedDoWAttributionPreservesOnlyKnownTrustGrades(t *testing.T) {
	for _, trust := range []config.DoWSubjectTrust{
		config.DoWTrustNetwork,
		config.DoWTrustAgent,
		config.DoWTrustPrincipal,
	} {
		_, attribution := resolvedDoWAttribution(MCPProxyOpts{DoWAttribution: DoWAttribution{
			SubjectKey: "subject",
			Trust:      trust.String(),
		}})
		if attribution.Trust != trust.String() {
			t.Errorf("trust %q resolved as %q", trust, attribution.Trust)
		}
	}

	_, attribution := resolvedDoWAttribution(MCPProxyOpts{DoWAttribution: DoWAttribution{
		SubjectKey: "subject",
		Trust:      "unrecognized-strong-grade",
	}})
	if attribution.Trust != dowSubjectTrustDefault {
		t.Fatalf("unrecognized trust resolved as %q, want weakest grade %q", attribution.Trust, dowSubjectTrustDefault)
	}
}

func TestMustMCPDoWAuditContextHandlesMissingResource(t *testing.T) {
	for _, logger := range []*audit.Logger{nil, audit.NewNop()} {
		ctx := mustMCPDoWAuditContext(logger, "", MCPProxyOpts{})
		if ctx.Method() != "MCP" {
			t.Fatalf("fallback method = %q, want MCP", ctx.Method())
		}
	}
}

type dowTransportVerdict struct {
	blocked   bool
	forwarded bool
}

func runStdioDoWVerdict(t *testing.T, action string, observability bool) dowTransportVerdict {
	t.Helper()
	sc := testInputScanner(t)
	opts := testOpts(sc)
	opts.DoWCheck = func(_, _, _ string) (bool, string, string, string) {
		return false, action, testDoWBudgetReason, testDoWBudgetType
	}
	if observability {
		opts.AuditLogger = audit.NewNop()
		opts.Metrics = metrics.New()
		opts.DoWSubjectAgent = "configured-agent"
		opts.DoWSubjectAgentAuth = envelope.ActorAuthConfigDefault
	}

	request := makeRequest(701, "tools/call", map[string]any{
		"name":      testDoWToolName,
		"arguments": map[string]string{"q": "hello"},
	}) + "\n"
	var serverIn bytes.Buffer
	blockedCh := make(chan BlockedRequest, 1)
	ForwardScannedInput(
		transport.NewStdioReader(strings.NewReader(request)),
		transport.NewStdioWriter(&serverIn),
		io.Discard, config.ActionWarn, config.ActionBlock, blockedCh, nil, nil, opts,
	)
	blocked := false
	for range blockedCh {
		blocked = true
	}
	return dowTransportVerdict{blocked: blocked, forwarded: serverIn.Len() > 0}
}

func runHTTPDoWVerdict(t *testing.T, action string, observability bool) dowTransportVerdict {
	t.Helper()
	opts := MCPProxyOpts{
		Scanner: testScannerForHTTP(t),
		DoWCheck: func(_, _, _ string) (bool, string, string, string) {
			return false, action, testDoWBudgetReason, testDoWBudgetType
		},
	}
	if observability {
		opts.AuditLogger = audit.NewNop()
		opts.Metrics = metrics.New()
		opts.DoWSubjectAgent = "configured-agent"
		opts.DoWSubjectAgentAuth = envelope.ActorAuthBound
		opts.DoWAttribution = DoWAttribution{
			SubjectKey: "configured-agent|198.51.100.7",
			Trust:      config.DoWTrustAgent.String(),
		}
	}

	msg := []byte(`{"jsonrpc":"2.0","id":701,"method":"tools/call","params":{"name":"` + testDoWToolName + `","arguments":{"q":"hello"}}}`)
	blocked := scanHTTPInput(msg, io.Discard, "", "", opts) != nil
	return dowTransportVerdict{blocked: blocked, forwarded: !blocked}
}
