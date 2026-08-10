// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
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
	if agent != metrics.DoWAgentDefault {
		t.Fatalf("resolved agent = %q, want %q", agent, metrics.DoWAgentDefault)
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

func TestMCPDoWAuditContextFallbackPreservesAttribution(t *testing.T) {
	for _, action := range []string{config.ActionBlock, config.ActionWarn} {
		for _, tc := range []struct {
			name       string
			resource   string
			newContext func(string, string, string) (audit.LogContext, error)
		}{
			{name: "empty", newContext: audit.NewMCPLogContext},
			{
				name:     "validation_rejected",
				resource: "rejected-raw-resource",
				newContext: func(_, _, _ string) (audit.LogContext, error) {
					return audit.LogContext{}, errors.New("test validation rejection")
				},
			},
		} {
			t.Run(action+"_"+tc.name, func(t *testing.T) {
				var stream bytes.Buffer
				logger, err := audit.NewWithStream("json", "stdout", "", false, true, &stream)
				if err != nil {
					t.Fatal(err)
				}
				opts := MCPProxyOpts{
					DoWSubjectAgent:     "configured-agent",
					DoWSubjectAgentAuth: envelope.ActorAuthConfigDefault,
					DoWAttribution: DoWAttribution{
						SubjectKey: "raw-principal|198.51.100.7",
						Trust:      config.DoWTrustPrincipal.String(),
					},
				}
				ctx := mcpDoWAuditContext(logger, tc.resource, opts, tc.newContext)
				if ctx.Resource() != dowAuditFallbackTarget {
					t.Fatalf("fallback resource = %q, want %q", ctx.Resource(), dowAuditFallbackTarget)
				}
				if action == config.ActionBlock {
					logger.LogBlocked(ctx, "denial_of_wallet", "limit exceeded")
				} else {
					logger.LogAnomaly(ctx, "denial_of_wallet", "limit exceeded", 0)
				}

				var event map[string]any
				for _, line := range strings.Split(strings.TrimSpace(stream.String()), "\n") {
					var candidate map[string]any
					if json.Unmarshal([]byte(line), &candidate) == nil && candidate["scanner"] == "denial_of_wallet" {
						event = candidate
					}
				}
				if event == nil {
					t.Fatalf("missing denial-of-wallet event: %s", stream.String())
				}
				if event["agent"] != "configured-agent" || event["subject_trust"] != "principal" {
					t.Fatalf("fallback attribution = agent:%v trust:%v", event["agent"], event["subject_trust"])
				}
				discriminator, _ := event["subject_discriminator"].(string)
				if !strings.HasPrefix(discriminator, "hmac-sha256:") {
					t.Fatalf("fallback discriminator = %q", discriminator)
				}
				output := stream.String()
				for _, raw := range []string{tc.resource, "raw-principal", "198.51.100.7"} {
					if raw != "" && strings.Contains(output, raw) {
						t.Fatalf("fallback audit exposed raw value %q: %s", raw, output)
					}
				}
			})
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
