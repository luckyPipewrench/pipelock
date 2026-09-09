// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCredentialAudienceHosts_BodyAndHeaderCarriers(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	for _, tc := range credentialAudienceCarrierCases() {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"credential":"` + tc.credential + `"}`
			var bodyAllows []scanner.CredentialAudienceAllow
			_, bodyResult := scanRequestBody(context.Background(), BodyScanRequest{
				Body:                      strings.NewReader(body),
				ContentType:               "application/json",
				MaxBytes:                  cfg.RequestBodyScanning.MaxBodyBytes,
				Scanner:                   sc,
				Target:                    tc.target,
				AudienceSurface:           "body",
				OnCredentialAudienceAllow: func(allow scanner.CredentialAudienceAllow) { bodyAllows = append(bodyAllows, allow) },
			})
			if !bodyResult.Clean || len(bodyAllows) != 1 || bodyAllows[0].PatternName != tc.pattern {
				t.Fatalf("body audience result=%+v allows=%+v", bodyResult, bodyAllows)
			}

			headers := http.Header{"Authorization": []string{"Bearer " + tc.credential}}
			var headerAllows []scanner.CredentialAudienceAllow
			headerResult := scanRequestHeadersForTargetWithAudience(context.Background(), headers, cfg, sc, tc.target, nil, func(allow scanner.CredentialAudienceAllow) { headerAllows = append(headerAllows, allow) })
			if headerResult != nil && !headerResult.Clean {
				t.Fatalf("header audience result=%+v", headerResult)
			}
			if len(headerAllows) != 1 || headerAllows[0].PatternName != tc.pattern {
				t.Fatalf("header audience allows=%+v", headerAllows)
			}

			_, blockedBody := scanRequestBody(context.Background(), BodyScanRequest{
				Body: strings.NewReader(body), ContentType: "application/json", MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes,
				Scanner: sc, Target: "https://api.vendor.example/v1",
			})
			if blockedBody.Clean {
				t.Fatal("non-audience body allowed")
			}
			blockedHeader := scanRequestHeadersForTarget(context.Background(), headers, cfg, sc, "https://api.vendor.example/v1")
			if blockedHeader == nil || blockedHeader.Clean {
				t.Fatal("non-audience header allowed")
			}
		})
	}
}

func TestCredentialAudienceHosts_WebSocketFrameAndFragmentedDirectText(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	for _, tc := range credentialAudienceCarrierCases() {
		t.Run(tc.name, func(t *testing.T) {
			audienceTarget := strings.Replace(tc.target, "https://", "wss://", 1)

			bodyRelay := newCredentialAudienceWebSocketRelay(sc, cfg, audienceTarget)
			_, bodyResult := bodyRelay.scanClientMessageBody(context.Background(), []byte(`{"credential":"`+tc.credential+`"}`))
			if !bodyResult.Clean {
				t.Fatalf("WebSocket body path blocked audience credential: %+v", bodyResult)
			}
			assertCredentialAudienceWebSocketMetric(t, bodyRelay.proxy.metrics, tc.pattern)

			directRelay := newCredentialAudienceWebSocketRelay(sc, cfg, audienceTarget)
			if directRelay.scanClientText(context.Background(), audit.NewNop(), []byte(tc.credential)) {
				t.Fatal("WebSocket direct text path blocked audience credential")
			}
			assertCredentialAudienceWebSocketMetric(t, directRelay.proxy.metrics, tc.pattern)

			fragmentRelay := newCredentialAudienceWebSocketRelay(sc, cfg, audienceTarget)
			// The complete match arrives across two frame-like pieces. This exercises
			// the direct fragmented-text path, which has no independent authority.
			if fragmentRelay.scanClientCrossMessageText(context.Background(), audit.NewNop(), []byte(tc.credential[:10]), []byte(tc.credential[10:])) {
				t.Fatal("WebSocket fragmented direct text path blocked audience credential")
			}
			assertCredentialAudienceWebSocketMetric(t, fragmentRelay.proxy.metrics, tc.pattern)

			blockedRelay := newCredentialAudienceWebSocketRelay(sc, cfg, "wss://api.vendor.example/v1")
			_, blockedBody := blockedRelay.scanClientMessageBody(context.Background(), []byte(`{"credential":"`+tc.credential+`"}`))
			if blockedBody.Clean {
				t.Fatal("WebSocket body path allowed non-audience credential")
			}
			if !blockedRelay.scanClientText(context.Background(), audit.NewNop(), []byte(tc.credential)) {
				t.Fatal("WebSocket direct text path allowed non-audience credential")
			}
			if !blockedRelay.scanClientCrossMessageText(context.Background(), audit.NewNop(), []byte(tc.credential[:10]), []byte(tc.credential[10:])) {
				t.Fatal("WebSocket fragmented direct text path allowed non-audience credential")
			}
		})
	}
}

func newCredentialAudienceWebSocketRelay(sc *scanner.Scanner, cfg *config.Config, target string) *wsRelay {
	return &wsRelay{
		scanner:      sc,
		proxy:        &Proxy{logger: audit.NewNop(), metrics: metrics.New()},
		cfg:          cfg,
		targetURL:    target,
		hostname:     strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(target, "wss://"), "ws://"), "/v1"),
		path:         "/v1",
		maxMsg:       1 << 20,
		clientConn:   discardConn{},
		upstreamConn: discardConn{},
	}
}

func assertCredentialAudienceWebSocketMetric(t *testing.T, m *metrics.Metrics, pattern string) {
	t.Helper()
	rec := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	want := `pipelock_dlp_credential_audience_allows_total{pattern="` + pattern + `",surface="websocket_frame"} 1`
	if !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("credential audience WebSocket metric missing or not exactly one: want %q in %s", want, rec.Body.String())
	}
}

func TestCredentialAudienceHosts_CorePatternStillBlocksAtAudience(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	core := "AKIA" + "IOSFODNN7EXAMPLE"
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body: strings.NewReader(`{"credential":"` + core + `"}`), ContentType: "application/json", MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner: sc, Target: "https://api.openai.com/v1",
	})
	if result.Clean {
		t.Fatal("core credential was allowed at an audience host")
	}
}

func TestCredentialAudienceHosts_RuntimeBodyKnobsCannotBypassMismatch(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.RequestBodyScanning.DisablePatterns = []string{"OpenAI API Key"}
	cfg.RequestBodyScanning.PatternActions = map[string]string{"OpenAI API Key": config.ActionWarn}
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	key := "sk-" + "proj-" + strings.Repeat("a", 24)
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:            strings.NewReader(`{"credential":"` + key + `"}`),
		ContentType:     "application/json",
		MaxBytes:        cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:         sc,
		Target:          "https://api.vendor.example/v1",
		Action:          config.ActionBlock,
		DisablePatterns: cfg.RequestBodyScanning.DisablePatterns,
		PatternActions:  cfg.RequestBodyScanning.PatternActions,
	})
	if result.Clean || result.Action != config.ActionBlock {
		t.Fatalf("runtime body knobs weakened audience mismatch: %+v", result)
	}
}

func TestCredentialAudienceReceiptExtensionFallbackKeepsSignedReceipt(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	rph := newReceiptProxyHelper(t)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithReceiptEmitter(rph.emitter))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	p.emitCredentialAudienceReceipt(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionAllow,
		Layer:     credentialAudienceReceiptExtensionKey,
		Pattern:   "OpenAI API Key",
		Transport: TransportFetch,
		Method:    http.MethodPost,
		Target:    "https://api.openai.com/v1/responses",
		RequestID: "credential-audience-extension-fallback",
		Extension: json.RawMessage("null"),
	})

	got := rph.requireReceipt(t, credentialAudienceReceiptExtensionKey)
	if len(got.Ext) != 0 {
		t.Fatalf("fallback receipt kept malformed extension: %s", got.Ext)
	}
	if got.ActionRecord.Pattern != "OpenAI API Key" || got.ActionRecord.Verdict != config.ActionAllow {
		t.Fatalf("fallback receipt lost signed audience record: %+v", got.ActionRecord)
	}
}

type credentialAudienceCarrierCase struct {
	name       string
	pattern    string
	credential string
	target     string
}

func credentialAudienceCarrierCases() []credentialAudienceCarrierCase {
	return []credentialAudienceCarrierCase{
		{name: "OpenAI", pattern: "OpenAI API Key", credential: "sk-" + "proj-" + strings.Repeat("a", 24), target: "https://api.openai.com/v1/responses"},
		{name: "Anthropic", pattern: "Anthropic API Key", credential: "sk-" + "ant-" + strings.Repeat("a", 24), target: "https://api.anthropic.com/v1/messages"},
		{name: "Discord", pattern: "Discord Bot Token", credential: "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27), target: "https://discord.com/api/v10"},
	}
}

// An allow at the declared audience must reach the receipt channel with its
// advisory extension intact. The signed record stays a plain allow; the
// extension carries the audience detail without becoming a signed
// authorization claim.
func TestRecordCredentialAudienceAllow_EmitsReceiptWithExtension(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	rph := newReceiptProxyHelper(t)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithReceiptEmitter(rph.emitter))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	allow := scanner.CredentialAudienceAllow{
		PatternName: "OpenAI API Key",
		Surface:     "header",
		Destination: "api.openai.com",
	}
	p.recordCredentialAudienceAllow(audit.LogContext{}, allow, TransportFetch, http.MethodPost,
		"https://api.openai.com/v1/responses", "credential-audience-allow", "agent-1")

	got := rph.requireReceipt(t, credentialAudienceReceiptExtensionKey)
	if got.ActionRecord.Verdict != config.ActionAllow {
		t.Fatalf("verdict = %q, want allow", got.ActionRecord.Verdict)
	}
	if got.ActionRecord.Pattern != "OpenAI API Key" {
		t.Fatalf("pattern = %q", got.ActionRecord.Pattern)
	}
	if len(got.Ext) == 0 {
		t.Fatal("advisory audience extension was dropped on the happy path")
	}
	if !strings.Contains(string(got.Ext), "api.openai.com") {
		t.Fatalf("extension does not name the destination: %s", got.Ext)
	}
}

// Repeated allows for the same pattern, surface and destination collapse to one
// record. Without this a single request carrying the credential in several
// places would emit a receipt per occurrence.
func TestRecordCredentialAudienceAllows_DeduplicatesBeforeEmitting(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	rph := newReceiptProxyHelper(t)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithReceiptEmitter(rph.emitter))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	allow := scanner.CredentialAudienceAllow{
		PatternName: "OpenAI API Key",
		Surface:     "header",
		Destination: "api.openai.com",
	}
	other := scanner.CredentialAudienceAllow{
		PatternName: "Anthropic API Key",
		Surface:     "body",
		Destination: "api.anthropic.com",
	}
	p.recordCredentialAudienceAllows(audit.LogContext{},
		[]scanner.CredentialAudienceAllow{allow, allow, other, allow},
		TransportFetch, http.MethodPost, "https://api.openai.com/v1/responses", "dedup", "agent-1")

	var audience int
	for _, r := range rph.findReceipts(t) {
		if r.ActionRecord.Layer == credentialAudienceReceiptExtensionKey {
			audience++
		}
	}
	if audience != 2 {
		t.Fatalf("emitted %d audience receipts, want 2 (one per distinct allow)", audience)
	}
}

// A proxy with no receipt emitter configured must record the allow and return,
// not panic. Receipts are optional; the audit and metric paths are not.
func TestRecordCredentialAudienceAllow_NoReceiptEmitterIsSafe(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	p.recordCredentialAudienceAllow(audit.LogContext{}, scanner.CredentialAudienceAllow{
		PatternName: "OpenAI API Key",
		Surface:     "header",
		Destination: "api.openai.com",
	}, TransportFetch, http.MethodPost, "https://api.openai.com/v1/responses", "no-emitter", "agent-1")
}

// A nil receiver is reachable through the reverse-proxy handler path and must
// not panic.
func TestRecordCredentialAudienceAllow_NilReceiversAreInert(t *testing.T) {
	var p *Proxy
	p.recordCredentialAudienceAllow(audit.LogContext{}, scanner.CredentialAudienceAllow{}, TransportFetch, http.MethodGet, "", "", "")
	p.emitCredentialAudienceReceipt(receipt.EmitOpts{})
	var rp *ReverseProxyHandler
	rp.recordCredentialAudienceAllow(audit.LogContext{}, scanner.CredentialAudienceAllow{}, http.MethodGet, "", "", "")
}

// The reverse proxy is a separate carrier of the same audience allow and has
// its own receipt path, so it needs its own coverage: a defect here would be
// invisible to every forward-proxy test.
func TestReverseProxy_RecordCredentialAudienceAllow_EmitsReceipt(t *testing.T) {
	rph := newReceiptProxyHelper(t)
	var emitterPtr atomic.Pointer[receipt.Emitter]
	emitterPtr.Store(rph.emitter)

	rp := &ReverseProxyHandler{
		logger:            audit.NewNop(),
		metrics:           metrics.New(),
		receiptEmitterPtr: &emitterPtr,
	}

	allow := scanner.CredentialAudienceAllow{
		PatternName: "Anthropic API Key",
		Surface:     "header",
		Destination: "api.anthropic.com",
	}
	rp.recordCredentialAudienceAllow(audit.LogContext{}, allow, http.MethodPost,
		"https://api.anthropic.com/v1/messages", "reverse-audience-allow", "agent-1")

	got := rph.requireReceipt(t, credentialAudienceReceiptExtensionKey)
	if got.ActionRecord.Verdict != config.ActionAllow {
		t.Fatalf("verdict = %q, want allow", got.ActionRecord.Verdict)
	}
	if got.ActionRecord.Transport != "reverse" {
		t.Fatalf("transport = %q, want reverse", got.ActionRecord.Transport)
	}
	if !strings.Contains(string(got.Ext), "api.anthropic.com") {
		t.Fatalf("extension does not name the destination: %s", got.Ext)
	}
}

// The reverse handler's dedup wrapper shares the audience path but not the
// forward proxy's, so it is exercised separately.
func TestReverseProxy_RecordCredentialAudienceAllows_Deduplicates(t *testing.T) {
	rph := newReceiptProxyHelper(t)
	var emitterPtr atomic.Pointer[receipt.Emitter]
	emitterPtr.Store(rph.emitter)
	rp := &ReverseProxyHandler{
		logger:            audit.NewNop(),
		metrics:           metrics.New(),
		receiptEmitterPtr: &emitterPtr,
	}

	allow := scanner.CredentialAudienceAllow{
		PatternName: "Anthropic API Key",
		Surface:     "header",
		Destination: "api.anthropic.com",
	}
	rp.recordCredentialAudienceAllows(audit.LogContext{},
		[]scanner.CredentialAudienceAllow{allow, allow, allow},
		http.MethodPost, "https://api.anthropic.com/v1/messages", "reverse-dedup", "agent-1")

	var audience int
	for _, r := range rph.findReceipts(t) {
		if r.ActionRecord.Layer == credentialAudienceReceiptExtensionKey {
			audience++
		}
	}
	if audience != 1 {
		t.Fatalf("emitted %d audience receipts, want 1", audience)
	}
}
