// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestJSONInspectionBodyAndWebSocketWarn(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	cfg.ResponseScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.Action = config.ActionWarn
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	card := cardtest.Number()
	for _, tt := range []struct {
		name, body string
		refuse     bool
	}{
		{"exponent", `[1e10001]`, true},
		{"digits", `[` + strings.Repeat("9", 4097) + `]`, true},
		{"depth", strings.Repeat("[", 65) + `1` + strings.Repeat("]", 65), true},
		{"clean", `[1,2]`, false},
		{"informational", `[` + card[:8] + `,` + card[8:] + `]`, false},
		{"ordinary-card", `["` + card + `"]`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, v := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(tt.body), ContentType: "application/json", MaxBytes: 1 << 20, Scanner: sc, Action: config.ActionWarn})
			if tt.refuse {
				if v.Clean || v.Action != config.ActionBlock {
					t.Fatalf("body incomplete allowed: action=%s reason=%s", v.Action, v.Reason)
				}
			} else if string(out) != tt.body || v.Action == config.ActionBlock {
				t.Fatal("body control refused")
			}
			r, _ := newWebSocketFrameSuppressionRelay(t, cfg, "wss://api.vendor.example/socket")
			if tt.name != "ordinary-card" && r.scanClientText(t.Context(), audit.NewNop(), []byte(tt.body)) != tt.refuse {
				t.Fatal("outbound WebSocket inspection decision differs")
			}
			// Server-to-client text and HTTP response bodies are injection-only;
			// the typed card budget does not refuse them.
			received, blocked := r.enforceUpstreamTextPayload(t.Context(), audit.NewNop(), []byte(tt.body), false)
			if blocked || string(received) != tt.body {
				t.Fatalf("inbound WebSocket decision: blocked=%v", blocked)
			}
			response := sc.ScanResponseBodyWithSuppress(t.Context(), []byte(tt.body), "https://api.vendor.example", nil)
			if response.Failed() {
				t.Fatalf("HTTP response refused: error=%s", response.ScanError)
			}
		})
	}
}

func TestJSONInspectionHTTPResponseInjectionOnly(t *testing.T) {
	for _, exempt := range []bool{false, true} {
		t.Run(map[bool]string{false: "inspected", true: "exempt"}[exempt], func(t *testing.T) {
			body := `[1e10001]`
			backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
			}))
			t.Cleanup(backend.Close)
			addr, _, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
				cfg.ResponseScanning.Action = config.ActionWarn
				if exempt {
					cfg.ResponseScanning.ExemptDomains = []string{mustURLHostname(t, backend.URL)}
				}
			})
			t.Cleanup(cleanup)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, backend.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := proxyClient(addr).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK || string(data) != body {
				t.Fatalf("injection-only response changed: status=%d", resp.StatusCode)
			}
		})
	}
	// Fetch responses are injection-only as well.
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[1e10001]`)
	}))
	t.Cleanup(upstream.Close)
	cfg := testScannerConfig()
	cfg.ResponseScanning.Action = config.ActionWarn
	p := newTestProxyWithConfig(t, cfg)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil)
	response := httptest.NewRecorder()
	p.handleFetch(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("fetch status=%d", response.Code)
	}
}

func TestJSONInspectionBodyPolicy(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	limit := sc.ScanJSONCardRuns(t.Context(), `[1e10001]`)
	if !scanner.HasInspectionLimit(limit) {
		t.Fatal("inspection limit missing")
	}
	for _, enforce := range []bool{true, false} {
		cfg.Enforce = &enforce
		if !shouldHardBlockCriticalDLP(limit, enforce) || !shouldHardBlockRequestDLP(limit, cfg) || !isFailClosedBodyResult(BodyScanResult{DLPMatches: limit}, []byte("original")) {
			t.Fatal("inspection limit lost hard refusal")
		}
		if requestBodyDLPAction(limit, config.ActionWarn, map[string]string{scanner.UninspectableJSONNumberPattern: config.ActionWarn}) != config.ActionBlock {
			t.Fatal("pattern override weakened refusal")
		}
		r, _ := newWebSocketFrameSuppressionRelay(t, cfg, "wss://api.vendor.example/socket")
		if !r.scanClientText(t.Context(), audit.NewNop(), []byte(`[1e10001]`)) {
			t.Fatal("audit-mode WebSocket forwarded incomplete inspection")
		}
	}
	kept := filterBodyDLPMatches(limit, "https://api.vendor.example", []config.SuppressEntry{{Rule: scanner.UninspectableJSONNumberPattern}}, map[string]struct{}{scanner.UninspectableJSONNumberPattern: {}}, nil)
	if !scanner.HasInspectionLimit(kept) {
		t.Fatal("body suppression removed inspection refusal")
	}
}

func TestJSONInspectionA2AAudit(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	enforce := false
	cfg.Enforce = &enforce
	cfg.A2AScanning.Enabled = true
	cfg.A2AScanning.Action = config.ActionWarn
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, scan := range []func([]byte) mcp.A2AScanResult{
		func(b []byte) mcp.A2AScanResult { return mcp.ScanA2ARequestBody(t.Context(), b, sc, &cfg.A2AScanning) },
		func(b []byte) mcp.A2AScanResult { return mcp.ScanA2AResponseBody(t.Context(), b, sc, &cfg.A2AScanning) },
	} {
		result := scan([]byte(`[1e10001]`))
		if !a2aResultBlocks(cfg, result.Action, result) {
			t.Fatal("A2A incomplete inspection forwarded in audit mode")
		}
		control := scan([]byte(`[1,2]`))
		if !control.Clean || a2aResultBlocks(cfg, control.Action, control) {
			t.Fatal("A2A clean control refused")
		}
	}
}

func TestJSONInspectionA2AHTTPTransports(t *testing.T) {
	for _, transport := range []string{"forward", "intercept"} {
		for _, direction := range []string{"request", "response", "stream"} {
			for _, limit := range []bool{true, false} {
				t.Run(transport+"/"+direction+"/"+map[bool]string{true: "limit", false: "clean"}[limit], func(t *testing.T) {
					cfg := config.Defaults()
					cfg.Internal = nil
					cfg.A2AScanning.Enabled = true
					cfg.A2AScanning.Action = config.ActionWarn
					cfg.RequestBodyScanning.Enabled = false
					cfg.ResponseScanning.Enabled = false
					enforce := false
					cfg.Enforce = &enforce
					body := `[1,2]`
					if limit {
						body = `[1e10001]`
					}
					request, response, contentType := `{"text":"hello"}`, body, "application/a2a+json"
					if direction == "request" {
						request = body
						response = `{"text":"hello"}`
					}
					if direction == "stream" {
						response = "data: " + body + "\n\n"
						contentType = "text/event-stream"
					}
					w, hits, _ := driveProxyA2AHardening(t, transport, request, response, contentType, cfg)
					if limit {
						if direction == "stream" {
							if w.Body.Len() != 0 {
								t.Fatal("incomplete stream forwarded")
							}
						} else if w.Code != http.StatusForbidden {
							t.Fatalf("incomplete body status=%d", w.Code)
						}
						if direction == "request" && hits != 0 {
							t.Fatal("incomplete request reached upstream")
						}
					} else if w.Code != http.StatusOK || w.Body.String() != response {
						t.Fatalf("clean control status=%d body=%s", w.Code, w.Body.String())
					}
				})
			}
		}
	}
}

func TestJSONInspectionInterceptResponseInjectionOnly(t *testing.T) {
	for _, body := range []string{`[1e10001]`, `[1,2]`} {
		upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(upstream.Close)
		cache, pool, cfg, _, logger, met := testInterceptSetup(t)
		cfg.ResponseScanning.Action = config.ActionWarn
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp := interceptAndRequest(t, upstream, cache, pool, cfg, sc, logger, met, req)
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || string(data) != body {
			t.Fatalf("intercept response changed: status=%d", resp.StatusCode)
		}
	}
}

func TestJSONInspectionReverseResponseInjectionOnly(t *testing.T) {
	for _, body := range []string{`[1e10001]`, `[1,2]`} {
		cfg := testScannerConfig()
		cfg.ResponseScanning.Action = config.ActionWarn
		server := reverseTestSetup(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		})
		resp := testGet(t, server.URL)
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || string(data) != body {
			t.Fatalf("reverse response changed: status=%d", resp.StatusCode)
		}
	}
}

func TestJSONInspectionProxyFragmentsWarn(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	ceeCfg := cfg.CrossRequestDetection
	ceeCfg.Enabled = true
	ceeCfg.Action = config.ActionWarn
	ceeCfg.FragmentReassembly.Enabled = true
	buffer := scanner.NewFragmentBuffer(65536, 10, 300)
	t.Cleanup(buffer.Close)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for i, part := range []string{`[1e`, `10001]`} {
		result := ceeAdmit(t.Context(), ceeAdmitOptions{Outbound: []byte(part), TargetURL: "https://api.vendor.example", Agent: "inspection", ClientIP: "192.0.2.1", RequestID: "inspection", Config: ceeCfg, Fragments: buffer, Scanner: sc, Logger: audit.NewNop(), Metrics: metrics.New()})
		if result.Blocked != (i == 1) {
			t.Fatalf("fragment %d blocked=%v", i, result.Blocked)
		}
	}
}

func TestJSONInspectionProxyFragmentAttribution(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	ceeCfg := cfg.CrossRequestDetection
	ceeCfg.Enabled = true
	ceeCfg.Action = config.ActionWarn
	ceeCfg.FragmentReassembly.Enabled = true
	buffer := scanner.NewFragmentBuffer(65536, 10, 300)
	t.Cleanup(buffer.Close)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	card := cardtest.Number()
	parts := []string{`{"n":1e10001,"s":"` + card[:8], card[8:] + `"}`}
	probe := sc.ScanTextForDLP(t.Context(), parts[0]+parts[1])
	if !scanner.HasInspectionLimit(probe.Matches) || len(probe.Matches) < 2 || probe.Matches[0].IsInspectionLimit() {
		t.Fatal("mixed-finding fixture did not exercise ordinary-first ordering")
	}
	var result ceeResult
	for i, part := range parts {
		result = ceeAdmit(t.Context(), ceeAdmitOptions{Outbound: []byte(part), TargetURL: "https://api.vendor.example", Agent: "inspection", ClientIP: "192.0.2.1", RequestID: "inspection", Config: ceeCfg, Fragments: buffer, Scanner: sc, Logger: audit.NewNop(), Metrics: metrics.New()})
		if i == 0 && result.Blocked {
			t.Fatal("partial fragment refused")
		}
	}
	if !result.Blocked || result.BlockKind != scanner.UninspectableJSONNumberPattern {
		t.Fatalf("fragment refusal attribution: blocked=%v kind=%s", result.Blocked, result.BlockKind)
	}
}

func TestJSONInspectionForwardFragmentReceipt(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	cfg.RequestBodyScanning.Enabled = false
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.Action = config.ActionWarn
	cfg.CrossRequestDetection.EntropyBudget.Enabled = false
	cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
	cfg.ApplyDefaults()
	cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"93.184.216.34"}}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	var records bytes.Buffer
	log, err := audit.NewWithStream("json", "stdout", "", true, true, &records)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(log.Close)
	p, err := New(cfg, log, sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if p.fragmentBufferPtr.Load() == nil {
		t.Fatal("CEE fragment buffer not initialized")
	}
	rph := newReceiptProxyHelper(t)
	p.receiptEmitterPtr.Store(rph.emitter)
	hits := 0
	p.client = &http.Client{Transport: forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
		hits++
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("accepted")), Request: r}, nil
	})}
	card := cardtest.Number()
	parts := []string{`{"n":1e10001,"s":"` + card[:8], card[8:] + `"}`}
	var blocked *httptest.ResponseRecorder
	for i, part := range parts {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.vendor.example/upload", strings.NewReader(part))
		req.Header.Set("Content-Type", "text/plain")
		req.RemoteAddr = "192.0.2.1:12345"
		w := httptest.NewRecorder()
		p.handleForwardHTTP(w, req)
		want := http.StatusOK
		if i == 1 {
			want = http.StatusForbidden
			blocked = w
		}
		if w.Code != want {
			t.Fatalf("fragment=%d status=%d want=%d body=%s", i, w.Code, want, w.Body.String())
		}
	}
	if hits != 1 {
		t.Fatalf("hits=%d want=1", hits)
	}
	receipts := rph.findReceipts(t)
	denials := 0
	for _, r := range receipts {
		if err := receipt.VerifyWithKey(r, rph.pubHex); err != nil {
			t.Fatal(err)
		}
		if r.ActionRecord.Layer == "cross_request" && r.ActionRecord.Verdict == config.ActionBlock {
			denials++
			if r.ActionRecord.Pattern != scanner.UninspectableJSONNumberPattern {
				t.Fatalf("pattern=%s", r.ActionRecord.Pattern)
			}
			requireSignedRecordedReceipt(t, rph, receipts, blocked.Header().Get("X-Pipelock-Receipt"))
			if r.ActionRecord.PolicyHash != cfg.CanonicalPolicyHash() {
				t.Fatal("receipt policy hash differs from deciding config")
			}
		}
	}
	if !strings.Contains(records.String(), "fragment reassembly DLP match: "+scanner.UninspectableJSONNumberPattern) {
		t.Fatalf("missing audit cause: %s", records.String())
	}
	if denials != 1 {
		t.Fatalf("forward CEE denial receipts=%d want=1; total receipts=%d; status=%d hits=%d", denials, len(receipts), blocked.Code, hits)
	}
}
