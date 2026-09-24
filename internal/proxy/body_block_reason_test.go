// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const testWarnMarkerPattern = "Test Warn Marker"

func TestBlockingBodyFinding(t *testing.T) {
	t.Parallel()

	entropy := &ContentEntropyFinding{Entropy: 6, Threshold: 4.5, Length: 64}
	warnMatch := scanner.TextDLPMatch{PatternName: testWarnMarkerPattern, Severity: config.SeverityMedium}
	coreMatch := scanner.TextDLPMatch{PatternName: "AWS Access ID", Severity: config.SeverityCritical}
	injection := []scanner.ResponseMatch{{PatternName: "Test Injection"}}
	const host = "api.vendor.example"

	newCfg := func(bodyAction string, trusted ...string) *config.Config {
		cfg := config.Defaults()
		cfg.RequestBodyScanning.Action = bodyAction
		cfg.RequestBodyScanning.TrustedHosts = trusted
		return cfg
	}
	blockingEntropy := func(r BodyScanResult) BodyScanResult {
		r.EntropyFinding, r.EntropyAction = entropy, config.ActionBlock
		return r
	}
	for _, tt := range []struct {
		name   string
		result BodyScanResult
		cfg    *config.Config
		want   bodyBlockCause
	}{
		{name: "nil config", result: blockingEntropy(BodyScanResult{}), cfg: nil, want: bodyBlockCauseUnknown},
		{name: "nothing blocks on its own", result: BodyScanResult{EntropyFinding: entropy, EntropyAction: config.ActionWarn, DLPMatches: []scanner.TextDLPMatch{warnMatch}}, cfg: newCfg(config.ActionWarn), want: bodyBlockCauseUnknown},
		{name: "blocking entropy alone", result: blockingEntropy(BodyScanResult{}), cfg: newCfg(config.ActionWarn), want: bodyBlockCauseEntropy},
		{name: "blocking entropy beside warn-level secret", result: blockingEntropy(BodyScanResult{DLPMatches: []scanner.TextDLPMatch{warnMatch}}), cfg: newCfg(config.ActionWarn), want: bodyBlockCauseEntropy},
		{name: "blocking secret beside blocking entropy", result: blockingEntropy(BodyScanResult{DLPMatches: []scanner.TextDLPMatch{warnMatch}}), cfg: newCfg(config.ActionBlock), want: bodyBlockCauseDLP},
		{name: "hard-blocking core secret", result: blockingEntropy(BodyScanResult{DLPMatches: []scanner.TextDLPMatch{coreMatch}}), cfg: newCfg(config.ActionWarn), want: bodyBlockCauseDLP},
		{name: "injection to untrusted host", result: blockingEntropy(BodyScanResult{InjectionMatches: injection}), cfg: newCfg(config.ActionWarn), want: bodyBlockCauseInjection},
		{name: "injection to trusted host beside blocking entropy", result: blockingEntropy(BodyScanResult{InjectionMatches: injection}), cfg: newCfg(config.ActionWarn, host), want: bodyBlockCauseEntropy},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := blockingBodyFinding(tt.result, host, tt.cfg); got != tt.want {
				t.Fatalf("blockingBodyFinding = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBodyBlockCauseLabel(t *testing.T) {
	t.Parallel()
	for cause, want := range map[bodyBlockCause]string{
		bodyBlockCauseUnknown:   "current",
		bodyBlockCauseInjection: scannerLabelBodyPromptInjection,
		bodyBlockCauseDLP:       scannerLabelBodyDLP,
		bodyBlockCauseEntropy:   scannerLabelBodyEntropy,
	} {
		if got := bodyBlockCauseLabel(cause, "current"); got != want {
			t.Fatalf("bodyBlockCauseLabel(%v) = %q, want %q", cause, got, want)
		}
	}
}

// A blocking entropy finding beside a warn-level secret match must be named as
// the cause; the secret match only rode along.
func TestInterceptTunnel_BodyBlockNamesEntropyOverWarnSecret(t *testing.T) {
	var upstreamHit atomic.Bool
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	cache, pool, cfg, _, logger, m := testInterceptSetup(t)
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:     testWarnMarkerPattern,
		Regex:    `warnmarker[0-9]{6}`,
		Severity: config.SeverityMedium,
	})
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.ContentEntropyEnabled = true
	cfg.RequestBodyScanning.ContentEntropyAction = config.ActionBlock
	cfg.RequestBodyScanning.ContentEntropyThreshold = 4.5
	cfg.RequestBodyScanning.ContentEntropyMinLength = 32
	sc := scanner.MustNew(cfg)
	t.Cleanup(func() { sc.Close() })

	body := `{"blob":"` + opaqueHighEntropyBodyValue() + `","note":"warnmarker123456"}`
	addr := upstream.Listener.Addr().String()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+addr+"/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp := interceptAndRequest(t, upstream, cache, pool, cfg, sc, logger, m, req)
	defer func() { _ = resp.Body.Close() }()

	assertEntropyNamedNotWarnSecret(t, resp)
	if upstreamHit.Load() {
		t.Fatal("blocked request reached upstream")
	}
}

// warnSecretBesideBlockingEntropy configures a warn-level custom secret pattern
// next to a blocking entropy check, the combination where only entropy blocks.
func warnSecretBesideBlockingEntropy(cfg *config.Config) {
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:     testWarnMarkerPattern,
		Regex:    `warnmarker[0-9]{6}`,
		Severity: config.SeverityMedium,
	})
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.ContentEntropyEnabled = true
	cfg.RequestBodyScanning.ContentEntropyAction = config.ActionBlock
	cfg.RequestBodyScanning.ContentEntropyThreshold = 4.5
	cfg.RequestBodyScanning.ContentEntropyMinLength = 32
}

func warnSecretEntropyBody() string {
	return `{"blob":"` + opaqueHighEntropyBodyValue() + `","note":"warnmarker123456"}`
}

func assertEntropyNamedNotWarnSecret(t *testing.T, resp *http.Response) {
	t.Helper()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", resp.StatusCode, string(respBody))
	}
	if !strings.Contains(string(respBody), "high entropy") {
		t.Fatalf("block reason must name the blocking entropy finding; body=%q", string(respBody))
	}
	if strings.Contains(string(respBody), testWarnMarkerPattern) {
		t.Fatalf("block reason must not blame the warn-level secret; body=%q", string(respBody))
	}
	if got := resp.Header.Get(blockreason.HeaderReason); got != string(blockreason.BodyEntropy) {
		t.Fatalf("structured block reason = %q, want %s; layer=%q", got, blockreason.BodyEntropy, resp.Header.Get(blockreason.HeaderLayer))
	}
}

func TestForwardBodyBlockNamesEntropyOverWarnSecret(t *testing.T) {
	var hits atomic.Int32
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, warnSecretBesideBlockingEntropy)
	defer cleanup()
	installForwardTestDialer(p, backend.Listener.Addr().String())

	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(t.Context(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	body := warnSecretEntropyBody()
	_, _ = fmt.Fprintf(conn, "POST http://upload.vendor.example/upload HTTP/1.1\r\nHost: upload.vendor.example\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertEntropyNamedNotWarnSecret(t, resp)
	if hits.Load() != 0 {
		t.Fatalf("upstream hits = %d, want 0", hits.Load())
	}
}

func TestReverseBodyBlockNamesEntropyOverWarnSecret(t *testing.T) {
	var hits atomic.Int32
	cfg := reverseTestConfig()
	warnSecretBesideBlockingEntropy(cfg)
	rule := contractruntimetest.HTTPEnforceRule("r-chat", "api.example.com", "/v1/chat", http.MethodPost)
	proxy := reverseLiveLockSetupWithConfig(t, cfg, "api.example.com", testContractLoader(t, contractruntime.ModeLive, rule), nil,
		func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			_, _ = w.Write([]byte("unexpected"))
		})

	resp := testAgentPost(t, proxy.URL+"/v1/chat", warnSecretEntropyBody())
	defer func() { _ = resp.Body.Close() }()

	assertEntropyNamedNotWarnSecret(t, resp)
	if hits.Load() != 0 {
		t.Fatalf("upstream hits = %d, want 0", hits.Load())
	}
}

func wsScanHitLabels(t *testing.T, m *metrics.Metrics) map[string]float64 {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	hits := map[string]float64{}
	for _, fam := range families {
		if fam.GetName() != "pipelock_ws_scan_hits_total" {
			continue
		}
		for _, mm := range fam.GetMetric() {
			for _, lp := range mm.GetLabel() {
				hits[lp.GetValue()] += mm.GetCounter().GetValue()
			}
		}
	}
	return hits
}

// The WebSocket block path classifies a blocking entropy finding beside a
// warn-level secret as entropy, and a hard-blocking injection beside blocking
// entropy as injection.
func TestWSRelay_BodyBlockClassifiesByBlockingFinding(t *testing.T) {
	entropy := &ContentEntropyFinding{Entropy: 6, Threshold: 4.5, Length: 64}
	for _, tt := range []struct {
		name   string
		result BodyScanResult
		want   string
	}{
		{
			name: "entropy beside warn-level secret",
			result: BodyScanResult{
				Action:         config.ActionBlock,
				EntropyFinding: entropy,
				EntropyAction:  config.ActionBlock,
				DLPMatches:     []scanner.TextDLPMatch{{PatternName: testWarnMarkerPattern, Severity: config.SeverityMedium}},
			},
			want: scannerLabelBodyEntropy,
		},
		{
			name: "hard-blocking injection beside blocking entropy",
			result: BodyScanResult{
				Action:           config.ActionBlock,
				EntropyFinding:   entropy,
				EntropyAction:    config.ActionBlock,
				InjectionMatches: []scanner.ResponseMatch{{PatternName: "Test Injection"}},
			},
			want: scannerLabelBodyPromptInjection,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			relay, m := newAdaptiveWSRelay(t, 0)
			enforce := true
			relay.cfg.Enforce = &enforce
			relay.cfg.RequestBodyScanning.Action = config.ActionWarn
			relay.hostname = "exfil.vendor.example"

			if !relay.handleClientMessageBodyResult(audit.NewNop(), []byte(`{"payload":"x"}`), tt.result) {
				t.Fatal("expected the frame to be blocked")
			}
			hits := wsScanHitLabels(t, m)
			if hits[tt.want] != 1 || len(hits) != 1 {
				t.Fatalf("ws scan hits = %v, want exactly one %q", hits, tt.want)
			}
		})
	}
}
