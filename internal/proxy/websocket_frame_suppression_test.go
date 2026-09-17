// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	wsSuppressedPattern = "WebSocket Frame Suppression"
	wsSuppressedValue   = "framesuppressionmarkerqzv"
	wsOtherPattern      = "WebSocket Frame Other"
	wsOtherValue        = "frameothermarkerqzv"
	wsAllowedTarget     = "wss://socket.vendor.example/allowed"
)

func TestWebSocketFrameSuppressionHonorsScopedBodyControls(t *testing.T) {
	for _, requestBodyEnabled := range []bool{false, true} {
		t.Run("request_body_scanning_enabled="+strconv.FormatBool(requestBodyEnabled), func(t *testing.T) {
			cfg := websocketFrameSuppressionConfig(requestBodyEnabled)
			relay, m := newWebSocketFrameSuppressionRelay(t, cfg, wsAllowedTarget)

			if relay.scanClientText(t.Context(), audit.NewNop(), []byte(wsSuppressedValue)) {
				t.Fatal("scoped suppressed frame was blocked")
			}
			assertWebSocketFrameDroppedMetric(t, m, 1)
			if relay.scanClientText(t.Context(), audit.NewNop(), []byte("ordinary websocket message")) {
				t.Fatal("ordinary frame was blocked")
			}
		})
	}

	t.Run("different upstream remains blocked", func(t *testing.T) {
		cfg := websocketFrameSuppressionConfig(true)
		relay, _ := newWebSocketFrameSuppressionRelay(t, cfg, "wss://socket.vendor.example/other")
		if !relay.scanClientText(t.Context(), audit.NewNop(), []byte(wsSuppressedValue)) {
			t.Fatal("suppression scoped to another upstream allowed the frame")
		}
	})

	t.Run("unrelated pattern remains blocked", func(t *testing.T) {
		cfg := websocketFrameSuppressionConfig(true)
		relay, m := newWebSocketFrameSuppressionRelay(t, cfg, wsAllowedTarget)
		payload := wsSuppressedValue + ":" + wsOtherValue
		if !relay.scanClientText(t.Context(), audit.NewNop(), []byte(payload)) {
			t.Fatal("suppressed finding masked an unrelated frame finding")
		}
		assertWebSocketFrameDroppedMetric(t, m, 1)
	})

	t.Run("core floor remains blocked", func(t *testing.T) {
		cfg := websocketFrameSuppressionConfig(true)
		cfg.Suppress = append(cfg.Suppress, config.SuppressEntry{Rule: "AWS Access ID", Path: "*"})
		relay, _ := newWebSocketFrameSuppressionRelay(t, cfg, wsAllowedTarget)
		core := "AKIA" + "IOSFODNN7EXAMPLE"
		if !relay.scanClientText(t.Context(), audit.NewNop(), []byte(core)) {
			t.Fatal("suppression bypassed immutable core DLP")
		}
	})
}

func TestWebSocketFrameSuppressionCrossMessageAndRedaction(t *testing.T) {
	t.Run("scoped cross-message finding is allowed and recorded once", func(t *testing.T) {
		cfg := websocketFrameSuppressionConfig(true)
		relay, m := newWebSocketFrameSuppressionRelay(t, cfg, wsAllowedTarget)
		if relay.scanClientCrossMessageText(t.Context(), audit.NewNop(), []byte("framesuppression"), []byte("markerqzv")) {
			t.Fatal("scoped suppressed cross-message finding was blocked")
		}
		assertWebSocketFrameDroppedMetric(t, m, 1)
	})

	t.Run("cross-message redaction still fails closed", func(t *testing.T) {
		cfg := websocketFrameSuppressionConfig(true)
		cfg.Redaction = redact.Config{
			Enabled:        true,
			DefaultProfile: "code",
			Profiles: map[string]redact.ProfileSpec{
				"code": {Classes: []string{string(redact.ClassAWSAccessKey)}},
			},
			Limits: redact.DefaultLimits(),
		}
		p := &Proxy{logger: audit.NewNop(), metrics: metrics.New()}
		runtime, err := p.buildRedactionRuntimeWithScanner(cfg, nil)
		if err != nil {
			t.Fatalf("build redaction runtime: %v", err)
		}
		if runtime == nil || !runtime.required {
			t.Fatal("expected required redaction runtime")
		}
		relay, _ := newWebSocketFrameSuppressionRelay(t, cfg, wsAllowedTarget)
		relay.proxy = p
		relay.redaction = runtime
		if !relay.scanClientCrossMessageText(t.Context(), audit.NewNop(), []byte("framesuppression"), []byte("markerqzv")) {
			t.Fatal("cross-message redaction did not fail closed")
		}
	})
}

func TestWebSocketFrameSuppressionControlPayloadTelemetry(t *testing.T) {
	cfg := websocketFrameSuppressionConfig(true)
	relay, m := newWebSocketFrameSuppressionRelay(t, cfg, wsAllowedTarget)
	var tail []byte
	for i := 1; i <= 2; i++ {
		if relay.enforceClientControlPayload(t.Context(), audit.NewNop(), []byte(wsSuppressedValue), &tail) {
			t.Fatal("scoped control payload was blocked")
		}
		assertWebSocketFrameDroppedMetric(t, m, i)
	}
}

func TestWebSocketFrameSuppressionTelemetryAvailability(t *testing.T) {
	t.Run("missing proxy does not prevent suppression", func(t *testing.T) {
		relay, _ := newWebSocketFrameSuppressionRelay(t, websocketFrameSuppressionConfig(true), wsAllowedTarget)
		relay.proxy = nil
		if relay.scanClientText(t.Context(), audit.NewNop(), []byte(wsSuppressedValue)) {
			t.Fatal("scoped frame was blocked without an audit consumer")
		}
	})
	t.Run("missing logger retains metrics and deduplicates one frame", func(t *testing.T) {
		relay, m := newWebSocketFrameSuppressionRelay(t, websocketFrameSuppressionConfig(true), wsAllowedTarget)
		relay.proxy.logger = nil
		for range 2 {
			if relay.scanClientText(t.Context(), audit.NewNop(), []byte(wsSuppressedValue)) {
				t.Fatal("scoped frame was blocked without a logger")
			}
		}
		assertWebSocketFrameDroppedMetric(t, m, 1)
	})
}

func websocketFrameSuppressionConfig(requestBodyEnabled bool) *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.RequestBodyScanning.Enabled = requestBodyEnabled
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.DLP.Patterns = append(cfg.DLP.Patterns,
		config.DLPPattern{Name: wsSuppressedPattern, Regex: wsSuppressedValue, Severity: config.SeverityHigh},
		config.DLPPattern{Name: wsOtherPattern, Regex: wsOtherValue, Severity: config.SeverityHigh},
	)
	cfg.Suppress = []config.SuppressEntry{{Rule: wsSuppressedPattern, Path: wsAllowedTarget}}
	return cfg
}

func newWebSocketFrameSuppressionRelay(t *testing.T, cfg *config.Config, target string) (*wsRelay, *metrics.Metrics) {
	t.Helper()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	m := metrics.New()
	return &wsRelay{
		clientConn:   discardConn{},
		upstreamConn: discardConn{},
		scanner:      sc,
		proxy:        &Proxy{logger: audit.NewNop(), metrics: m},
		cfg:          cfg,
		targetURL:    target,
		hostname:     "socket.vendor.example",
		path:         "/allowed",
		maxMsg:       cfg.WebSocketProxy.MaxMessageBytes,
		scanText:     true,
	}, m
}

func assertWebSocketFrameDroppedMetric(t *testing.T, m *metrics.Metrics, want int) {
	t.Helper()
	rec := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	line := `pipelock_dlp_dropped_matches_total{pattern="` + wsSuppressedPattern + `",reason="suppressed",surface="body"} ` + strconv.Itoa(want)
	if !slices.Contains(strings.Split(rec.Body.String(), "\n"), line) {
		t.Fatalf("dropped DLP metric missing or wrong count: want exact line %q", line)
	}
}
