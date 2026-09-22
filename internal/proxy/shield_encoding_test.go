// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/shield"
)

func encodeUTF16ForShieldTest(s string, order shieldUTF16Order, bom bool) []byte {
	out := make([]byte, 0, len(s)*2+2)
	if bom {
		if order == shieldUTF16LE {
			out = append(out, 0xff, 0xfe)
		} else {
			out = append(out, 0xfe, 0xff)
		}
	}
	for _, unit := range utf16.Encode([]rune(s)) {
		out = appendUTF16Unit(out, unit, order)
	}
	return out
}

func appendUTF16Unit(out []byte, unit uint16, order shieldUTF16Order) []byte {
	var encoded [2]byte
	if order == shieldUTF16LE {
		binary.LittleEndian.PutUint16(encoded[:], unit)
	} else {
		binary.BigEndian.PutUint16(encoded[:], unit)
	}
	return append(out, encoded[:]...)
}

func TestShieldUTF16_RewritesAndRepairsMetadata(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults().BrowserShield
	cfg.Enabled = true
	cfg.InjectFingerprintShims = false
	cfg.StripExtensionProbing = false
	cfg.StripTrackingPixels = true
	engine := shield.NewEngine(nil)

	tests := []struct {
		name        string
		body        string
		contentType string
		order       shieldUTF16Order
		bom         bool
		wantXML     bool
	}{
		{
			name:        "html little endian BOM and meta declaration",
			body:        `<html><head><meta charset="UTF-16LE"></head><body><img src="https://track.example.com/pixel" width="1" height="1"></body></html>`,
			contentType: "text/html; charset=utf-16le",
			order:       shieldUTF16LE,
			bom:         true,
		},
		{
			name:        "html transport charset overrides stale meta",
			body:        `<html><head><meta charset="UTF-8"></head><body><img src="https://track.example.com/pixel" width="1" height="1"></body></html>`,
			contentType: "text/html; charset=utf-16le",
			order:       shieldUTF16LE,
			bom:         true,
		},
		{
			name:        "SVG big endian BOM and XML declaration",
			body:        `<?xml version="1.0" encoding="UTF-16BE"?><svg xmlns="http://www.w3.org/2000/svg"><image href="https://track.example.com/pixel" width="1" height="1"/></svg>`,
			contentType: "image/svg+xml; charset=utf-16be",
			order:       shieldUTF16BE,
			bom:         true,
			wantXML:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{"Content-Type": {tt.contentType}}
			headers.Set("ETag", `"upstream"`)
			headers.Set("Digest", "sha-256=upstream")
			headers.Set("Content-MD5", "upstream")
			result := runShieldPipelineWithEncoding(engine, encodeUTF16ForShieldTest(tt.body, tt.order, tt.bom), tt.contentType, headers, &cfg, metrics.New(), TransportFetch)
			if result.uninspectableReason != "" {
				t.Fatal(result.uninspectableReason)
			}
			if result.summary == nil {
				t.Fatal("expected Shield rewrite summary")
			}
			if strings.Contains(string(result.body), "track.example.com") || !strings.HasPrefix(headers.Get("Content-Type"), strings.Split(tt.contentType, ";")[0]+"; charset=utf-8") {
				t.Fatalf("rewritten body or content type was not normalized: body=%q content-type=%q", result.body, headers.Get("Content-Type"))
			}
			if got, want := headers.Get("Content-Length"), fmt.Sprintf("%d", len(result.body)); got != want {
				t.Fatalf("Content-Length = %q, want %q", got, want)
			}
			if headers.Get("ETag") != "" || headers.Get("Digest") != "" || headers.Get("Content-MD5") != "" {
				t.Fatalf("stale validators survived: %#v", headers)
			}
			if tt.wantXML && !strings.Contains(string(result.body), `encoding="UTF-8"`) {
				t.Fatalf("XML declaration not repaired: %q", result.body)
			}
		})
	}
}

func TestShieldUTF16_UnchangedKeepsOriginalBytesAndMetadata(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults().BrowserShield
	cfg.Enabled = true
	cfg.InjectFingerprintShims = false
	cfg.StripExtensionProbing = false
	body := encodeUTF16ForShieldTest(`<html><head></head><body>plain</body></html>`, shieldUTF16LE, true)
	headers := http.Header{"Content-Type": {"text/html; charset=utf-16le"}}
	headers.Set("ETag", `"upstream"`)
	result := runShieldPipelineWithEncoding(shield.NewEngine(nil), body, headers.Get("Content-Type"), headers, &cfg, metrics.New(), TransportFetch)
	if result.uninspectableReason != "" || result.summary != nil {
		t.Fatalf("unexpected outcome: %+v", result)
	}
	if !bytes.Equal(result.body, body) || headers.Get("Content-Type") != "text/html; charset=utf-16le" || headers.Get("ETag") != `"upstream"` {
		t.Fatalf("unchanged UTF-16 response mutated: equal=%t content-type=%q etag=%q", bytes.Equal(result.body, body), headers.Get("Content-Type"), headers.Get("ETag"))
	}
}

func TestShieldRewritePreservesLegacyCharsetWithoutTranscoding(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults().BrowserShield
	cfg.Enabled = true
	cfg.InjectFingerprintShims = false
	cfg.StripExtensionProbing = false
	cfg.StripTrackingPixels = true
	body := append([]byte(`<html><body>caf`), 0xe9)
	body = append(body, []byte(`<img src="https://track.example.com/pixel" width="1" height="1"></body></html>`)...)
	headers := http.Header{"Content-Type": {"text/html; charset=windows-1252"}}
	headers.Set("ETag", `"upstream"`)

	result := runShieldPipelineWithEncoding(shield.NewEngine(nil), body, headers.Get("Content-Type"), headers, &cfg, metrics.New(), TransportFetch)
	if result.uninspectableReason != "" || result.summary == nil {
		t.Fatalf("unexpected outcome: %+v", result)
	}
	if strings.Contains(string(result.body), "track.example.com") || !bytes.Contains(result.body, []byte{0xe9}) {
		t.Fatalf("rewrite did not preserve legacy body bytes: %q", result.body)
	}
	if got := headers.Get("Content-Type"); got != "text/html; charset=windows-1252" {
		t.Fatalf("Content-Type = %q, want legacy charset preserved", got)
	}
	if headers.Get("ETag") != "" {
		t.Fatalf("stale validator survived: %#v", headers)
	}
}

func TestShieldUTF16_RejectsUninspectableInputs(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults().BrowserShield
	cfg.Enabled = true
	tests := []struct {
		name        string
		body        []byte
		contentType string
	}{
		{"odd byte count", []byte{0xff, 0xfe, '<'}, "text/html; charset=utf-16le"},
		{"unpaired surrogate", []byte{0xff, 0xfe, 0x00, 0xd8}, "text/html; charset=utf-16le"},
		{"BOM conflicts with header", []byte{0xff, 0xfe, '<', 0}, "text/html; charset=utf-16be"},
		{"UTF-16 body conflicts with UTF-8 header", []byte{0xfe, 0xff, 0, '<'}, "text/html; charset=utf-8"},
		{"duplicate charset parameter", encodeUTF16ForShieldTest(`<html><body>plain</body></html>`, shieldUTF16LE, true), "text/html; charset=utf-16le; charset=UTF-16LE"},
		{"trailing malformed parameter", encodeUTF16ForShieldTest(` <html><body>plain</body></html>`, shieldUTF16LE, false), "text/html; charset=utf-16le; @"},
		{"unsupported XML declaration", encodeUTF16ForShieldTest(`<?xml version="1.0" encoding="ISO-8859-1"?><svg/>`, shieldUTF16BE, true), "image/svg+xml; charset=utf-16be"},
		{"XML declaration byte order conflict", encodeUTF16ForShieldTest(`<?xml version="1.0" encoding="UTF-16LE"?><svg/>`, shieldUTF16BE, true), "image/svg+xml; charset=utf-16be"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runShieldPipelineWithEncoding(shield.NewEngine(nil), tt.body, tt.contentType, http.Header{"Content-Type": {tt.contentType}}, &cfg, metrics.New(), TransportFetch)
			if result.uninspectableReason == "" {
				t.Fatal("expected distinct uninspectable outcome")
			}
		})
	}
}

func TestShieldUTF16_DecoderBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		body        []byte
		contentType string
		pipeline    shield.PipelineType
		wantUTF16   bool
		want        string
		wantErr     bool
	}{
		{"ordinary UTF-8", []byte(`<html>plain</html>`), "text/html", shield.PipelineHTML, false, "", false},
		{"little endian signature", encodeUTF16ForShieldTest(`<html>plain</html>`, shieldUTF16LE, false), "text/html; charset=utf-16le", shield.PipelineHTML, true, `<html>plain</html>`, false},
		{"big endian signature", encodeUTF16ForShieldTest(`<html>plain</html>`, shieldUTF16BE, false), "text/html; charset=utf-16be", shield.PipelineHTML, true, `<html>plain</html>`, false},
		{"generic charset without order", []byte("plain"), "text/html; charset=utf-16", shield.PipelineHTML, true, "", true},
		{"malformed content type", []byte{0xff, 0xfe, '<', 0}, "text/html; charset=\"", shield.PipelineHTML, true, "", true},
		{"unsupported declared charset", []byte{0xff, 0xfe, '<', 0}, "text/html; charset=windows-1252", shield.PipelineHTML, true, "", true},
		{"unpaired low surrogate", []byte{0xff, 0xfe, 0x00, 0xdc}, "text/html; charset=utf-16le", shield.PipelineHTML, true, "", true},
		{"valid surrogate pair", encodeUTF16ForShieldTest(`<html>🙂</html>`, shieldUTF16LE, true), "text/html; charset=utf-16le", shield.PipelineHTML, true, `<html>🙂</html>`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, utf16, err := decodeShieldUTF16(tt.body, tt.contentType, tt.pipeline)
			if utf16 != tt.wantUTF16 || (err != nil) != tt.wantErr || (!tt.wantErr && got != tt.want) {
				t.Fatalf("decode = (%q, %t, %v), want (%q, %t, err=%t)", got, utf16, err, tt.want, tt.wantUTF16, tt.wantErr)
			}
		})
	}
}

func TestShieldUTF16_MetadataFallbackAndDeclarations(t *testing.T) {
	t.Parallel()
	if got := embeddedCharsetDeclaration(`<?xml version="1.0"?><svg/>`, shield.PipelineSVG); got != "" {
		t.Fatalf("missing XML charset = %q", got)
	}
	if got := embeddedCharsetDeclaration(`<meta charset="UTF-16BE">`, shield.PipelineHTML); got != "" {
		t.Fatalf("HTML transport encoding must not be overridden by meta charset, got %q", got)
	}
	if got := embeddedCharsetDeclaration(`plain`, shield.PipelineJS); got != "" {
		t.Fatalf("JavaScript charset = %q", got)
	}
	for _, pipeline := range []shield.PipelineType{shield.PipelineHTML, shield.PipelineJS, shield.PipelineSVG, shield.PipelineXHTML} {
		headers := http.Header{"Content-Type": {`invalid; charset="`}}
		repairShieldResponseMetadata(headers, pipeline, []byte("ok"), true)
		if headers.Get("Content-Type") == "" || headers.Get("Content-Length") != "2" {
			t.Fatalf("pipeline %d metadata = %#v", pipeline, headers)
		}
	}
}

func TestShieldUTF16_MalformedContentTypeCannotSkipPipeline(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults().BrowserShield
	cfg.Enabled = true
	cfg.InjectFingerprintShims = false
	cfg.StripExtensionProbing = false
	cfg.StripTrackingPixels = true

	tests := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{
			name:        "duplicate charset with BOM",
			contentType: "text/html; charset=utf-16le; charset=UTF-16LE",
			body:        encodeUTF16ForShieldTest(`<html><body><img src="https://track.example.com/pixel" width="1" height="1"></body></html>`, shieldUTF16LE, true),
		},
		{
			name:        "trailing junk with leading whitespace",
			contentType: "text/html; charset=utf-16le; @",
			body:        encodeUTF16ForShieldTest(` <html><body><img src="https://track.example.com/pixel" width="1" height="1"></body></html>`, shieldUTF16LE, false),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runShieldPipelineWithEncoding(shield.NewEngine(nil), tt.body, tt.contentType, http.Header{"Content-Type": {tt.contentType}}, &cfg, metrics.New(), TransportFetch)
			if result.pipeline != shield.PipelineHTML || result.uninspectableReason == "" {
				t.Fatalf("malformed UTF-16 result = %+v, want HTML pipeline and fail-closed refusal", result)
			}
		})
	}
}

func TestShieldUTF16_HelperFailureBranches(t *testing.T) {
	t.Parallel()
	if _, ok := shieldUTF16BOM([]byte{0}); ok {
		t.Fatal("one byte must not be a BOM")
	}
	if _, ok := shieldUTF16Signature([]byte{0}); ok {
		t.Fatal("one byte must not be a UTF-16 signature")
	}
	if _, err := strictDecodeUTF16([]byte{0x00, 0xd8, 0x41, 0x00}, shieldUTF16LE); err == nil {
		t.Fatal("high surrogate without low surrogate should fail")
	}
	if _, err := strictDecodeUTF16([]byte{0x00, 0x00}, 0); err != nil {
		t.Fatalf("zero byte order uses the big-endian branch safely: %v", err)
	}

	cfg := config.Defaults().BrowserShield
	cfg.Enabled = true
	engine := shield.NewEngine(nil)
	if result := runShieldPipelineWithEncoding(engine, []byte(`{"plain":true}`), "application/json", nil, &cfg, metrics.New(), TransportFetch); result.pipeline != shield.PipelineNone || result.summary != nil {
		t.Fatalf("non-shieldable result = %+v", result)
	}
	cfg.InjectFingerprintShims = false
	cfg.StripExtensionProbing = false
	if result := runShieldPipelineWithEncoding(engine, []byte(`<html>plain</html>`), "text/html", nil, &cfg, metrics.New(), TransportFetch); result.utf16 || string(result.body) != `<html>plain</html>` {
		t.Fatalf("ordinary UTF-8 result = %+v", result)
	}
	if result := runShieldPipelineWithEncoding(engine, []byte{0xff, 0xfe, '<'}, "text/html; charset=utf-16le", nil, &cfg, metrics.New(), TransportFetch); result.uninspectableReason == "" {
		t.Fatal("malformed UTF-16 must produce an uninspectable result")
	}
	if _, err := strictDecodeUTF16([]byte{0xd8, 0x00, 0x00, 0x41}, shieldUTF16BE); err == nil {
		t.Fatal("big-endian high surrogate without low surrogate should fail")
	}
	recordShieldRewriteMetrics(metrics.New(), shield.Result{ExtensionHits: 1, TrackingHits: 1, TrapHits: 1, ShimInjected: true}, TransportFetch)
}

func TestProxy_ApplyShield_UTF16ScanHeadBlocks(t *testing.T) {
	t.Parallel()
	p := newTestProxy(t)
	cfg := config.Defaults()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.MaxShieldBytes = 16
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeScanHead
	body := encodeUTF16ForShieldTest(`<html><body>`+strings.Repeat("safe", 20)+`</body></html>`, shieldUTF16LE, true)
	_, _, blocked := p.applyShield(body, "text/html; charset=utf-16le", "example.com", http.Header{}, cfg, audit.LogContext{}, "127.0.0.1", "req", TransportFetch, "action")
	if blocked == nil || blocked.info.Reason != blockreason.BrowserShieldUninspectable {
		t.Fatalf("scan-head UTF-16 block = %+v, want browser shield uninspectable", blocked)
	}
}

func TestShieldUTF16_OversizeClassifierDoesNotDecodeBody(t *testing.T) {
	body := make([]byte, 1<<16)
	body[0], body[1] = 0xff, 0xfe
	if !isShieldUTF16Response(body, "text/html; charset=utf-16le") {
		t.Fatal("UTF-16 BOM was not classified")
	}
	if allocs := testing.AllocsPerRun(100, func() {
		if !isShieldUTF16Response(body, "text/html; charset=utf-16le") {
			panic("UTF-16 BOM was not classified")
		}
	}); allocs != 0 {
		t.Fatalf("oversize UTF-16 classification allocated %.1f times per run", allocs)
	}
}

func TestProxy_ApplyShield_UTF16TransportParity(t *testing.T) {
	t.Parallel()
	p := newTestProxy(t)
	cfg := config.Defaults()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.InjectFingerprintShims = false
	cfg.BrowserShield.StripExtensionProbing = false
	cfg.BrowserShield.StripTrackingPixels = true
	body := encodeUTF16ForShieldTest(`<html><body><img src="https://track.example.com/pixel" width="1" height="1"></body></html>`, shieldUTF16LE, true)
	for _, transport := range []string{TransportFetch, TransportForward, TransportConnect} {
		t.Run(transport, func(t *testing.T) {
			headers := http.Header{"Content-Type": {"text/html; charset=utf-16le"}}
			headers.Set("ETag", `"upstream"`)
			out, summary, blocked := p.applyShield(body, headers.Get("Content-Type"), "example.com", headers, cfg, audit.LogContext{}, "127.0.0.1", "req", transport, "action")
			if blocked != nil || summary == nil || strings.Contains(string(out), "track.example.com") {
				t.Fatalf("transport outcome: blocked=%+v summary=%+v body=%q", blocked, summary, out)
			}
			if headers.Get("Content-Type") != "text/html; charset=utf-8" || headers.Get("ETag") != "" {
				t.Fatalf("metadata = %#v", headers)
			}
		})
	}
}

func TestReverseShieldUTF16_BufferedAndScanHeadPaths(t *testing.T) {
	page := string(encodeUTF16ForShieldTest(`<html><body><img src="https://track.example.com/pixel" width="1" height="1"></body></html>`, shieldUTF16BE, true))
	t.Run("buffered rewrite", func(t *testing.T) {
		resp := reverseShieldResponseHarnessWithContentType(t, config.ShieldStrictnessStandard, config.ShieldOversizeBlock, false, 4096, "text/html; charset=utf-16be", page)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "track.example.com") || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
			t.Fatalf("reverse buffered response: status=%d content-type=%q body=%q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
		}
	})
	t.Run("scan head blocks", func(t *testing.T) {
		resp := reverseShieldResponseHarnessWithContentType(t, config.ShieldStrictnessStandard, config.ShieldOversizeScanHead, false, 16, "text/html; charset=utf-16be", page)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "UTF-16") || resp.Header.Get(blockreason.HeaderReason) != string(blockreason.BrowserShieldUninspectable) {
			t.Fatalf("reverse scan-head response: status=%d body=%q", resp.StatusCode, body)
		}
	})
}

func TestForwardAndConnectShieldUTF16RuntimeParity(t *testing.T) {
	body := encodeUTF16ForShieldTest(`<html><body><img src="https://track.example.com/pixel" width="1" height="1"></body></html>`, shieldUTF16LE, true)

	t.Run("forward", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-16le")
			w.Header().Set("ETag", `"upstream"`)
			_, _ = w.Write(body)
		}))
		defer backend.Close()

		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		cfg.APIAllowlist = nil
		cfg.ForwardProxy.Enabled = true
		cfg.DLP.Patterns = nil
		cfg.ResponseScanning.Enabled = false
		cfg.BrowserShield.Enabled = true
		cfg.BrowserShield.InjectFingerprintShims = false
		cfg.BrowserShield.StripExtensionProbing = false
		cfg.BrowserShield.StripTrackingPixels = true
		proxyAddr, cleanup := startProxyOnFreePort(t, cfg)
		defer cleanup()

		resp := doGet(t, proxyClient(proxyAddr), backend.URL+"/page")
		defer func() { _ = resp.Body.Close() }()
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || strings.Contains(string(got), "track.example.com") || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" || resp.Header.Get("ETag") != "" {
			t.Fatalf("forward response: status=%d headers=%#v body=%q", resp.StatusCode, resp.Header, got)
		}
	})

	t.Run("CONNECT", func(t *testing.T) {
		upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-16le")
			w.Header().Set("ETag", `"upstream"`)
			_, _ = w.Write(body)
		}))
		defer upstream.Close()

		cache, pool, cfg, sc, logger, m := testInterceptSetup(t)
		cfg.DLP.Patterns = nil
		cfg.ResponseScanning.Enabled = false
		cfg.BrowserShield.Enabled = true
		cfg.BrowserShield.InjectFingerprintShims = false
		cfg.BrowserShield.StripExtensionProbing = false
		cfg.BrowserShield.StripTrackingPixels = true
		p, err := New(cfg, audit.NewNop(), sc, m)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+"/page", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, p)
		defer func() { _ = resp.Body.Close() }()
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || strings.Contains(string(got), "track.example.com") || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" || resp.Header.Get("ETag") != "" {
			t.Fatalf("CONNECT response: status=%d headers=%#v body=%q", resp.StatusCode, resp.Header, got)
		}
	})
}
