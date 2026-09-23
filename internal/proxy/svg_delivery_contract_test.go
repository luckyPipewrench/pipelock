// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// The SVG delivery contract: an SVG response reaches the client only after
// Browser Shield validated the COMPLETE body and the rewritten body it will
// deliver. Every other state (shield disabled or exempt, partial, oversized,
// undecodable, or refused by validation) is a refusal, never raw bytes.

const (
	benignSVGFixture  = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M2 2h20v20H2z"/></svg>`
	hostileSVGFixture = `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`
	// A hyperlink passes validation (it fetches nothing until followed) and is
	// rewritten by Shield, so this proves the delivered body is the rewritten
	// one: the external target is gone and the drawing survives.
	linkedSVGFixture = `<svg xmlns="http://www.w3.org/2000/svg"><a href="https://link.vendor.example/page"><rect id="kept" width="4" height="4"/></a></svg>`
)

// hostileSVGForms enumerates the active constructs the contract refuses.
// Each carries a unique marker that must never reach the client.
var hostileSVGForms = map[string]string{
	"script":            `<svg xmlns="http://www.w3.org/2000/svg"><script>zqx_script()</script></svg>`,
	"onload":            `<svg xmlns="http://www.w3.org/2000/svg" onload="zqx_onload()"><rect/></svg>`,
	"javascript href":   `<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:zqx_js()"><rect/></a></svg>`,
	"fetching href":     `<svg xmlns="http://www.w3.org/2000/svg"><image href="https://zqx-fetch.vendor.example/b.png"/></svg>`,
	"presentation url":  `<svg xmlns="http://www.w3.org/2000/svg"><rect fill="url(https://zqx-fill.vendor.example/p.svg#p)"/></svg>`,
	"stylesheet import": `<svg xmlns="http://www.w3.org/2000/svg"><style>@im<![CDATA[port "https://zqx-css.vendor.example/x.css";]]></style></svg>`,
}

func hostileMarker(doc string) string {
	idx := strings.Index(doc, "zqx")
	return doc[idx : idx+8]
}

func enableSVGDeliveryContract(cfg *config.Config) {
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.MaxShieldBytes = 1 << 20
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeBlock
	cfg.ResponseScanning.Enabled = false
}

func svgFixtureHandler(body string) http.HandlerFunc {
	return svgResponseHandler(http.StatusOK, http.Header{"Content-Type": {"image/svg+xml"}}, []byte(body))
}

func svgResponseHandler(status int, headers http.Header, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for key, values := range headers {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
}

func svgPartialHandler(body string) http.HandlerFunc {
	return svgResponseHandler(http.StatusPartialContent, http.Header{
		"Content-Type":  {"image/svg+xml"},
		"Content-Range": {fmt.Sprintf("bytes 0-%d/%d", len(body)-1, len(body)+100)},
	}, []byte(body))
}

func svgGzipHandler(t *testing.T, body string) http.HandlerFunc {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return svgResponseHandler(http.StatusOK, http.Header{"Content-Type": {"image/svg+xml"}, "Content-Encoding": {"gzip"}}, buf.Bytes())
}

type svgPathResult struct {
	delivered bool
	status    int
	body      []byte
}

var svgResponsePaths = []string{"fetch", "forward", "tls interception", "reverse"}

// runSVGPath drives one real transport with the contract baseline plus mod.
func runSVGPath(t *testing.T, path string, mod func(*config.Config), handler http.HandlerFunc) svgPathResult {
	t.Helper()
	configure := func(cfg *config.Config) {
		enableSVGDeliveryContract(cfg)
		if mod != nil {
			mod(cfg)
		}
	}
	readAll := func(response *http.Response) svgPathResult {
		t.Helper()
		defer func() { _ = response.Body.Close() }()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		return svgPathResult{delivered: response.StatusCode < 300, status: response.StatusCode, body: body}
	}

	switch path {
	case "fetch":
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
		configure(cfg)
		p := newTestProxyWithConfig(t, cfg)
		upstream := httptest.NewServer(handler)
		t.Cleanup(upstream.Close)
		w := httptest.NewRecorder()
		p.handleFetch(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil))
		var response FetchResponse
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode fetch response (status %d): %v", w.Code, err)
		}
		return svgPathResult{delivered: w.Code == http.StatusOK && !response.Blocked, status: w.Code, body: []byte(response.Content)}
	case "forward":
		upstream := httptest.NewServer(handler)
		t.Cleanup(upstream.Close)
		addr, cleanup := setupForwardProxy(t, configure)
		t.Cleanup(cleanup)
		response := doGet(t, proxyClient(addr), upstream.URL)
		return readAll(response)
	case "tls interception":
		upstream := httptest.NewTLSServer(handler)
		t.Cleanup(upstream.Close)
		cache, pool, cfg, sc, logger, m := testInterceptSetup(t)
		configure(cfg)
		p, err := New(cfg, logger, sc, m)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(p.Close)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		response := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, p)
		return readAll(response)
	case "reverse":
		cfg := reverseTestConfig()
		configure(cfg)
		server := reverseShieldConfiguredServer(t, cfg, handler, nil, audit.NewNop())
		return readAll(testGet(t, server.URL+"/page"))
	default:
		t.Fatalf("unknown path %q", path)
		return svgPathResult{}
	}
}

func assertSVGDelivered(t *testing.T, got svgPathResult, want string) {
	t.Helper()
	if !got.delivered || string(got.body) != want {
		t.Fatalf("SVG not delivered intact: status=%d body=%q", got.status, got.body)
	}
}

func assertSVGRefused(t *testing.T, got svgPathResult, forbidden string) {
	t.Helper()
	if got.delivered || bytes.Contains(got.body, []byte(forbidden)) {
		t.Fatalf("SVG was not refused: status=%d body=%q", got.status, got.body)
	}
}

// Positive control: every buffered HTTP response transport delivers an
// ordinary SVG, and delivers the REWRITTEN body when Shield changed it.
func TestSVGDeliveryContract_BenignTransportParity(t *testing.T) {
	for _, path := range svgResponsePaths {
		t.Run(path+"/plain", func(t *testing.T) {
			assertSVGDelivered(t, runSVGPath(t, path, nil, svgFixtureHandler(benignSVGFixture)), benignSVGFixture)
		})
		t.Run(path+"/rewritten", func(t *testing.T) {
			got := runSVGPath(t, path, nil, svgFixtureHandler(linkedSVGFixture))
			if !got.delivered || bytes.Contains(got.body, []byte("link.vendor.example")) || !bytes.Contains(got.body, []byte(`<rect id="kept"`)) {
				t.Fatalf("rewritten SVG: status=%d body=%q", got.status, got.body)
			}
		})
		t.Run(path+"/media policy disabled", func(t *testing.T) {
			disabled := false
			got := runSVGPath(t, path, func(cfg *config.Config) { cfg.MediaPolicy.Enabled = &disabled }, svgFixtureHandler(benignSVGFixture))
			assertSVGDelivered(t, got, benignSVGFixture)
		})
		t.Run(path+"/decodable gzip", func(t *testing.T) {
			assertSVGDelivered(t, runSVGPath(t, path, nil, svgGzipHandler(t, benignSVGFixture)), benignSVGFixture)
		})
	}
}

func TestSVGDeliveryContract_HostileFormsRefused(t *testing.T) {
	for _, path := range svgResponsePaths {
		for name, doc := range hostileSVGForms {
			t.Run(path+"/"+name, func(t *testing.T) {
				assertSVGRefused(t, runSVGPath(t, path, nil, svgFixtureHandler(doc)), hostileMarker(doc))
			})
		}
		t.Run(path+"/hostile inside gzip", func(t *testing.T) {
			assertSVGRefused(t, runSVGPath(t, path, nil, svgGzipHandler(t, hostileSVGFixture)), "alert(1)")
		})
	}
}

// Every state in which Shield did not validate the complete body is refused,
// including a benign document, because no proof exists for the bytes.
func TestSVGDeliveryContract_IncompleteValidationRefused(t *testing.T) {
	disabled := false
	cases := []struct {
		name    string
		mod     func(*config.Config)
		handler func(t *testing.T) http.HandlerFunc
	}{
		{"shield disabled", func(cfg *config.Config) { cfg.BrowserShield.Enabled = false }, func(*testing.T) http.HandlerFunc { return svgFixtureHandler(hostileSVGFixture) }},
		{"shield and media policy disabled", func(cfg *config.Config) {
			cfg.BrowserShield.Enabled = false
			cfg.MediaPolicy.Enabled = &disabled
		}, func(*testing.T) http.HandlerFunc { return svgFixtureHandler(hostileSVGFixture) }},
		{"shield exempt host", func(cfg *config.Config) { cfg.BrowserShield.ExemptDomains = []string{"127.0.0.1"} }, func(*testing.T) http.HandlerFunc { return svgFixtureHandler(hostileSVGFixture) }},
		{"partial 206", nil, func(*testing.T) http.HandlerFunc { return svgPartialHandler(hostileSVGFixture) }},
		{"partial 206 shield disabled", func(cfg *config.Config) { cfg.BrowserShield.Enabled = false }, func(*testing.T) http.HandlerFunc { return svgPartialHandler(hostileSVGFixture) }},
		{"oversize scan_head", func(cfg *config.Config) {
			cfg.BrowserShield.MaxShieldBytes = 40
			cfg.BrowserShield.OversizeAction = config.ShieldOversizeScanHead
		}, func(*testing.T) http.HandlerFunc { return svgFixtureHandler(hostileSVGFixture) }},
		{"oversize warn", func(cfg *config.Config) {
			cfg.BrowserShield.MaxShieldBytes = 40
			cfg.BrowserShield.OversizeAction = config.ShieldOversizeWarn
		}, func(*testing.T) http.HandlerFunc { return svgFixtureHandler(hostileSVGFixture) }},
		{"undecodable gzip", nil, func(*testing.T) http.HandlerFunc {
			return svgResponseHandler(http.StatusOK, http.Header{"Content-Type": {"image/svg+xml"}, "Content-Encoding": {"gzip"}}, []byte(hostileSVGFixture))
		}},
		{"unsupported encoding", nil, func(*testing.T) http.HandlerFunc {
			return svgResponseHandler(http.StatusOK, http.Header{"Content-Type": {"image/svg+xml"}, "Content-Encoding": {"compress"}}, []byte(hostileSVGFixture))
		}},
		// A client combines every Content-Type value and keeps the LAST valid
		// one (Fetch "extract a MIME type"), so both of these render as SVG
		// although the first value, the only one Header.Get returns, is inert.
		{"comma-combined content type", nil, func(*testing.T) http.HandlerFunc {
			return svgResponseHandler(http.StatusOK, http.Header{"Content-Type": {"text/plain, image/svg+xml"}}, []byte(hostileSVGFixture))
		}},
		{"duplicate content-type fields", nil, func(*testing.T) http.HandlerFunc {
			return svgResponseHandler(http.StatusOK, http.Header{"Content-Type": {"text/plain", "image/svg+xml"}}, []byte(hostileSVGFixture))
		}},
		{"malformed content-type parameters", func(cfg *config.Config) { cfg.BrowserShield.Enabled = false }, func(*testing.T) http.HandlerFunc {
			return svgResponseHandler(http.StatusOK, http.Header{"Content-Type": {"image/svg+xml; a=1; a=2"}}, []byte(hostileSVGFixture))
		}},
	}
	for _, path := range svgResponsePaths {
		for _, tc := range cases {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				assertSVGRefused(t, runSVGPath(t, path, tc.mod, tc.handler(t)), "alert(1)")
			})
		}
	}
}

// The reverse proxy streams declared image/* bodies without buffering. SVG is
// the one active image format and must never take that path; this is the
// regression guard for the streaming bypass, in each configuration that
// reaches the streaming branch.
func TestSVGDeliveryContract_ReverseNeverStreamsSVG(t *testing.T) {
	disabled := false
	for name, mod := range map[string]func(*config.Config){
		"shield on media on":   nil,
		"shield on media off":  func(cfg *config.Config) { cfg.MediaPolicy.Enabled = &disabled },
		"shield off media off": func(cfg *config.Config) { cfg.BrowserShield.Enabled = false; cfg.MediaPolicy.Enabled = &disabled },
		"shield off media on":  func(cfg *config.Config) { cfg.BrowserShield.Enabled = false },
	} {
		t.Run(name, func(t *testing.T) {
			assertSVGRefused(t, runSVGPath(t, "reverse", mod, svgFixtureHandler(hostileSVGFixture)), "alert(1)")
		})
	}
}

func TestSVGDeliveryContract_RequiresShieldEvenWhenMediaPolicyIsDisabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.BrowserShield.Enabled = false
	disabled := false
	cfg.MediaPolicy.Enabled = &disabled
	p := newTestProxyWithConfig(t, cfg)
	body, _, svgShielded, shieldBlocked := p.applyShield([]byte(benignSVGFixture), "image/svg+xml", "icons.vendor.example", nil, cfg, audit.LogContext{}, "127.0.0.1", "req-svg", TransportFetch, "action-svg")
	if shieldBlocked != nil || svgShielded {
		t.Fatalf("disabled shield result = blocked:%v proof:%t", shieldBlocked, svgShielded)
	}
	verdict := applyMediaPolicy(cfg, "image/svg+xml", body, mediaPolicyOptions{svgShielded: svgShielded})
	if !verdict.Blocked {
		t.Fatal("SVG without a complete shield proof was allowed")
	}
	// A caller that omits the option entirely gets the same refusal.
	if !applyMediaPolicy(cfg, "image/svg+xml", body).Blocked {
		t.Fatal("SVG admitted by a caller that never supplied the shield proof")
	}
}

// An empty SVG body (HEAD, 204, 304) carries nothing to activate and must not
// be refused as malformed when Shield is active.
func TestSVGDeliveryContract_EmptyBodyValidatedWhenShieldActive(t *testing.T) {
	cfg := config.Defaults()
	enableSVGDeliveryContract(cfg)
	p := newTestProxyWithConfig(t, cfg)
	body, _, svgShielded, blocked := p.applyShield(nil, "image/svg+xml", "icons.vendor.example", http.Header{"Content-Type": {"image/svg+xml"}}, cfg, audit.LogContext{}, "127.0.0.1", "req", TransportForward, "action")
	if blocked != nil || !svgShielded || len(body) != 0 {
		t.Fatalf("empty SVG: blocked=%+v proof=%t body=%q", blocked, svgShielded, body)
	}
}

func TestResponseHeadersDeclareSVG(t *testing.T) {
	t.Parallel()
	cases := []struct {
		values []string
		want   bool
	}{
		{nil, false},
		{[]string{"image/svg+xml"}, true},
		{[]string{"image/svg+xml; charset=utf-8"}, true},
		{[]string{"text/plain, image/svg+xml"}, true},
		{[]string{"text/plain", "image/svg+xml"}, true},
		{[]string{"image/svg+xml, */*"}, true},
		{[]string{"image/svg+xml, text/plain"}, false},
		{[]string{"image/svg+xml", "text/plain"}, false},
		{[]string{`text/plain; x="a, image/svg+xml"`}, false},
		{[]string{"image/png"}, false},
	}
	for _, tc := range cases {
		headers := http.Header{}
		for _, value := range tc.values {
			headers.Add("Content-Type", value)
		}
		if got := responseHeadersDeclareSVG(headers); got != tc.want {
			t.Errorf("responseHeadersDeclareSVG(%q) = %t, want %t", tc.values, got, tc.want)
		}
	}
}
