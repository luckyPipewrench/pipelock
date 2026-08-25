// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/shield"
)

// oversizeShieldPage returns an HTML page carrying a tracking pixel, larger
// than the cap the test sets. The pixel is what proves whether the shield ran:
// if it survives, the response reached the client unscrubbed.
func oversizeShieldPage(minBytes int) string {
	var b strings.Builder
	b.WriteString("<html><body><img src=\"https://tracker.vendor.example/p.gif\" width=\"1\" height=\"1\">")
	for b.Len() < minBytes {
		b.WriteString("<p>filler paragraph for size</p>")
	}
	b.WriteString("</body></html>")
	return b.String()
}

// reverseShieldOversizeHarness serves one oversized shieldable page through the
// reverse proxy with the given oversize action and a deliberately small cap.
func reverseShieldOversizeHarness(t *testing.T, action string, capBytes int) *http.Response {
	t.Helper()

	cfg := reverseTestConfig()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = config.ShieldStrictnessStandard
	cfg.BrowserShield.StripTrackingPixels = true
	cfg.BrowserShield.MaxShieldBytes = capBytes
	cfg.BrowserShield.OversizeAction = action

	page := oversizeShieldPage(capBytes * 2)
	upstream := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(page))
	}

	upstreamSrv := httptest.NewServer(http.HandlerFunc(upstream))
	t.Cleanup(upstreamSrv.Close)

	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	logger, _ := audit.New("json", "stdout", "", false, false)
	t.Cleanup(logger.Close)

	handler := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, metrics.New(), killswitch.New(cfg), nil, shield.NewEngine(nil))
	proxySrv := httptest.NewServer(handler)
	t.Cleanup(proxySrv.Close)

	return testGet(t, proxySrv.URL+"/page")
}

// The reverse transport used to skip Browser Shield entirely above
// max_shield_bytes: no block, no scan_head, no audit line, and the unscrubbed
// body reached the client. Every other transport honours oversize_action. This
// is the fail-closed direction.
func TestReverseProxy_ShieldOversize_BlockRefusesTheResponse(t *testing.T) {
	resp := reverseShieldOversizeHarness(t, config.ShieldOversizeBlock, 2048)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("oversize response must be blocked, got status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "tracker.vendor.example") {
		t.Fatal("blocked response leaked the unscrubbed upstream body")
	}
	// The block has to name the cap and its remedies, not just say "blocked".
	for _, want := range []string{
		"browser_shield.max_shield_bytes",
		"browser_shield.oversize_action",
		"browser_shield.exempt_domains",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("block reason does not name %q: %s", want, body)
		}
	}
}

// scan_head shields the first max_shield_bytes and passes the remainder
// through. The pixel sits in the head, so it must be gone while the tail
// survives intact.
func TestReverseProxy_ShieldOversize_ScanHeadScrubsTheHead(t *testing.T) {
	resp := reverseShieldOversizeHarness(t, config.ShieldOversizeScanHead, 2048)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scan_head must not block, got status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "tracker.vendor.example") {
		t.Fatal("scan_head left the tracking pixel in the shielded head")
	}
	if !strings.Contains(string(body), "filler paragraph") {
		t.Fatal("scan_head dropped the unshielded tail instead of passing it through")
	}
}

// warn is the deliberate pass-through: the operator asked to be told, not
// protected. It must not block, and it must not pretend to have scrubbed.
func TestReverseProxy_ShieldOversize_WarnPassesThrough(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.BrowserShield.Strictness = config.ShieldStrictnessMinimal
	if cfg.BrowserShield.Strictness != config.ShieldStrictnessMinimal {
		t.Skip("warn requires minimal strictness")
	}

	resp := reverseShieldOversizeHarness(t, config.ShieldOversizeWarn, 2048)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("warn must not block, got status %d", resp.StatusCode)
	}
}

// A body at or under the cap keeps the ordinary whole-body shield path, so the
// oversize branch must not capture the normal case.
func TestReverseProxy_ShieldUnderCap_ScrubsWholeBody(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = config.ShieldStrictnessStandard
	cfg.BrowserShield.StripTrackingPixels = true
	cfg.BrowserShield.MaxShieldBytes = 1 << 20
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeBlock

	page := "<html><body><img src=\"https://tracker.vendor.example/p.gif\" width=\"1\" height=\"1\"><p>small</p></body></html>"
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(page))
	}))
	t.Cleanup(upstreamSrv.Close)

	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	logger, _ := audit.New("json", "stdout", "", false, false)
	t.Cleanup(logger.Close)

	handler := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, metrics.New(), killswitch.New(cfg), nil, shield.NewEngine(nil))
	proxySrv := httptest.NewServer(handler)
	t.Cleanup(proxySrv.Close)

	resp := testGet(t, proxySrv.URL+"/page")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("under-cap response must pass, got status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "tracker.vendor.example") {
		t.Fatal("under-cap body was not shielded")
	}
}
