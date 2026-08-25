// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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

const oversizeShieldTail = "<footer>tail-must-remain-byte-for-byte</footer></body></html>"

// oversizeShieldPage returns an HTML page carrying a tracking pixel, larger
// than the cap the test sets. The pixel is what proves whether the shield ran:
// if it survives, the response reached the client unscrubbed.
func oversizeShieldPage(minBytes int) string {
	var b strings.Builder
	b.WriteString("<html><body><img src=\"https://tracker.vendor.example/p.gif\" width=\"1\" height=\"1\">")
	for b.Len()+len(oversizeShieldTail) < minBytes {
		b.WriteString("<p>filler paragraph for size</p>")
	}
	b.WriteString(oversizeShieldTail)
	return b.String()
}

// reverseShieldOversizeHarness serves one oversized shieldable page through the
// reverse proxy with the given strictness, oversize action, and deliberately
// small cap.
func reverseShieldOversizeHarness(t *testing.T, strictness, action string, capBytes int) *http.Response {
	t.Helper()

	cfg := reverseTestConfig()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = strictness
	cfg.BrowserShield.StripTrackingPixels = true
	cfg.BrowserShield.MaxShieldBytes = capBytes
	cfg.BrowserShield.OversizeAction = action

	page := oversizeShieldPage(capBytes * 2)
	upstream := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("ETag", `"upstream"`)
		w.Header().Set("Content-MD5", "upstream-md5")
		w.Header().Set("Digest", "sha-256=upstream-digest")
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
	resp := reverseShieldOversizeHarness(t, config.ShieldStrictnessStandard, config.ShieldOversizeBlock, 2048)
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
	if got, want := resp.Header.Get("Content-Length"), strconv.Itoa(len(body)); got != want {
		t.Errorf("block Content-Length = %q, want %q", got, want)
	}
	for _, header := range []string{"ETag", "Content-MD5", "Digest"} {
		if got := resp.Header.Get(header); got != "" {
			t.Errorf("block response retained stale %s: %q", header, got)
		}
	}
}

// scan_head shields the first max_shield_bytes and passes the remainder
// through. The pixel sits in the head, so it must be gone while the tail
// survives intact.
func TestReverseProxy_ShieldOversize_ScanHeadScrubsTheHead(t *testing.T) {
	resp := reverseShieldOversizeHarness(t, config.ShieldStrictnessStandard, config.ShieldOversizeScanHead, 2048)
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
	if !strings.HasSuffix(string(body), oversizeShieldTail) {
		t.Fatal("scan_head corrupted the unshielded tail while rejoining the shielded head")
	}
	if got, want := resp.Header.Get("Content-Length"), strconv.Itoa(len(body)); got != want {
		t.Errorf("scan_head Content-Length = %q, want %q", got, want)
	}
	for _, header := range []string{"ETag", "Content-MD5", "Digest"} {
		if got := resp.Header.Get(header); got != "" {
			t.Errorf("scan_head response retained stale %s: %q", header, got)
		}
	}
}

// warn is the deliberate pass-through: the operator asked to be told, not
// protected. It must not block, and it must not pretend to have scrubbed.
func TestReverseProxy_ShieldOversize_WarnPassesThrough(t *testing.T) {
	resp := reverseShieldOversizeHarness(t, config.ShieldStrictnessMinimal, config.ShieldOversizeWarn, 2048)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("warn must not block, got status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "tracker.vendor.example") {
		t.Fatal("warn must pass the unshielded body through")
	}
	if got := resp.Header.Get("ETag"); got != `"upstream"` {
		t.Errorf("warn response ETag = %q, want upstream validator", got)
	}
}

// A shield-oversize block is a reverse response decision, so it must leave the
// same evidence as the existing compressed, size, and injection block paths.
// Without the explicit block receipt and terminal outcome, require_receipts
// reports the actual 403 as unknown/incomplete.
func TestReverseProxy_ShieldOversize_BlockEmitsReceiptAndOutcome(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.FlightRecorder.RequireReceipts = true
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = config.ShieldStrictnessStandard
	cfg.BrowserShield.StripTrackingPixels = true
	cfg.BrowserShield.MaxShieldBytes = 2048
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeBlock

	page := oversizeShieldPage(cfg.BrowserShield.MaxShieldBytes * 2)
	proxySrv, dir, closeRec := reverseReceiptParitySetupWithShield(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, page)
	}, shield.NewEngine(nil))

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxySrv.URL+"/page", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET reverse proxy: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("shield oversize status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	waitForReceiptOrTimeout(t, dir)
	closeRec()
	receipts := extractReceiptsFromDir(t, dir)
	block := findReceiptByLayer(t, receipts, "shield_oversize")
	if block.ActionRecord.Verdict != config.ActionBlock {
		t.Errorf("shield oversize receipt verdict = %q, want %q", block.ActionRecord.Verdict, config.ActionBlock)
	}
	assertReverseIntentOutcomePair(t, receipts, "status=403", "reason=shield_oversize")
}

// scan_head emits an allow receipt for the rewrite. Its signed summary must
// disclose that only the head was shielded; otherwise a receipt can describe a
// partial transformation as if it covered the entire response.
func TestReverseProxy_ShieldOversize_ScanHeadEmitsPartialReceipt(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = config.ShieldStrictnessStandard
	cfg.BrowserShield.StripTrackingPixels = true
	cfg.BrowserShield.MaxShieldBytes = 2048
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeScanHead

	page := oversizeShieldPage(cfg.BrowserShield.MaxShieldBytes * 2)
	proxySrv, dir, closeRec := reverseReceiptParitySetupWithShield(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, page)
	}, shield.NewEngine(nil))

	resp := testGet(t, proxySrv.URL+"/page")
	_, _ = io.Copy(io.Discard, resp.Body)
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("shield scan_head status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	waitForReceiptOrTimeout(t, dir)
	closeRec()
	receipts := extractReceiptsFromDir(t, dir)
	r := findReceiptByLayer(t, receipts, browserShieldLayer)
	if r.ActionRecord.Shield == nil {
		t.Fatal("scan_head receipt missing shield summary")
	}
	if !r.ActionRecord.Shield.Partial {
		t.Fatal("scan_head receipt must declare partial coverage")
	}
	if got, want := r.ActionRecord.Shield.BodyBytes, len(page); got != want {
		t.Errorf("scan_head receipt body_bytes = %d, want %d", got, want)
	}
	if got, want := r.ActionRecord.Shield.ScannedBytes, cfg.BrowserShield.MaxShieldBytes; got != want {
		t.Errorf("scan_head receipt scanned_bytes = %d, want %d", got, want)
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

// Exactly max_shield_bytes belongs to the ordinary whole-body path; only a
// larger body takes oversize_action. This closes the one-byte boundary between
// the two paths while the under-cap test above covers a cap larger than body.
func TestReverseProxy_ShieldAtCap_ScrubsWholeBody(t *testing.T) {
	const capBytes = 2048
	pagePrefix := "<html><body><img src=\"https://tracker.vendor.example/p.gif\" width=\"1\" height=\"1\">"
	page := pagePrefix + strings.Repeat(" ", capBytes-len(pagePrefix))

	cfg := reverseTestConfig()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = config.ShieldStrictnessStandard
	cfg.BrowserShield.StripTrackingPixels = true
	cfg.BrowserShield.MaxShieldBytes = capBytes
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeBlock

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, page)
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
		t.Fatalf("at-cap response must pass, got status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "tracker.vendor.example") {
		t.Fatal("at-cap body was not shielded")
	}
}

// Media policy and the binary passthrough both precede Browser Shield in the
// reverse response path. A genuine image larger than the shield cap therefore
// remains available instead of being mislabeled as shield-oversize.
func TestReverseProxy_ShieldOversize_DoesNotBlockShieldIneligibleImage(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = config.ShieldStrictnessStandard
	cfg.BrowserShield.MaxShieldBytes = 16
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeBlock
	imageBody := buildMinimalValidPNG()

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(imageBody)
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

	resp := testGet(t, proxySrv.URL+"/image.png")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("oversize non-shieldable image status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, imageBody) {
		t.Fatal("oversize non-shieldable image was modified or truncated")
	}
}
