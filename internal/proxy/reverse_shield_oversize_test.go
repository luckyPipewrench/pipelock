// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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

const (
	oversizeShieldTail    = "<footer>tail-must-remain-byte-for-byte</footer></body></html>"
	oversizeShieldTestCap = 2048
)

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
func reverseShieldOversizeHarness(t *testing.T, strictness, action string, responseScanning bool) *http.Response {
	t.Helper()
	return reverseShieldResponseHarness(t, strictness, action, responseScanning, oversizeShieldTestCap, oversizeShieldPage(oversizeShieldTestCap*2))
}

func reverseShieldResponseHarness(t *testing.T, strictness, action string, responseScanning bool, maxShieldBytes int, page string) *http.Response {
	t.Helper()
	return reverseShieldResponseHarnessWithContentType(t, strictness, action, responseScanning, maxShieldBytes, "text/html", page)
}

func reverseShieldResponseHarnessWithContentType(t *testing.T, strictness, action string, responseScanning bool, maxShieldBytes int, contentType, page string) *http.Response {
	t.Helper()

	cfg := reverseTestConfig()
	cfg.ResponseScanning.Enabled = responseScanning
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = strictness
	cfg.BrowserShield.StripTrackingPixels = true
	cfg.BrowserShield.MaxShieldBytes = maxShieldBytes
	cfg.BrowserShield.OversizeAction = action

	upstream := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
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

func reverseShieldConfiguredServer(t *testing.T, cfg *config.Config, upstream http.HandlerFunc, configure func(*config.Config, *url.URL), logger *audit.Logger) *httptest.Server {
	t.Helper()
	upstreamSrv := httptest.NewServer(upstream)
	t.Cleanup(upstreamSrv.Close)
	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	if configure != nil {
		configure(cfg, upstreamURL)
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)
	if logger == nil {
		logger, _ = audit.New("json", "stdout", "", false, false)
		t.Cleanup(logger.Close)
	}
	handler := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, metrics.New(), killswitch.New(cfg), nil, shield.NewEngine(nil))
	proxySrv := httptest.NewServer(handler)
	t.Cleanup(proxySrv.Close)
	return proxySrv
}

// With response injection scanning disabled, Browser Shield must use its own
// ceiling. Crossing the reverse response-scanner ceiling must not select the
// scanner's block path or bypass the configured shield oversize action.
func TestReverseProxy_ShieldOnlyResponseAboveScannerCeilingHonorsOversizeAction(t *testing.T) {
	page := oversizeShieldPage(reverseProxyMaxBodyBytes + 4096)
	for _, tt := range []struct {
		name        string
		action      string
		wantStatus  int
		wantTracker bool
	}{
		{name: "block", action: config.ShieldOversizeBlock, wantStatus: http.StatusForbidden},
		{name: "warn", action: config.ShieldOversizeWarn, wantStatus: http.StatusOK, wantTracker: true},
		{name: "scan_head", action: config.ShieldOversizeScanHead, wantStatus: http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp := reverseShieldResponseHarness(t, config.ShieldStrictnessStandard, tt.action, false, oversizeShieldTestCap, page)
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if got := strings.Contains(string(body), "tracker.vendor.example"); got != tt.wantTracker {
				t.Errorf("tracking pixel present = %v, want %v", got, tt.wantTracker)
			}
			if tt.wantStatus == http.StatusOK && !strings.HasSuffix(string(body), oversizeShieldTail) {
				t.Fatal("oversize action truncated the streamed response tail")
			}
		})
	}
}

func TestReverseProxy_ShieldOnlyResponseAboveScannerCeilingPassesNonShieldableContent(t *testing.T) {
	body := strings.Repeat("plain response data\n", reverseProxyMaxBodyBytes/10)
	resp := reverseShieldResponseHarnessWithContentType(t, config.ShieldStrictnessStandard, config.ShieldOversizeBlock, false, oversizeShieldTestCap, "text/plain", body)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("non-shieldable response status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(got) != body {
		t.Fatal("non-shieldable response was modified or truncated")
	}
}

// The reverse transport used to skip Browser Shield entirely above
// max_shield_bytes: no block, no scan_head, no audit line, and the unscrubbed
// body reached the client. Every other transport honours oversize_action. This
// is the fail-closed direction.
func TestReverseProxy_ShieldOversize_BlockRefusesTheResponse(t *testing.T) {
	resp := reverseShieldOversizeHarness(t, config.ShieldStrictnessStandard, config.ShieldOversizeBlock, true)
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

func TestReverseProxy_ShieldOversize_BlockRefusesWhenResponseScanningDisabled(t *testing.T) {
	resp := reverseShieldOversizeHarness(t, config.ShieldStrictnessStandard, config.ShieldOversizeBlock, false)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("block with response scanning disabled returned status %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "tracker.vendor.example") {
		t.Fatal("blocked response leaked the upstream tracking pixel")
	}
}

// scan_head shields the first max_shield_bytes and passes the remainder
// through. The pixel sits in the head, so it must be gone while the tail
// survives intact.
func TestReverseProxy_ShieldOversize_ScanHeadScrubsTheHead(t *testing.T) {
	resp := reverseShieldOversizeHarness(t, config.ShieldStrictnessStandard, config.ShieldOversizeScanHead, true)
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
	resp := reverseShieldOversizeHarness(t, config.ShieldStrictnessMinimal, config.ShieldOversizeWarn, true)
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
	assertReverseIntentOutcomePair(t, receipts,
		"status=403",
		fmt.Sprintf("bytes=%d", len(page)),
		"reason=shield_oversize",
		"bytes_exact=true",
	)
}

func TestReceiptObservedOutcomePatternPreservesExactness(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		exact bool
	}{
		{name: "known content length", exact: true},
		{name: "streamed lower bound", exact: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := receiptObservedOutcomePattern("403", 2049, "shield_oversize", tc.exact)
			want := fmt.Sprintf("status=403 bytes=2049 reason=shield_oversize bytes_exact=%t", tc.exact)
			if got != want {
				t.Fatalf("outcome pattern = %q, want %q", got, want)
			}
		})
	}
}

func TestReverseProxy_ShieldOversize_WarnEmitsReceiptAndOutcome(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.FlightRecorder.RequireReceipts = true
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.MaxShieldBytes = oversizeShieldTestCap
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeWarn
	page := oversizeShieldPage(oversizeShieldTestCap * 2)
	proxySrv, dir, closeRec := reverseReceiptParitySetupWithShield(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, page)
	}, shield.NewEngine(nil))

	resp := testGet(t, proxySrv.URL+"/page")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("warn status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	waitForReceiptOrTimeout(t, dir)
	closeRec()
	receipts := extractReceiptsFromDir(t, dir)
	warn := findReceiptByLayer(t, receipts, "shield_oversize")
	if warn.ActionRecord.Verdict != config.ActionAllow {
		t.Errorf("warn receipt verdict = %q, want %q", warn.ActionRecord.Verdict, config.ActionAllow)
	}
	if warn.ActionRecord.Shield == nil || !warn.ActionRecord.Shield.Partial || warn.ActionRecord.Shield.ScannedBytes != 0 {
		t.Fatalf("warn receipt must disclose an unscanned partial body: %+v", warn.ActionRecord.Shield)
	}
	assertReverseIntentOutcomePair(t, receipts, "status=200", "reason=shield_oversize_warn")
}

func TestReverseProxy_ShieldOnlyUnknownLengthReceiptPreservesLowerBound(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.ResponseScanning.Enabled = false
	cfg.FlightRecorder.RequireReceipts = true
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.MaxShieldBytes = oversizeShieldTestCap
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeWarn
	page := oversizeShieldPage(oversizeShieldTestCap * 2)
	proxySrv, dir, closeRec := reverseReceiptParitySetupWithShield(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.WriteString(w, page)
	}, shield.NewEngine(nil))

	resp := testGet(t, proxySrv.URL+"/page")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	waitForReceiptOrTimeout(t, dir)
	closeRec()
	receipts := extractReceiptsFromDir(t, dir)
	warn := findReceiptByLayer(t, receipts, "shield_oversize")
	if got, want := warn.ActionRecord.Shield.BodyBytes, cfg.BrowserShield.MaxShieldBytes+1; got != want {
		t.Fatalf("unknown-length receipt body_bytes = %d, want observed lower bound %d", got, want)
	}
	if !strings.Contains(warn.ActionRecord.Pattern, "at least") {
		t.Fatalf("unknown-length reason presents lower bound as exact: %q", warn.ActionRecord.Pattern)
	}
}

func TestReverseProxy_ResponseScannerUnknownLengthOversizeUsesLowerBound(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.BrowserShield.Enabled = false
	page := strings.Repeat("ordinary response text ", reverseProxyMaxBodyBytes/10)
	proxySrv := reverseShieldConfiguredServer(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.WriteString(w, page)
	}, nil, nil)

	resp := testGet(t, proxySrv.URL+"/page")
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown-length oversize response status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if !strings.Contains(string(body), "is at least") {
		t.Fatalf("unknown-length block reason presents lower bound as exact: %s", body)
	}
}

// scan_head emits an allow receipt for the rewrite. Its signed summary must
// disclose that only the head was shielded; otherwise a receipt can describe a
// partial transformation as if it covered the entire response.
func TestReverseProxy_ShieldOversize_ScanHeadEmitsPartialReceipt(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.FlightRecorder.RequireReceipts = true
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
	assertReverseIntentOutcomePair(t, receipts, "status=200", "reason=shield_oversize_scan_head")
}

func TestReverseProxy_ShieldOversize_CleanScanHeadEmitsPartialReceipt(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = config.ShieldStrictnessMinimal
	cfg.BrowserShield.MaxShieldBytes = oversizeShieldTestCap
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeScanHead
	cfg.BrowserShield.StripExtensionProbing = false
	cfg.BrowserShield.StripHiddenTraps = false
	cfg.BrowserShield.StripTrackingPixels = false
	cfg.BrowserShield.InjectFingerprintShims = false

	page := "<html><body>" + strings.Repeat("ordinary text ", oversizeShieldTestCap) + oversizeShieldTail
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
		t.Fatalf("clean scan_head status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	waitForReceiptOrTimeout(t, dir)
	closeRec()
	receipts := extractReceiptsFromDir(t, dir)
	r := findReceiptByLayer(t, receipts, browserShieldLayer)
	if r.ActionRecord.Shield == nil {
		t.Fatal("clean scan_head receipt missing shield summary")
	}
	if got := r.ActionRecord.Shield.TotalRewrites; got != 0 {
		t.Errorf("clean scan_head total_rewrites = %d, want 0", got)
	}
	if !r.ActionRecord.Shield.Partial {
		t.Fatal("clean scan_head receipt must declare partial coverage")
	}
	if got, want := r.ActionRecord.Shield.BodyBytes, len(page); got != want {
		t.Errorf("clean scan_head body_bytes = %d, want %d", got, want)
	}
	if got, want := r.ActionRecord.Shield.ScannedBytes, cfg.BrowserShield.MaxShieldBytes; got != want {
		t.Errorf("clean scan_head scanned_bytes = %d, want %d", got, want)
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

// A reverse response that crosses the normal scan ceiling exercises the real
// size-exempt bounded reader and holds its memory reservation until Browser
// Shield finishes. The tracking pixel sits past both the normal scan ceiling
// and max_shield_bytes, proving the entire admitted body was rewritten.
func TestReverseProxy_ShieldSizeExempt_ScrubsBoundedWholeBody(t *testing.T) {
	const shieldCap = 2048

	page := "<html><body>" + strings.Repeat("safe document text ", reverseProxyMaxBodyBytes/19+1) +
		`<img src="https://tracker.vendor.example/p.gif" width="1" height="1"></body></html>`
	if len(page) <= reverseProxyMaxBodyBytes {
		t.Fatalf("test page size %d must exceed normal reverse scan ceiling %d", len(page), reverseProxyMaxBodyBytes)
	}

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, page)
	}))
	t.Cleanup(upstreamSrv.Close)

	upstreamURL, err := url.Parse(upstreamSrv.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	tests := []struct {
		name                    string
		responseScanningEnabled bool
		scanMaxBytes            int
		inflightMaxBytes        int
		wantStatus              int
		wantBodyContains        string
	}{
		{name: "response_scanning_enabled", responseScanningEnabled: true, scanMaxBytes: len(page) + 1024, wantStatus: http.StatusOK},
		{name: "shield_only", responseScanningEnabled: false, scanMaxBytes: len(page) + 1024, wantStatus: http.StatusOK},
		{name: "shield_only_exceeds_bounded_ceiling", responseScanningEnabled: false, scanMaxBytes: shieldCap * 2, wantStatus: http.StatusForbidden},
		{name: "shield_only_exceeds_inflight_budget", responseScanningEnabled: false, scanMaxBytes: len(page) + 1024, inflightMaxBytes: shieldCap, wantStatus: http.StatusForbidden, wantBodyContains: "response_scanning.size_exempt_scan_max_inflight_bytes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := reverseTestConfig()
			cfg.ResponseScanning.Enabled = tc.responseScanningEnabled
			cfg.BrowserShield.Enabled = true
			cfg.BrowserShield.Strictness = config.ShieldStrictnessStandard
			cfg.BrowserShield.StripTrackingPixels = true
			cfg.BrowserShield.MaxShieldBytes = shieldCap
			cfg.BrowserShield.OversizeAction = config.ShieldOversizeBlock
			cfg.ResponseScanning.SizeExemptDomains = []string{"127.0.0.1"}
			cfg.ResponseScanning.SizeExemptScanMaxBytes = tc.scanMaxBytes
			cfg.ResponseScanning.SizeExemptScanMaxInflightBytes = cfg.ResponseScanning.SizeExemptScanMaxBytes
			if tc.inflightMaxBytes > 0 {
				cfg.ResponseScanning.SizeExemptScanMaxInflightBytes = tc.inflightMaxBytes
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
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("bounded size-exempt response status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if tc.wantStatus == http.StatusOK && strings.Contains(string(body), "tracker.vendor.example") {
				t.Fatal("tracking pixel beyond the ordinary shield cap survived whole-body shielding")
			}
			if tc.wantStatus == http.StatusOK && !strings.Contains(string(body), "</body></html>") {
				t.Fatal("bounded whole-body shielding did not preserve the response tail")
			}
			if tc.wantBodyContains != "" && !strings.Contains(string(body), tc.wantBodyContains) {
				t.Fatalf("response body %q does not contain %q", body, tc.wantBodyContains)
			}
		})
	}
}

// Browser Shield is independent of response injection scanning. Disabling the
// latter must not make reverse responses bypass an explicitly enabled shield.
func TestReverseProxy_ShieldRunsWhenResponseScanningDisabled(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.ResponseScanning.Enabled = false
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = config.ShieldStrictnessStandard
	cfg.BrowserShield.StripTrackingPixels = true
	cfg.BrowserShield.MaxShieldBytes = 1 << 20

	page := "<html><body><img src=\"https://tracker.vendor.example/p.gif\" width=\"1\" height=\"1\"><p>small</p></body></html>"
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
		t.Fatalf("response status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if strings.Contains(string(body), "tracker.vendor.example") {
		t.Fatal("Browser Shield was skipped when response scanning was disabled")
	}
}

func TestReverseProxy_ShieldRunsForGenericMIMEWhenResponseScanningDisabled(t *testing.T) {
	page := "<html><body><img src=\"https://tracker.vendor.example/p.gif\" width=\"1\" height=\"1\"></body></html>"
	resp := reverseShieldResponseHarnessWithContentType(t, config.ShieldStrictnessStandard, config.ShieldOversizeBlock, false, 1<<20, "application/octet-stream", page)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("generic MIME response status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if strings.Contains(string(body), "tracker.vendor.example") {
		t.Fatal("generic MIME HTML bypassed Browser Shield")
	}
}

func TestReverseProxy_ShieldExemptHostPassesLargeResponseWhenResponseScanningDisabled(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.ResponseScanning.Enabled = false
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.MaxShieldBytes = oversizeShieldTestCap
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeBlock
	page := oversizeShieldPage(reverseProxyMaxBodyBytes + 4096)
	proxySrv := reverseShieldConfiguredServer(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, page)
	}, func(cfg *config.Config, upstreamURL *url.URL) {
		cfg.BrowserShield.ExemptDomains = []string{upstreamURL.Hostname()}
	}, nil)

	resp := testGet(t, proxySrv.URL+"/page")
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("shield-exempt response status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != page {
		t.Fatal("shield-exempt response was modified or truncated")
	}
}

func TestReverseProxy_ShieldOversize_ScanHeadEmitsAudit(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.MaxShieldBytes = oversizeShieldTestCap
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeScanHead
	page := oversizeShieldPage(oversizeShieldTestCap * 2)
	auditPath := t.TempDir() + "/audit.log"
	logger, err := audit.New("json", "file", auditPath, false, false)
	if err != nil {
		t.Fatalf("create audit logger: %v", err)
	}
	proxySrv := reverseShieldConfiguredServer(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, page)
	}, nil, logger)
	resp := testGet(t, proxySrv.URL+"/page")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	logger.Close()
	logBytes, err := os.ReadFile(filepath.Clean(auditPath))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !bytes.Contains(logBytes, []byte("shield_oversize_scan_head")) {
		t.Fatalf("scan_head audit event missing: %s", logBytes)
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
