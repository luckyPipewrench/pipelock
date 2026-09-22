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
	oversizeShieldTail                  = "<footer>tail-must-remain-byte-for-byte</footer></body></html>"
	oversizeShieldTestCap               = 2048
	oversizeShieldResponseScanTestLimit = 16 * 1024
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
	return reverseShieldResponseHarnessWithHeaders(t, strictness, action, responseScanning, maxShieldBytes, http.Header{"Content-Type": {contentType}}, page)
}

func reverseShieldResponseHarnessWithHeaders(t *testing.T, strictness, action string, responseScanning bool, maxShieldBytes int, responseHeaders http.Header, page string) *http.Response {
	t.Helper()

	cfg := reverseTestConfig()
	cfg.ResponseScanning.Enabled = responseScanning
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = strictness
	cfg.BrowserShield.StripTrackingPixels = true
	cfg.BrowserShield.MaxShieldBytes = maxShieldBytes
	cfg.BrowserShield.OversizeAction = action

	upstream := func(w http.ResponseWriter, _ *http.Request) {
		for name, values := range responseHeaders {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
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

// The immutable core floor is still active when response_scanning is disabled,
// so a response larger than its whole-body scan ceiling is denied regardless of
// Browser Shield's oversize action. The clean under-ceiling control proves this
// does not turn ordinary shielded traffic into a blanket block.
func TestReverseProxy_CoreFloorResponseAboveScannerCeilingBlocksDespiteShieldOversizeAction(t *testing.T) {
	page := oversizeShieldPage(reverseProxyMaxBodyBytes + 4096)
	for _, action := range []string{config.ShieldOversizeBlock, config.ShieldOversizeWarn, config.ShieldOversizeScanHead} {
		t.Run(action, func(t *testing.T) {
			resp := reverseShieldResponseHarness(t, config.ShieldStrictnessStandard, action, false, oversizeShieldTestCap, page)
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if strings.Contains(string(body), "tracker.vendor.example") {
				t.Fatal("blocked response leaked the upstream body")
			}
		})
	}

	t.Run("clean response below scan ceiling still flows", func(t *testing.T) {
		clean := oversizeShieldPage(oversizeShieldTestCap * 2)
		resp := reverseShieldResponseHarness(t, config.ShieldStrictnessStandard, config.ShieldOversizeScanHead, false, oversizeShieldTestCap, clean)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("under-ceiling clean response status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if !strings.HasSuffix(string(body), oversizeShieldTail) {
			t.Fatal("under-ceiling clean response did not preserve its tail")
		}
	})
}

// Non-shieldable text still belongs to the core response floor. The positive
// control separates the necessary large-response block from a text/plain
// regression for ordinary responses.
func TestReverseProxy_CoreFloorResponseAboveScannerCeilingBlocksNonShieldableContent(t *testing.T) {
	body := strings.Repeat("plain response data\n", reverseProxyMaxBodyBytes/10)
	resp := reverseShieldResponseHarnessWithContentType(t, config.ShieldStrictnessStandard, config.ShieldOversizeBlock, false, oversizeShieldTestCap, "text/plain", body)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-shieldable response status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read response: %v", err)
	}

	clean := strings.Repeat("plain response data\n", oversizeShieldTestCap/10)
	cleanResp := reverseShieldResponseHarnessWithContentType(t, config.ShieldStrictnessStandard, config.ShieldOversizeBlock, false, oversizeShieldTestCap, "text/plain", clean)
	defer func() { _ = cleanResp.Body.Close() }()
	if cleanResp.StatusCode != http.StatusOK {
		t.Fatalf("under-ceiling non-shieldable response status = %d, want %d", cleanResp.StatusCode, http.StatusOK)
	}
	got, err := io.ReadAll(cleanResp.Body)
	if err != nil {
		t.Fatalf("read under-ceiling response: %v", err)
	}
	if string(got) != clean {
		t.Fatal("under-ceiling non-shieldable response was modified or truncated")
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

	// The property is evidence integrity, not a particular ceiling: an
	// unknown-length response must never have its receipt overstate what was
	// actually read, and the reason must present the number as a lower bound.
	//
	// This formerly pinned the shield ceiling plus one, which was a proxy for
	// "the read stopped at the shield ceiling". It no longer does: the core
	// floor consumes the body regardless of the optional layer, so the recorded
	// figure is the larger amount genuinely observed. Asserting the bound
	// rather than the old ceiling keeps the invariant while letting the read
	// length follow the code.
	got := warn.ActionRecord.Shield.BodyBytes
	if got != len(page) {
		t.Fatalf("receipt body_bytes = %d, want the %d bytes actually read", got, len(page))
	}
	// The floor read the whole body, so the figure is exact and the reason must
	// not hedge it. The lower-bound wording belongs to a body the proxy could
	// not finish reading, which no longer reaches this path: such a body blocks
	// at the response scan ceiling first.
	if strings.Contains(warn.ActionRecord.Pattern, "at least") {
		t.Fatalf("a fully-read body reported its exact size as a lower bound: %q", warn.ActionRecord.Pattern)
	}
}

// TestReverseProxy_ShieldOversizeAboveScanCeilingBlocksBeforeShield pins where
// an over-ceiling body is now decided.
//
// This case formerly asserted that a body larger than the proxy would read
// produced a shield_oversize receipt whose figure was presented as a lower
// bound. With the floor live, such a body never reaches shield handling: it
// blocks at the response scan ceiling first, because an unreadable body cannot
// be inspected and the floor fails closed. The evidence contract is preserved
// by there being no under-stated shield figure to emit at all.
func TestReverseProxy_ShieldOversizeAboveScanCeilingBlocksBeforeShield(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.ResponseScanning.Enabled = false
	cfg.FlightRecorder.RequireReceipts = true
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.MaxShieldBytes = oversizeShieldTestCap
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeWarn
	page := oversizeShieldPage(reverseProxyMaxBodyBytes + 4096)
	proxySrv, dir, closeRec := reverseReceiptParitySetupWithShield(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.WriteString(w, page)
	}, shield.NewEngine(nil))

	resp := testGet(t, proxySrv.URL+"/page")
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	waitForReceiptOrTimeout(t, dir)
	closeRec()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a body above the scan ceiling must fail closed, got %d body=%q", resp.StatusCode, string(body))
	}
	for _, r := range extractReceiptsFromDir(t, dir) {
		if r.ActionRecord.Layer == "shield_oversize" {
			t.Fatalf("shield_oversize receipt emitted for a body the floor refused before shield handling")
		}
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

	page := "<html><body>" + strings.Repeat("safe document text ", oversizeShieldResponseScanTestLimit/19+1) +
		`<img src="https://tracker.vendor.example/p.gif" width="1" height="1"></body></html>`
	if len(page) <= oversizeShieldResponseScanTestLimit {
		t.Fatalf("test page size %d must exceed test response scan ceiling %d", len(page), oversizeShieldResponseScanTestLimit)
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
		useProductionLimit      bool
		oversizeAction          string
		wantStatus              int
		wantTracker             bool
		wantBodyContains        string
	}{
		{name: "response_scanning_enabled", responseScanningEnabled: true, scanMaxBytes: len(page) + 1024, wantStatus: http.StatusOK},
		{name: "response_scanning_exceeds_test_bounded_ceiling", responseScanningEnabled: true, scanMaxBytes: oversizeShieldResponseScanTestLimit / 2, oversizeAction: config.ShieldOversizeWarn, wantStatus: http.StatusForbidden, wantBodyContains: "response_scanning.size_exempt_scan_max_bytes"},
		{name: "response_scanning_same_body_below_production_ceiling", responseScanningEnabled: true, scanMaxBytes: oversizeShieldResponseScanTestLimit / 2, useProductionLimit: true, oversizeAction: config.ShieldOversizeWarn, wantStatus: http.StatusOK, wantTracker: true},
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
			if tc.oversizeAction != "" {
				cfg.BrowserShield.OversizeAction = tc.oversizeAction
			}
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
			wantResponseBodyLimit := reverseProxyMaxBodyBytes
			if !tc.useProductionLimit {
				handler.responseBodyLimit = oversizeShieldResponseScanTestLimit
				wantResponseBodyLimit = oversizeShieldResponseScanTestLimit
			}
			if got := handler.responseScanBodyLimit(); got != wantResponseBodyLimit {
				t.Fatalf("response scan ceiling = %d, want %d", got, wantResponseBodyLimit)
			}
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
			trackerPresent := strings.Contains(string(body), "tracker.vendor.example")
			if tc.wantStatus == http.StatusOK && trackerPresent != tc.wantTracker {
				t.Fatalf("tracking pixel present = %v, want %v", trackerPresent, tc.wantTracker)
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
	// Formerly streamed a body larger than the scan ceiling because the
	// optional layer was off and the host was shield-exempt. The core floor
	// still requires a scan, so the scan ceiling applies and this oversize
	// body is blocked.
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
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("oversize shield-exempt body must hit the scan ceiling, got status %d body=%q", resp.StatusCode, string(body))
	}
}

func TestReverseProxy_ShieldExemptHostPassesUnderCapResponseWhenResponseScanningDisabled(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.ResponseScanning.Enabled = false
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.MaxShieldBytes = oversizeShieldTestCap
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeBlock
	page := oversizeShieldPage(oversizeShieldTestCap)
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
		t.Fatalf("under-cap shield-exempt response status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != page {
		t.Fatal("under-cap shield-exempt response was modified or truncated")
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

// oversizeShieldPageWithInjection builds an oversized shieldable page whose
// core prompt-injection phrase begins after the shield cap. A head-only scan
// cannot find the phrase; a whole-body core-floor scan must.
func oversizeShieldPageWithInjection(minBytes int) string {
	var b strings.Builder
	b.WriteString("<html><body>")
	for b.Len()+len(corePayloadForFloor)+len(oversizeShieldTail) < minBytes {
		b.WriteString("<p>filler paragraph for size</p>")
	}
	b.WriteString("<p>" + corePayloadForFloor + "</p>")
	b.WriteString(oversizeShieldTail)
	return b.String()
}

func TestReverseProxy_ShieldOversizeTailCoreInjectionBlocks(t *testing.T) {
	for _, action := range []string{config.ShieldOversizeScanHead, config.ShieldOversizeWarn} {
		t.Run(action, func(t *testing.T) {
			cfg := reverseTestConfig()
			cfg.ResponseScanning.Enabled = false
			cfg.BrowserShield.Enabled = true
			cfg.BrowserShield.MaxShieldBytes = oversizeShieldTestCap
			cfg.BrowserShield.OversizeAction = action
			page := oversizeShieldPageWithInjection(oversizeShieldTestCap * 2)
			if offset := strings.Index(page, corePayloadForFloor); offset <= cfg.BrowserShield.MaxShieldBytes {
				t.Fatalf("core payload offset = %d, must exceed shield cap %d", offset, cfg.BrowserShield.MaxShieldBytes)
			}

			// Shield must be active for this host. An exempt host would not prove
			// the shield-capped response path that used to leave this tail unseen.
			proxySrv := reverseShieldConfiguredServer(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(w, page)
			}, nil, nil)

			resp := testGet(t, proxySrv.URL+"/page")
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("tail core injection status = %d, want %d", resp.StatusCode, http.StatusForbidden)
			}
			if strings.Contains(string(body), corePayloadForFloor) {
				t.Fatalf("tail core injection reached the client with action=%s", action)
			}
		})
	}
}
