// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// The shield oversize reason is emitted by three callers: the fetch handler,
// the absolute-URI forward path, and CONNECT interception. The fetch caller has
// its own receipt test; this covers the forward path, which can regress
// independently because it computes the body length and hostname itself.
func TestForwardProxy_ShieldOversize_BlocksWithTheExplainingReason(t *testing.T) {
	t.Parallel()

	body := "<html>" + strings.Repeat("x", 256) + "</html>"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(body))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "test-hash",
		Principal:  "test",
		Actor:      "test",
	})

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.DLP.Patterns = nil
	cfg.ResponseScanning.Enabled = false
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.MaxShieldBytes = 16
	cfg.BrowserShield.OversizeAction = config.ShieldOversizeBlock
	cfg.ForwardProxy.Enabled = true
	// The forward path records its evidence through the deferred outcome
	// receipt, which only emits when receipts are required. The fetch path
	// emits its block receipt unconditionally; that asymmetry is pre-existing
	// and is noted as adjacent work, not changed here.
	cfg.FlightRecorder.RequireReceipts = true
	cfg.ApplyDefaults()

	sc := scanner.MustNew(cfg)
	defer sc.Close()

	p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithRecorder(rec), WithReceiptEmitter(emitter))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	wantReason := shieldOversizeBlockReason(upstreamURL.Hostname(), len(body), cfg.BrowserShield.MaxShieldBytes)
	wantOutcomePattern := receiptOutcomePattern(strconv.Itoa(http.StatusForbidden), 0, "shield_oversize")

	proxySrv := newIPv4Server(t, p.buildHandler(p.buildMux()))
	t.Cleanup(proxySrv.Close)

	proxyURL, err := url.Parse(proxySrv.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL+"/oversize", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("forward request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on the forward path, got %d", resp.StatusCode)
	}
	respBody, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(respBody), "xxxxxxxxxxxxxxxx") {
		t.Fatal("forward block leaked the unshielded upstream body")
	}
	// Same explaining reason the fetch path returns: host, size, cap, remedies.
	if !strings.Contains(string(respBody), wantReason) {
		t.Errorf("forward block body = %s, want it to contain %q", respBody, wantReason)
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	var found bool
	trustedKey := hex.EncodeToString(pub)
	for _, entry := range readAllEntries(t, dir) {
		if entry.Type != receiptEntryType {
			continue
		}
		detailJSON, err := json.Marshal(entry.Detail)
		if err != nil {
			t.Fatalf("marshal receipt detail: %v", err)
		}
		recorded, err := receipt.Unmarshal(detailJSON)
		if err != nil {
			t.Fatalf("unmarshal receipt: %v", err)
		}
		// The forward transport records a terminal OUTCOME receipt rather than
		// the fetch path's block receipt, so match its exact composed pattern.
		// A substring match on "shield_oversize" alone would pass on any
		// receipt that merely mentions the layer, which proves nothing.
		//
		// Note what this pins down: the outcome receipt carries the SHORT
		// reason only. The detailed text naming the cap and its remedies goes
		// to the client but never into the evidence chain, so an auditor
		// reading receipts cannot see which limit fired. Recorded as adjacent
		// work rather than widened into this change.
		if recorded.ActionRecord.Pattern == wantOutcomePattern {
			if err := receipt.VerifyV1BytesWithKey(entry.RawDetail, trustedKey); err != nil {
				t.Fatalf("receipt authenticity verification failed: %v", err)
			}
			tampered := bytes.Replace(entry.RawDetail, []byte(upstreamURL.Hostname()), []byte("tampered.example"), 1)
			if bytes.Equal(tampered, entry.RawDetail) {
				t.Fatal("receipt fixture does not contain the upstream host needed for the tamper check")
			}
			if err := receipt.VerifyV1BytesWithKey(tampered, trustedKey); err == nil {
				t.Fatal("receipt authenticity verification accepted a modified target")
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("forward path emitted no outcome receipt with pattern %q", wantOutcomePattern)
	}
}
