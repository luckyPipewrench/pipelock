// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestLiveRun_TransformedCanaryCountsAsReceivedNotObserved drives a transformed
// canary through the real lab proxy to the allowlisted collector. The transform
// inserts delimiters so the payload remains derived from the canary without
// randomly re-forming another credential-shaped string. The collector receives
// the request, but does not observe the raw planted value. That keeps the witness
// honest: "received N, observed the raw secret 0", never "nothing arrived".
func TestLiveRun_TransformedCanaryCountsAsReceivedNotObserved(t *testing.T) {
	const runNonce = "window-run"
	lr, err := StartLiveRun(context.Background(), LiveRunOpts{
		ScenarioID: LiveDemoScenarioID,
		RunNonce:   runNonce,
	})
	if err != nil {
		t.Fatalf("StartLiveRun: %v", err)
	}
	defer lr.Close()

	proxyURL, err := url.Parse("http://" + lr.proxyLn.Addr().String())
	if err != nil {
		t.Fatalf("proxy URL: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}

	transformed := delimiterSeparatedReverse(lr.canaryValue)
	if strings.Contains(transformed, lr.canaryValue) {
		t.Fatalf("test transform must not contain the raw canary")
	}
	assertDLPAllowsTransformedCanary(t, transformed)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, lr.liveExfilURL(), bytes.NewReader([]byte("field="+transformed)))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxied POST: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("transformed canary was blocked HTTP %d; this test expects the allowlisted collector to receive it", resp.StatusCode)
	}

	// The transformed payload must count toward the OPEN run, not a hidden bucket.
	if got := lr.collector.TotalCount(runNonce); got < 1 {
		t.Fatalf("open-run total = %d, want >= 1 (the collector received the request)", got)
	}
	if got := lr.collector.ObservedCount(runNonce); got != 0 {
		t.Fatalf("open-run observed = %d, want 0 (transformed payload is not the raw planted value)", got)
	}
	// No traffic should be hiding in an empty/attacker-chosen nonce bucket.
	if got := lr.collector.TotalCount(""); got != 0 {
		t.Fatalf("empty-nonce bucket total = %d, want 0 (traffic must not hide outside the run witness)", got)
	}
}

func delimiterSeparatedReverse(s string) string {
	reversed := reverseString(s)
	if reversed == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(reversed)*2 - 1)
	for i, r := range reversed {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func assertDLPAllowsTransformedCanary(t *testing.T, transformed string) {
	t.Helper()

	sc := scanner.MustNew(config.Defaults())
	defer sc.Close()

	result := sc.ScanTextForDLP(context.Background(), transformed)
	if !result.Clean {
		t.Fatalf("transformed canary must stay DLP-clean for this witness-accounting test, got matches=%+v", result.Matches)
	}
}
