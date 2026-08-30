// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func entropyWarnRoute() config.RequestBodyEntropyWarnRoute {
	return config.RequestBodyEntropyWarnRoute{
		Host: "upload.vendor.example", Path: "/v1/files", ContentTypes: []string{"application/octet-stream"},
		Methods: []string{"POST"}, Reason: "encrypted customer archive", Owner: "storage team", Expires: "2099-12-31",
	}
}

func TestMatchBodyEntropyWarnRouteIsExactHTTPSAndExpiresAtRuntime(t *testing.T) {
	base := BodyScanRequest{
		Scheme: "https", Host: "upload.vendor.example", Path: "/v1/files", EntropyRoutePath: "/v1/files", Method: "POST",
		ContentType: "application/octet-stream; version=1", ContentEntropyAction: config.ActionBlock,
		ContentEntropyWarnRoutes: []config.RequestBodyEntropyWarnRoute{entropyWarnRoute()},
	}
	if got := matchBodyEntropyWarnRoute(base, time.Date(2099, 12, 31, 12, 0, 0, 0, time.UTC)); got == nil {
		t.Fatal("exact route did not match on its expiry date")
	}
	for _, mutate := range []func(*BodyScanRequest){
		func(r *BodyScanRequest) { r.Scheme = "http" },
		func(r *BodyScanRequest) { r.Host = "other.vendor.example" },
		func(r *BodyScanRequest) { r.EntropyRoutePath = "/v1/files/child" },
		func(r *BodyScanRequest) { r.EntropyRoutePath = "/v1%2ffiles" },
		func(r *BodyScanRequest) { r.EntropyRoutePath = "" },
		func(r *BodyScanRequest) { r.Method = "PUT" },
		func(r *BodyScanRequest) { r.ContentType = "image/png" },
		func(r *BodyScanRequest) { r.ContentType = "" },
	} {
		req := base
		mutate(&req)
		if got := matchBodyEntropyWarnRoute(req, time.Date(2099, 12, 31, 12, 0, 0, 0, time.UTC)); got != nil {
			t.Fatalf("nearby route unexpectedly matched: %+v", req)
		}
	}
	if got := matchBodyEntropyWarnRoute(base, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)); got != nil {
		t.Fatal("expired route still matched in a long-running process")
	}
}

func TestMatchBodyEntropyWarnRouteRejectsEncodedTopologyBeforeDecode(t *testing.T) {
	u, err := url.Parse("https://upload.vendor.example/v1%2ffiles")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if u.Path != "/v1/files" || u.EscapedPath() != "/v1%2ffiles" {
		t.Fatalf("unexpected URL parser precondition: Path=%q EscapedPath=%q", u.Path, u.EscapedPath())
	}
	req := BodyScanRequest{
		Scheme: u.Scheme, Host: u.Hostname(), Path: u.Path, EntropyRoutePath: u.EscapedPath(), Method: http.MethodPost,
		ContentType: "application/octet-stream", ContentEntropyAction: config.ActionBlock,
		ContentEntropyWarnRoutes: []config.RequestBodyEntropyWarnRoute{entropyWarnRoute()},
	}
	if got := matchBodyEntropyWarnRoute(req, time.Date(2099, 12, 31, 12, 0, 0, 0, time.UTC)); got != nil {
		t.Fatalf("encoded topology change matched decoded exact route: %+v", got)
	}
}

func TestScanRequestBodyEntropyWarnRoutePreservesFindingAndProvenance(t *testing.T) {
	cfg := testScannerConfig()
	cfg.RequestBodyScanning.ContentEntropyEnabled = true
	cfg.RequestBodyScanning.ContentEntropyAction = config.ActionBlock
	cfg.RequestBodyScanning.ContentEntropyThreshold = 4.5
	cfg.RequestBodyScanning.ContentEntropyMinLength = 32
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	req := BodyScanRequest{
		Body: strings.NewReader(opaqueHighEntropyBodyValue()), Scheme: "https", Method: "POST",
		ContentType: "application/octet-stream", MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes, Scanner: sc,
		Host: "upload.vendor.example", Path: "/v1/files", Target: "https://upload.vendor.example/v1/files",
		EntropyRoutePath: "/v1/files",
		Action:           config.ActionBlock, ContentEntropyEnabled: true, ContentEntropyAction: config.ActionBlock,
		ContentEntropyThreshold: 4.5, ContentEntropyMinLength: 32,
		ContentEntropyWarnRoutes: []config.RequestBodyEntropyWarnRoute{entropyWarnRoute()},
	}
	_, result := scanRequestBody(context.Background(), req)
	if result.Clean || result.EntropyFinding == nil || result.EntropyWarnRoute == nil {
		t.Fatalf("expected visible entropy warning with route provenance, got %+v", result)
	}
	if result.Action != config.ActionWarn || result.EntropyAction != config.ActionWarn {
		t.Fatalf("actions = %q/%q, want warn/warn", result.Action, result.EntropyAction)
	}
	for _, want := range []string{"encrypted customer archive", "storage team", "2099-12-31"} {
		if !strings.Contains(result.Reason, want) {
			t.Fatalf("reason %q does not contain %q", result.Reason, want)
		}
	}

	req.EntropyRoutePath = "/v1/other"
	req.Body = strings.NewReader(opaqueHighEntropyBodyValue())
	_, blocked := scanRequestBody(context.Background(), req)
	if blocked.Action != config.ActionBlock || blocked.EntropyWarnRoute != nil {
		t.Fatalf("non-matching route did not retain entropy block: %+v", blocked)
	}

	req.EntropyRoutePath = "/v1/files"
	req.Body = strings.NewReader(fakeAPIKey() + opaqueHighEntropyBodyValue())
	_, withDLP := scanRequestBody(context.Background(), req)
	if len(withDLP.DLPMatches) == 0 || withDLP.Action != config.ActionBlock {
		t.Fatalf("route warning hid a stronger DLP finding: %+v", withDLP)
	}
}

func TestBodyEntropyReasonIncludesRouteProvenance(t *testing.T) {
	result := BodyScanResult{
		EntropyFinding: &ContentEntropyFinding{Entropy: 7.5, Threshold: 4.5},
		EntropyWarnRoute: &BodyEntropyWarnRouteMatch{
			Reason:  "encrypted customer archive",
			Owner:   "storage team",
			Expires: "2099-12-31",
		},
	}
	got := bodyEntropyReason(result)
	for _, want := range []string{"route warning override", "encrypted customer archive", "storage team", "2099-12-31"} {
		if !strings.Contains(got, want) {
			t.Fatalf("reason %q does not contain %q", got, want)
		}
	}
}

func TestCheckRedirectBindsEntropyWarningToAdmittedRoute(t *testing.T) {
	p, cfg, sc := redirectPolicyTestProxy(t)
	cfg.RequestBodyScanning.ContentEntropyAction = config.ActionBlock
	cfg.RequestBodyScanning.ContentEntropyWarnRoutes = []config.RequestBodyEntropyWarnRoute{entropyWarnRoute()}
	admitted := &BodyEntropyWarnRouteMatch{Host: "upload.vendor.example", Path: "/v1/files", Reason: "encrypted customer archive", Owner: "storage team", Expires: "2099-12-31"}

	ctx := context.WithValue(t.Context(), ctxKeyAgentConfig, cfg)
	ctx = context.WithValue(ctx, ctxKeyAgentScanner, sc)
	ctx = context.WithValue(ctx, ctxKeyEntropyWarnRoute, admitted)
	original := httptest.NewRequestWithContext(ctx, http.MethodPost, "https://upload.vendor.example/v1/files", nil)
	original.Header.Set(headerContentType, "application/octet-stream")

	for _, tt := range []struct {
		name    string
		target  string
		blocked bool
	}{
		{"same exact route", "https://upload.vendor.example/v1/files?part=2", false},
		{"different path", "https://upload.vendor.example/v1/other", true},
		{"different host", "https://other.vendor.example/v1/files", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			redirect := httptest.NewRequestWithContext(ctx, http.MethodPost, tt.target, nil)
			redirect.Header.Set(headerContentType, "application/octet-stream")
			err := p.client.CheckRedirect(redirect, []*http.Request{original})
			if tt.blocked && err == nil {
				t.Fatal("redirect replay outside admitted route was allowed")
			}
			if !tt.blocked && err != nil {
				t.Fatalf("same-route redirect was blocked: %v", err)
			}
		})
	}
}

func TestEntropyWarnRouteIsAdaptiveExemptButOrdinaryEntropyIsNot(t *testing.T) {
	cfg := config.Defaults()
	matched := BodyScanResult{EntropyFinding: &ContentEntropyFinding{}, EntropyWarnRoute: &BodyEntropyWarnRouteMatch{Host: "upload.vendor.example", Path: "/v1/files"}}
	if !isBodyAdaptiveExempt(scannerLabelBodyEntropy, matched, "upload.vendor.example", cfg) {
		t.Fatal("authorized entropy warning would be re-promoted by adaptive enforcement")
	}
	ordinary := BodyScanResult{EntropyFinding: &ContentEntropyFinding{}}
	if isBodyAdaptiveExempt(scannerLabelBodyEntropy, ordinary, "upload.vendor.example", cfg) {
		t.Fatal("ordinary entropy finding was incorrectly exempted from adaptive enforcement")
	}
}

func TestWebSocketContentEntropyConfigExplicitlyDropsHTTPWarnRoutes(t *testing.T) {
	cfg := config.Defaults()
	cfg.RequestBodyScanning.ContentEntropyWarnRoutes = []config.RequestBodyEntropyWarnRoute{entropyWarnRoute()}
	cfg.WebSocketProxy.ContentEntropyExclusions = []string{"stream.vendor.example"}
	req := BodyScanRequest{Scheme: "https"}
	applyWebSocketContentEntropyConfig(&req, cfg)
	if req.ContentEntropyWarnRoutes != nil {
		t.Fatalf("HTTP entropy warning routes leaked into WebSocket scan: %+v", req.ContentEntropyWarnRoutes)
	}
	if !stringListContains(req.ContentEntropyExclusions, "stream.vendor.example") {
		t.Fatalf("WebSocket entropy exclusions were not applied: %+v", req.ContentEntropyExclusions)
	}
}

func TestInterceptEntropyWarnReceiptPreservesProvenanceAndDoesNotFollowRedirect(t *testing.T) {
	for _, requireReceipts := range []bool{false, true} {
		t.Run(fmt.Sprintf("require_receipts_%t", requireReceipts), func(t *testing.T) {
			cache, pool, cfg, _, logger, m := testInterceptSetup(t)
			cfg.RequestBodyScanning.ContentEntropyEnabled = true
			cfg.RequestBodyScanning.ContentEntropyAction = config.ActionBlock
			cfg.RequestBodyScanning.ContentEntropyThreshold = 4.5
			cfg.RequestBodyScanning.ContentEntropyMinLength = 32
			cfg.RequestBodyScanning.ContentEntropyWarnRoutes = []config.RequestBodyEntropyWarnRoute{entropyWarnRoute()}
			cfg.FlightRecorder.RequireReceipts = requireReceipts
			sc := scanner.MustNew(cfg)
			t.Cleanup(func() { sc.Close() })
			p, err := New(cfg, logger, sc, m)
			if err != nil {
				t.Fatalf("proxy.New: %v", err)
			}
			rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(rph.emitter)

			var calls atomic.Int32
			rt := roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return &http.Response{
					StatusCode: http.StatusTemporaryRedirect,
					Header: http.Header{
						headerContentType: {"text/plain"},
						"Location":        {"https://other.vendor.example/v1/files"},
					},
					Body: http.NoBody,
				}, nil
			})
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
				"https://upload.vendor.example/v1/files", strings.NewReader(opaqueHighEntropyBodyValue()))
			if err != nil {
				t.Fatalf("NewRequestWithContext: %v", err)
			}
			req.Header.Set(headerContentType, "application/octet-stream")
			resp := interceptWithRT(t, cache, pool, cfg, sc, logger, m, rt,
				&InterceptContext{Proxy: p, TargetHost: "upload.vendor.example", TargetPort: "443"}, req)
			t.Cleanup(func() { _ = resp.Body.Close() })
			if resp.StatusCode != http.StatusTemporaryRedirect {
				t.Fatalf("status = %d, want 307 returned to the agent", resp.StatusCode)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("intercept RoundTrip calls = %d, want 1 (redirects are not followed internally)", got)
			}

			var warningReceiptFound bool
			for _, rcpt := range rph.findReceipts(t) {
				ar := rcpt.ActionRecord
				if ar.Transport != "intercept" || ar.Layer != scannerLabelBodyEntropy {
					continue
				}
				warningReceiptFound = true
				if ar.Verdict != config.ActionWarn {
					t.Fatalf("entropy receipt verdict = %q, want warn", ar.Verdict)
				}
				for _, want := range []string{"encrypted customer archive", "storage team", "2099-12-31"} {
					if !strings.Contains(ar.Pattern, want) {
						t.Fatalf("entropy receipt pattern %q does not contain %q", ar.Pattern, want)
					}
				}
			}
			if !warningReceiptFound {
				t.Fatal("intercept entropy warning receipt was not emitted")
			}
		})
	}
}
