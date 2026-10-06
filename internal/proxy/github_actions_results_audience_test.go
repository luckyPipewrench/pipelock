// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/capture"
)

func TestInterceptTunnel_GitHubActionsResultsSAS(t *testing.T) {
	const host = "productionresultssa1.blob.core.windows.net"
	const run = "/actions-results/00000000-0000-4000-8000-000000000011/workflow-job-run-00000000-0000-4000-8000-000000000012"
	query, err := url.ParseQuery(releaseGrantSASQuery("unused", "actions-interception"))
	if err != nil {
		t.Fatal(err)
	}
	query.Del("jwt")
	query.Set("st", "2026-10-03T21:29:55Z")
	query.Set("se", "2026-10-03T22:29:55Z")
	query.Set("rscd", `attachment; filename="test-results-linux-amd64-release-archive.zip"`)
	query.Set("rsct", "application/zip")
	good := query.Encode()
	for _, tc := range []struct {
		name, host, path, query string
		wantAllow               bool
	}{
		{"log", host, run + "/logs/job/job-logs.txt", good, true},
		{"artifact", host, run + "/artifacts/" + strings.Repeat("0123456789abcdef", 4) + ".zip", good, true},
		{"lookalike", host + ".vendor.example", run + "/logs/job/job-logs.txt", good, false},
		{"bad path", host, "/other/job-logs.txt", good, false},
		{"duplicate signature", host, run + "/logs/job/job-logs.txt", good + "&sig=" + url.QueryEscape(query.Get("sig")), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamHits atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits.Add(1)
				_, _ = fmt.Fprint(w, "asset")
			}))
			defer upstream.Close()

			cache, pool, cfg, _, logger, m := testInterceptSetup(t)
			addr := upstream.Listener.Addr().String()
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatalf("SplitHostPort: %v", err)
			}
			now := time.Date(2026, 10, 3, 22, 0, 0, 0, time.UTC)
			sc := releaseGrantScanner(t, cfg, now)

			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
				"https://"+tc.host+":"+port+tc.path+"?"+tc.query, nil)

			dialer := &net.Dialer{}
			upstreamRT := upstream.Client().Transport.(*http.Transport).Clone()
			upstreamRT.TLSClientConfig = upstreamRT.TLSClientConfig.Clone()
			upstreamRT.TLSClientConfig.ServerName = upstream.Listener.Addr().(*net.TCPAddr).IP.String()
			upstreamRT.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			}
			t.Cleanup(upstreamRT.CloseIdleConnections)

			resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
				Upstream:   upstream,
				TargetHost: tc.host,
				UpstreamRT: upstreamRT,
				Cache:      cache,
				Pool:       pool,
				Config:     cfg,
				Scanner:    sc,
				Logger:     logger,
				Metrics:    m,
				Request:    req,
				Proxy:      &Proxy{captureObs: capture.NopObserver{}, metrics: m},
			})
			defer func() { _ = resp.Body.Close() }()

			if !tc.wantAllow {
				if resp.StatusCode != http.StatusForbidden || upstreamHits.Load() != 0 {
					t.Fatalf("SAS reached the upstream: status=%d hits=%d", resp.StatusCode, upstreamHits.Load())
				}
				return
			}
			if resp.StatusCode != http.StatusOK || upstreamHits.Load() != 1 {
				t.Fatalf("Actions results SAS blocked: status=%d hits=%d", resp.StatusCode, upstreamHits.Load())
			}
			assertMetricSampleValue(t, m,
				`pipelock_dlp_credential_audience_allows_total{pattern="Azure SAS Token",surface="url"}`, 1)
		})
	}
}
