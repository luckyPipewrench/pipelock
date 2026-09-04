// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func sigV4CredentialRouteTestURL() string {
	query := url.Values{}
	query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	query.Set("X-Amz-Credential", fakeAPIKey()+"/20260831/us-east-1/s3/aws4_request")
	query.Set("X-Amz-Date", "20260831T120000Z")
	query.Set("X-Amz-Expires", "3600")
	query.Set("X-Amz-Signature", strings.Repeat("a", 64))
	query.Set("X-Amz-SignedHeaders", "host")
	return "https://uploads.s3.amazonaws.com/object?" + query.Encode()
}

func sigV4CredentialRouteTestConfig() *config.Config {
	cfg := testScannerConfig()
	cfg.RequestBodyScanning.ContentEntropyEnabled = false
	cfg.RequestBodyScanning.SigV4CredentialRoutes = []config.RequestBodySigV4CredentialRoute{{
		Host:         "api.vendor.example",
		Path:         "/v1/graphql",
		ContentTypes: []string{contentTypeJSON},
		Methods:      []string{http.MethodPost, http.MethodGet},
		Reason:       "attachment registration",
		Owner:        "platform",
		Expires:      "2099-12-31",
	}}
	return cfg
}

func TestReverseProxy_SigV4CredentialRoutes(t *testing.T) {
	t.Parallel()

	presigned := `{"url":"` + sigV4CredentialRouteTestURL() + `"}`
	for _, tc := range []struct {
		name        string
		upstream    string
		path        string
		method      string
		contentType string
		body        string
		blocked     bool
	}{
		{name: "allows configured route", upstream: "https://api.vendor.example", path: "/v1/graphql", method: http.MethodPost, contentType: contentTypeJSON, body: presigned},
		{name: "blocks outside configured route host", upstream: "https://other.vendor.example", path: "/v1/graphql", method: http.MethodPost, contentType: contentTypeJSON, body: presigned, blocked: true},
		{name: "blocks outside configured route path", upstream: "https://api.vendor.example", path: "/v2/graphql", method: http.MethodPost, contentType: contentTypeJSON, body: presigned, blocked: true},
		{name: "blocks outside configured route method", upstream: "https://api.vendor.example", path: "/v1/graphql", method: http.MethodPut, contentType: contentTypeJSON, body: presigned, blocked: true},
		{name: "blocks outside configured route content type", upstream: "https://api.vendor.example", path: "/v1/graphql", method: http.MethodPost, contentType: "application/x-www-form-urlencoded", body: "url=" + url.QueryEscape(sigV4CredentialRouteTestURL()), blocked: true},
		{name: "matching route still blocks a separate secret", upstream: "https://api.vendor.example", path: "/v1/graphql", method: http.MethodPost, contentType: contentTypeJSON, body: `{"url":"` + sigV4CredentialRouteTestURL() + `","key":"` + fakeAPIKey() + `"}`, blocked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sigV4CredentialRouteTestConfig()
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			upstream, err := url.Parse(tc.upstream)
			if err != nil {
				t.Fatalf("parse upstream: %v", err)
			}
			handler := &ReverseProxyHandler{upstream: upstream, logger: audit.NewNop(), metrics: metrics.New(), captureObs: capture.NopObserver{}}
			req := httptest.NewRequestWithContext(t.Context(), tc.method, "https://proxy.vendor.example"+tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			rec := httptest.NewRecorder()
			blocked, _, _, _ := handler.scanRequest(rec, req, cfg, sc, nil, reverseBlockReceiptInput{Target: tc.upstream + tc.path})
			if blocked != tc.blocked {
				t.Fatalf("blocked = %v, want %v; response=%s", blocked, tc.blocked, rec.Body.String())
			}
		})
	}
}

// WebSocket frames never match a SigV4 credential route: a frame has no request
// method or declared content type, and HTTP route exceptions are deliberately
// kept off the frame path. Even a route that names the relay's exact host and
// path leaves the embedded access-key ID blocked by the DLP floor.
func TestWebSocketClientMessageBody_SigV4CredentialRoutesNeverMatchFrames(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		host string
	}{
		{name: "route naming the relay host and path", host: "api.vendor.example"},
		{name: "host outside any route", host: "other.vendor.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sigV4CredentialRouteTestConfig()
			cfg.WebSocketProxy.Enabled = true
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			relay := &wsRelay{
				cfg:       cfg,
				maxMsg:    cfg.WebSocketProxy.MaxMessageBytes,
				scanner:   sc,
				hostname:  tc.host,
				path:      "/v1/graphql",
				targetURL: "wss://" + tc.host + "/v1/graphql",
			}

			_, result := relay.scanClientMessageBody(context.Background(), []byte(`{"url":"`+sigV4CredentialRouteTestURL()+`"}`))
			if result.Clean {
				t.Fatalf("WebSocket frame honored a SigV4 credential route; matches=%+v", result.DLPMatches)
			}
			if !hasDLPMatchName(result.DLPMatches, "AWS Access ID") {
				t.Fatalf("DLPMatches = %v, want AWS Access ID", dlpMatchNames(result.DLPMatches))
			}
		})
	}
}
