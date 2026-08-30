// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	domrules "github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const artifactIntegrationPath = "/rules/pipelock-community/bundle.yaml"

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

func artifactBundle(bodySuffix string) []byte {
	return []byte("format_version: 1\nname: pipelock-community\nversion: 2026.08.0\nauthor: test\ndescription: " + bodySuffix + "\nrules: []\n")
}

func installArtifactOfficialKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	origDefault, origKeyring := domrules.DefaultKeyringHex, domrules.KeyringHex
	domrules.DefaultKeyringHex, domrules.KeyringHex = hex.EncodeToString(pub), ""
	t.Cleanup(func() { domrules.DefaultKeyringHex, domrules.KeyringHex = origDefault, origKeyring })
	return priv
}

func artifactConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = config.ActionBlock
	cfg.ResponseScanning.AuthenticatedArtifacts = []config.AuthenticatedArtifactEntry{{Host: "rules.example", Path: artifactIntegrationPath, BundleName: "pipelock-community"}}
	return cfg
}

func newArtifactIntegrationProxy(t *testing.T, cfg *config.Config, logger *audit.Logger, rt http.RoundTripper) *Proxy {
	t.Helper()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.client = &http.Client{Transport: rt}
	t.Cleanup(p.Close)
	return p
}

func artifactResponse(req *http.Request, status int, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{headerContentType: {"text/plain"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: req}
}

// TestForwardHTTPAuthenticatedArtifact_HandlerPath covers the actual forward
// handler, including its response scanner and pre-release artifact verifier.
func TestForwardHTTPAuthenticatedArtifact_HandlerPath(t *testing.T) {
	priv := installArtifactOfficialKey(t)
	goodBody := artifactBundle(testInjectionPayload)
	goodSig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, goodBody)))
	oversizedSSEBody := artifactBundle(strings.Repeat("a", 65*1024))
	oversizedSSESig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, oversizedSSEBody)))

	for _, tc := range []struct {
		name        string
		policy      bool
		body        []byte
		signature   []byte
		sigStatus   int
		sigRedirect bool
		contentType string
		encoding    string
		bodyLimit   int64
		want        int
		wantReason  blockreason.Reason
	}{
		{name: "no matching policy retains response scan", body: []byte(testInjectionPayload), want: http.StatusForbidden, wantReason: blockreason.PromptInjection},
		{name: "valid official artifact bypasses only injection scan", policy: true, body: goodBody, signature: goodSig, sigStatus: http.StatusOK, want: http.StatusOK},
		{name: "valid official artifact bypasses SSE injection scan", policy: true, body: goodBody, signature: goodSig, sigStatus: http.StatusOK, contentType: "text/event-stream", want: http.StatusOK},
		{name: "valid official SSE artifact keeps response size gate", policy: true, body: oversizedSSEBody, signature: oversizedSSESig, sigStatus: http.StatusOK, contentType: "text/event-stream", bodyLimit: 64 * 1024, want: http.StatusForbidden, wantReason: blockreason.ResponseSize},
		{name: "valid official SSE artifact keeps compressed response gate", policy: true, body: goodBody, signature: goodSig, sigStatus: http.StatusOK, contentType: "text/event-stream", encoding: "gzip", want: http.StatusForbidden, wantReason: blockreason.CompressedResponse},
		{name: "tampered body is blocked", policy: true, body: artifactBundle("NEVER_RELEASE tampered"), signature: goodSig, sigStatus: http.StatusOK, want: http.StatusForbidden, wantReason: blockreason.EnvelopeVerifyFailed},
		{name: "invalid signature is blocked", policy: true, body: goodBody, signature: []byte("not-base64"), sigStatus: http.StatusOK, want: http.StatusForbidden, wantReason: blockreason.EnvelopeVerifyFailed},
		{name: "missing signature is blocked", policy: true, body: goodBody, sigStatus: http.StatusNotFound, want: http.StatusForbidden, wantReason: blockreason.EnvelopeVerifyFailed},
		{name: "signature redirect is blocked", policy: true, body: goodBody, signature: goodSig, sigStatus: http.StatusOK, sigRedirect: true, want: http.StatusForbidden, wantReason: blockreason.EnvelopeVerifyFailed},
		{name: "oversized signature is blocked", policy: true, body: goodBody, signature: bytes.Repeat([]byte("A"), 4097), sigStatus: http.StatusOK, want: http.StatusForbidden, wantReason: blockreason.EnvelopeVerifyFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := artifactConfig()
			if !tc.policy {
				cfg.ResponseScanning.AuthenticatedArtifacts = nil
			}
			originalBody := &closeTrackingBody{Reader: bytes.NewReader(tc.body)}
			rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				if strings.HasSuffix(req.URL.Path, ".sig") {
					if req.Context().Value(ctxKeyAgentConfig) != cfg {
						t.Fatal("signature fetch lost the scanned outbound request context")
					}
					responseReq := req
					if tc.sigRedirect {
						redirected := req.Clone(context.Background())
						redirected.URL = &url.URL{Scheme: "https", Host: "rules.example", Path: "/other.sig"}
						responseReq = redirected
					}
					return artifactResponse(responseReq, tc.sigStatus, tc.signature), nil
				}
				contentType := tc.contentType
				if contentType == "" {
					contentType = "text/plain"
				}
				header := http.Header{headerContentType: {contentType}}
				if tc.encoding != "" {
					header.Set("Content-Encoding", tc.encoding)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: header, Body: originalBody, Request: req}, nil
			})
			logger := audit.NewNop()
			p := newArtifactIntegrationProxy(t, cfg, logger, rt)
			p.responseBodyLimit = tc.bodyLimit
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://rules.example"+artifactIntegrationPath, nil)
			w := httptest.NewRecorder()
			p.handleForwardHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%q", w.Code, tc.want, w.Body.String())
			}
			if tc.wantReason != "" && w.Header().Get(blockreason.HeaderReason) != string(tc.wantReason) {
				t.Fatalf("%s=%q want=%q", blockreason.HeaderReason, w.Header().Get(blockreason.HeaderReason), tc.wantReason)
			}
			if tc.wantReason == blockreason.EnvelopeVerifyFailed && w.Header().Get(blockreason.HeaderLayer) != "authenticated_artifact" {
				t.Fatalf("%s=%q want authenticated_artifact", blockreason.HeaderLayer, w.Header().Get(blockreason.HeaderLayer))
			}
			if tc.want == http.StatusForbidden && strings.Contains(w.Body.String(), "NEVER_RELEASE") {
				t.Fatal("blocked artifact bytes reached the client")
			}
			if tc.want == http.StatusOK && !bytes.Equal(w.Body.Bytes(), tc.body) {
				t.Fatalf("released body=%q want exact verified body=%q", w.Body.Bytes(), tc.body)
			}
			if tc.policy && !originalBody.closed {
				t.Fatal("verified handler path did not close the upstream body")
			}
		})
	}
}

// TestInterceptAuthenticatedArtifact_HandlerPath drives the decrypted CONNECT
// handler itself rather than the verifier helper.
func TestInterceptAuthenticatedArtifact_HandlerPath(t *testing.T) {
	priv := installArtifactOfficialKey(t)
	goodBody := artifactBundle(testInjectionPayload)
	goodSig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, goodBody)))
	for _, tc := range []struct {
		name        string
		body        []byte
		signature   []byte
		sigStatus   int
		sigRedirect bool
		contentType string
		want        int
		wantReason  blockreason.Reason
	}{
		{name: "valid official artifact", body: goodBody, signature: goodSig, sigStatus: http.StatusOK, want: http.StatusOK},
		{name: "valid official artifact with SSE content type", body: goodBody, signature: goodSig, sigStatus: http.StatusOK, contentType: "text/event-stream", want: http.StatusOK},
		{name: "tampered body", body: artifactBundle("NEVER_RELEASE tampered"), signature: goodSig, sigStatus: http.StatusOK, want: http.StatusForbidden, wantReason: blockreason.EnvelopeVerifyFailed},
		{name: "invalid signature", body: goodBody, signature: []byte("not-base64"), sigStatus: http.StatusOK, want: http.StatusForbidden, wantReason: blockreason.EnvelopeVerifyFailed},
		{name: "missing signature", body: goodBody, sigStatus: http.StatusNotFound, want: http.StatusForbidden, wantReason: blockreason.EnvelopeVerifyFailed},
		{name: "signature path mismatch", body: goodBody, signature: goodSig, sigStatus: http.StatusOK, sigRedirect: true, want: http.StatusForbidden, wantReason: blockreason.EnvelopeVerifyFailed},
		{name: "oversized signature", body: goodBody, signature: bytes.Repeat([]byte("A"), 4097), sigStatus: http.StatusOK, want: http.StatusForbidden, wantReason: blockreason.EnvelopeVerifyFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := artifactConfig()
			cfg.AdaptiveEnforcement.Enabled = true
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			originalBody := &closeTrackingBody{Reader: bytes.NewReader(tc.body)}
			rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				if strings.HasSuffix(req.URL.Path, ".sig") {
					responseReq := req
					if tc.sigRedirect {
						redirected := req.Clone(context.Background())
						redirected.URL = &url.URL{Scheme: "https", Host: "rules.example", Path: "/other.sig"}
						responseReq = redirected
					}
					return artifactResponse(responseReq, tc.sigStatus, tc.signature), nil
				}
				contentType := tc.contentType
				if contentType == "" {
					contentType = "text/plain"
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{headerContentType: {contentType}}, Body: originalBody, Request: req}, nil
			})
			rec := &artifactCleanRecorder{}
			handler := newInterceptHandler(&InterceptContext{TargetHost: "rules.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: audit.NewNop(), Metrics: metrics.New(), ClientIP: testLoopbackIP, RequestID: "artifact-intercept", Agent: "test-agent", Recorder: rec}, rt)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://rules.example"+artifactIntegrationPath, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%q", w.Code, tc.want, w.Body.String())
			}
			if tc.wantReason != "" && w.Header().Get(blockreason.HeaderReason) != string(tc.wantReason) {
				t.Fatalf("%s=%q want=%q", blockreason.HeaderReason, w.Header().Get(blockreason.HeaderReason), tc.wantReason)
			}
			if tc.wantReason == blockreason.EnvelopeVerifyFailed && w.Header().Get(blockreason.HeaderLayer) != "authenticated_artifact" {
				t.Fatalf("%s=%q want authenticated_artifact", blockreason.HeaderLayer, w.Header().Get(blockreason.HeaderLayer))
			}
			if tc.want == http.StatusForbidden && strings.Contains(w.Body.String(), "NEVER_RELEASE") {
				t.Fatal("blocked artifact bytes reached the client")
			}
			if tc.want == http.StatusOK && !bytes.Equal(w.Body.Bytes(), tc.body) {
				t.Fatalf("released body=%q want exact verified body=%q", w.Body.Bytes(), tc.body)
			}
			if !originalBody.closed {
				t.Fatal("intercept handler did not close the upstream body")
			}
			if tc.want == http.StatusOK && rec.cleanCalls != 0 {
				t.Fatalf("verified artifact recorded %d clean adaptive events despite skipped injection scan", rec.cleanCalls)
			}
		})
	}
}

type artifactCleanRecorder struct{ cleanCalls int }

func (*artifactCleanRecorder) RecordSignal(session.SignalType, float64) (bool, string, string) {
	return false, "", ""
}
func (r *artifactCleanRecorder) RecordClean(float64) { r.cleanCalls++ }
func (*artifactCleanRecorder) EscalationLevel() int  { return 0 }
func (*artifactCleanRecorder) ThreatScore() float64  { return 0 }

func TestForwardHTTPAuthenticatedArtifact_EmitsLabelledAuditEvidence(t *testing.T) {
	priv := installArtifactOfficialKey(t)
	body := artifactBundle(testInjectionPayload)
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, body)))
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.New("json", "file", logPath, false, false)
	if err != nil {
		t.Fatal(err)
	}
	p := newArtifactIntegrationProxy(t, artifactConfig(), logger, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, ".sig") {
			return artifactResponse(req, http.StatusOK, sig), nil
		}
		return artifactResponse(req, http.StatusOK, body), nil
	}))
	w := httptest.NewRecorder()
	p.handleForwardHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://rules.example"+artifactIntegrationPath, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	logger.Close()
	logData, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "authenticated_artifact") {
		t.Fatalf("artifact verification did not emit labelled audit evidence: %s", logData)
	}
}

func TestForwardHTTPAuthenticatedArtifact_DoesNotDecayAdaptiveScore(t *testing.T) {
	priv := installArtifactOfficialKey(t)
	body := artifactBundle(testInjectionPayload)
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, body)))
	for _, contentType := range []string{"text/plain", "text/event-stream"} {
		t.Run(contentType, func(t *testing.T) {
			cfg := artifactConfig()
			cfg.SessionProfiling.Enabled = true
			cfg.AdaptiveEnforcement.Enabled = true
			cfg.AdaptiveEnforcement.EscalationThreshold = 100
			cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0.5
			p := newArtifactIntegrationProxy(t, cfg, audit.NewNop(), roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				if strings.HasSuffix(req.URL.Path, ".sig") {
					return artifactResponse(req, http.StatusOK, sig), nil
				}
				resp := artifactResponse(req, http.StatusOK, body)
				resp.Header.Set(headerContentType, contentType)
				return resp, nil
			}))
			sm := p.sessionMgrPtr.Load()
			if sm == nil {
				t.Fatal("session manager not initialized")
			}
			rec := sm.GetOrCreate("192.0.2.1")
			rec.RecordSignal(session.SignalBlock, cfg.AdaptiveEnforcement.EscalationThreshold)
			before := rec.ThreatScore()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://rules.example"+artifactIntegrationPath, nil)
			req.RemoteAddr = "192.0.2.1:1234"
			w := httptest.NewRecorder()
			p.handleForwardHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
			}
			if got := rec.ThreatScore(); got != before {
				t.Fatalf("verified artifact decayed adaptive score from %v to %v despite skipped injection scan", before, got)
			}
		})
	}
}

func TestForwardHTTPAdaptiveCleanRecordsOnlyScannedResponses(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
		body        []byte
	}{
		{name: "buffered response", contentType: "text/plain", body: []byte("clean response")},
		{name: "SSE response", contentType: "text/event-stream", body: []byte("data: clean response\n\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := artifactConfig()
			cfg.ResponseScanning.AuthenticatedArtifacts = nil
			cfg.SessionProfiling.Enabled = true
			cfg.AdaptiveEnforcement.Enabled = true
			cfg.AdaptiveEnforcement.EscalationThreshold = 100
			cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0.5
			p := newArtifactIntegrationProxy(t, cfg, audit.NewNop(), roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{headerContentType: {tc.contentType}}, Body: io.NopCloser(bytes.NewReader(tc.body)), Request: req}, nil
			}))
			sm := p.sessionMgrPtr.Load()
			if sm == nil {
				t.Fatal("session manager not initialized")
			}
			clientIP := "192.0.2.1"
			rec := sm.GetOrCreate(clientIP)
			rec.RecordSignal(session.SignalBlock, cfg.AdaptiveEnforcement.EscalationThreshold)
			before := rec.ThreatScore()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://clean.example/response", nil)
			req.RemoteAddr = clientIP + ":1234"
			w := httptest.NewRecorder()
			p.handleForwardHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
			}
			if got := rec.ThreatScore(); got >= before {
				t.Fatalf("clean scanned response did not reduce adaptive score: before=%v after=%v", before, got)
			}
		})
	}
}
