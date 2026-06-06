// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/jcs"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const interceptCardHost = "agent.example.com"

// interceptCardCfg builds a config that verifies Agent Card signatures, scoped
// to the intercept test host.
func interceptCardCfg(pub ed25519.PublicKey) *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.A2AScanning.Enabled = true
	cfg.A2AScanning.Action = config.ActionBlock
	cfg.A2AScanning.ScanAgentCards = false
	cfg.A2AScanning.DetectCardDrift = false
	cfg.A2AScanning.TrustedAgentCardKeys = []config.A2ATrustedCardKey{{
		KeyID:          "k1",
		PublicKey:      signing.EncodePublicKey(pub),
		AllowedOrigins: []string{"https://" + interceptCardHost},
	}}
	return cfg
}

// runInterceptCard drives a card body back through the TLS-intercept handler and
// returns the status code the agent would see.
func runInterceptCard(t *testing.T, cfg *config.Config, card []byte) int {
	t.Helper()
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)
	logger := audit.NewNop()
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	rt := roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": []string{"application/a2a+json"}},
			Body:          io.NopCloser(bytes.NewReader(card)),
			ContentLength: int64(len(card)),
		}, nil
	})
	handler := newInterceptHandler(&InterceptContext{
		TargetHost: interceptCardHost,
		TargetPort: "443",
		Config:     cfg,
		Scanner:    sc,
		Logger:     logger,
		Metrics:    m,
		ClientIP:   testLoopbackIP,
		RequestID:  "intercept-card",
		Agent:      "test-agent",
		Proxy:      p,
	}, rt)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://"+interceptCardHost+agentCardPath, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Code
}

// TestIntercept_AgentCardSignature_ForgedBlocked proves CONNECT/TLS-intercept
// parity with the forward path: a forged Agent Card signature is blocked (403).
func TestIntercept_AgentCardSignature_ForgedBlocked(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	if code := runInterceptCard(t, interceptCardCfg(pub), e2eSignedCard(t, priv, true)); code != http.StatusForbidden {
		t.Fatalf("forged Agent Card over intercept must be blocked (403), got %d", code)
	}
}

// TestIntercept_AgentCardSignature_ValidAllowed proves a validly signed card
// passes through the intercept path (200).
func TestIntercept_AgentCardSignature_ValidAllowed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	if code := runInterceptCard(t, interceptCardCfg(pub), e2eSignedCard(t, priv, false)); code != http.StatusOK {
		t.Fatalf("validly signed Agent Card over intercept must pass (200), got %d", code)
	}
}

const agentCardPath = "/.well-known/agent-card.json"

func e2ePreimage(t *testing.T, card map[string]any) []byte {
	t.Helper()
	cp := map[string]any{}
	for k, v := range card {
		if k != "signatures" {
			cp[k] = v
		}
	}
	b, err := jcs.Marshal(cp)
	if err != nil {
		t.Fatalf("jcs.Marshal: %v", err)
	}
	return b
}

// e2eSignedCard returns a JWS-signed Agent Card. When forged is true the
// signature bytes are replaced with zeros (valid length, wrong value).
func e2eSignedCard(t *testing.T, priv ed25519.PrivateKey, forged bool) []byte {
	t.Helper()
	card := map[string]any{"name": "Vendor Agent", "description": "ok", "version": "1.0"}
	pre := e2ePreimage(t, card)
	hdr, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "k1"})
	pb := base64.RawURLEncoding.EncodeToString(hdr)
	sig := ed25519.Sign(priv, []byte(pb+"."+base64.RawURLEncoding.EncodeToString(pre)))
	if forged {
		sig = make([]byte, ed25519.SignatureSize)
	}
	card["signatures"] = []any{map[string]any{
		"protected": pb,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	}}
	b, _ := json.Marshal(card)
	return b
}

func originOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	return u.Scheme + "://" + u.Host
}

// TestForwardHTTP_AgentCardSignature_ForgedBlocked proves the forward proxy
// surface verifies Agent Card signatures end-to-end: a forged signature yields 403.
func TestForwardHTTP_AgentCardSignature_ForgedBlocked(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	forged := e2eSignedCard(t, priv, true)

	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/a2a+json")
		_, _ = w.Write(forged)
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.A2AScanning.Enabled = true
		cfg.A2AScanning.Action = config.ActionBlock
		cfg.A2AScanning.ScanAgentCards = false
		cfg.A2AScanning.DetectCardDrift = false
		cfg.A2AScanning.TrustedAgentCardKeys = []config.A2ATrustedCardKey{{
			KeyID:          "k1",
			PublicKey:      signing.EncodePublicKey(pub),
			AllowedOrigins: []string{originOf(t, backend.URL)},
		}}
	})
	defer cleanup()

	resp := doGet(t, proxyClient(proxyAddr), backend.URL+agentCardPath)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged Agent Card signature must be blocked (403), got %d", resp.StatusCode)
	}
}

// TestForwardHTTP_AgentCardSignature_ValidAllowed proves a genuinely signed card
// passes through the forward proxy.
func TestForwardHTTP_AgentCardSignature_ValidAllowed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	valid := e2eSignedCard(t, priv, false)

	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/a2a+json")
		_, _ = w.Write(valid)
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.A2AScanning.Enabled = true
		cfg.A2AScanning.Action = config.ActionBlock
		cfg.A2AScanning.ScanAgentCards = false
		cfg.A2AScanning.DetectCardDrift = false
		cfg.A2AScanning.TrustedAgentCardKeys = []config.A2ATrustedCardKey{{
			KeyID:          "k1",
			PublicKey:      signing.EncodePublicKey(pub),
			AllowedOrigins: []string{originOf(t, backend.URL)},
		}}
	})
	defer cleanup()

	resp := doGet(t, proxyClient(proxyAddr), backend.URL+agentCardPath)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("validly signed Agent Card must pass (200), got %d", resp.StatusCode)
	}
}
