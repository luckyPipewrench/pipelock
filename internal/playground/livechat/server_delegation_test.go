// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestServer_RequireDelegatedSigning_RefusesBareCode(t *testing.T) {
	t.Parallel()
	g, err := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good", MaxSessions: 5}}, TokenTTL: time.Minute})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	srv, err := NewServer(ServerConfig{
		Gate:                    g,
		MaxConcurrent:           2,
		IPRate:                  RateConfig{RefillPerSec: 1000, Burst: 1000},
		CodeRate:                RateConfig{RefillPerSec: 1000, Burst: 1000},
		RequireDelegatedSigning: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptestServer(t, srv)
	resp := postJSON(t, ts+RouteSession, createReq{Code: "good"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bare code status = %d, want 400", resp.StatusCode)
	}
}

func TestServer_DelegatedSession_Starts(t *testing.T) {
	t.Parallel()
	g, err := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "good", MaxSessions: 5}}, TokenTTL: time.Minute})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	srv, err := NewServer(ServerConfig{
		Gate:                    g,
		MaxConcurrent:           2,
		IPRate:                  RateConfig{RefillPerSec: 1000, Burst: 1000},
		CodeRate:                RateConfig{RefillPerSec: 1000, Burst: 1000},
		RequireDelegatedSigning: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptestServer(t, srv)

	_, rootPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	image := "sha256:" + strings.Repeat("ab", 32)
	runNonce := "aa" + strings.Repeat("bb", 15)
	minted, err := playground.MintSessionDelegation(rootPriv, runNonce, image, time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	delJSON, err := json.Marshal(minted.Delegation)
	if err != nil {
		t.Fatal(err)
	}
	resp := postJSON(t, ts+RouteSession, createReq{
		Code:                   "good",
		RunNonce:               runNonce,
		SessionSigningKey:      hex.EncodeToString(minted.PrivateKey),
		OrchestratorDelegation: delJSON,
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delegated session status = %d", resp.StatusCode)
	}
}

func httptestServer(t *testing.T, srv *Server) string {
	t.Helper()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return ts.URL
}
