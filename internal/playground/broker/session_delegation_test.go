// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// testDelegationRoot returns a usable signing root and its canonical digest.
func testDelegationRoot(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return priv, "sha256:" + strings.Repeat("a", 64)
}

// The visitor VM must receive a short-lived session key and a root-signed
// delegation, never the durable root. The delegation has to bind the run and
// the image so a captured one cannot be replayed onto a different run or a
// different VM image.
func TestServer_CreateVMSession_SendsBoundDelegation(t *testing.T) {
	root, digest := testDelegationRoot(t)

	type captured struct {
		Code                   string          `json:"code"`
		RunNonce               string          `json:"run_nonce"`
		SessionSigningKey      string          `json:"session_signing_key"`
		OrchestratorDelegation json.RawMessage `json:"orchestrator_delegation"`
	}
	got := make(chan captured, 1)

	vmsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != livechat.RouteSession {
			writeBrokerErr(w, http.StatusNotFound, "not found")
			return
		}
		var req captured
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBrokerErr(w, http.StatusBadRequest, "bad request")
			return
		}
		select {
		case got <- req:
		default:
		}
		writeBrokerJSON(w, http.StatusOK, vmSessionResponse{
			Token:     "delegated-token",
			SessionID: "sid-delegated",
			ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano),
			State:     brokerTestState,
		})
	}))
	t.Cleanup(vmsrv.Close)

	u := vmsrv.URL
	host := u[strings.LastIndex(u, "/")+1:]
	provider := &serverFakeProvider{targets: []string{host}}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{
		OrchestratorRoot: root,
		ImageDigest:      digest,
	})

	status, _ := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}

	var req captured
	select {
	case req = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the VM never received a session request")
	}

	if req.SessionSigningKey == "" || len(req.OrchestratorDelegation) == 0 {
		t.Fatal("the VM must receive both a session key and a delegation")
	}
	if req.SessionSigningKey == hex.EncodeToString(root) {
		t.Fatal("the durable root must never be sent to a visitor VM")
	}

	d, err := playground.ParseOrchestratorDelegation(req.OrchestratorDelegation)
	if err != nil {
		t.Fatalf("delegation does not parse: %v", err)
	}
	if d.ImageDigest != digest {
		t.Fatalf("delegation image digest = %q, want %q", d.ImageDigest, digest)
	}
	if d.RunNonce != req.RunNonce {
		t.Fatalf("delegation run nonce = %q, want %q", d.RunNonce, req.RunNonce)
	}

	priv, err := playground.ParseOrchestratorPrivateKeyHex(req.SessionSigningKey)
	if err != nil {
		t.Fatalf("session signing key does not parse: %v", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("session key has no Ed25519 public half")
	}
	if hex.EncodeToString(pub) != d.SessionPublicKey {
		t.Fatal("the delegation does not authorize the session key that was sent")
	}
	if d.ExpiresAtUnix <= d.NotBeforeUnix {
		t.Fatal("the delegation must carry a bounded validity window")
	}
}

// Without a root the broker sends no delegation, which is the local and legacy
// shape. It must not invent one or send an unauthorized key.
func TestServer_CreateVMSession_NoRootSendsNoDelegation(t *testing.T) {
	vm := newFakeVM(t, "plain-token")
	provider := &serverFakeProvider{targets: []string{vm.targetHost(t)}}
	_, ts := newBrokerTestServer(t, provider, ServerConfig{})

	status, session := postBrokerSession(t, ts)
	if status != http.StatusOK {
		t.Fatalf("session status = %d, want 200", status)
	}
	if session.Token != vm.token {
		t.Fatalf("session token = %q, want %q", session.Token, vm.token)
	}
}
