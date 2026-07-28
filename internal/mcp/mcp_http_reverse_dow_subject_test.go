// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// With the trusted-session gate off, the subject key must still identify the
// client. An empty key here would land every caller in the DoW manager's shared
// "_default" bucket, so one caller could spend every other caller's budget.
func TestTrustedDoWSubjectKeyBucketsPerClientWhenGateOff(t *testing.T) {
	opts := MCPProxyOpts{DoWRequireTrustedSession: false, DoWSubjectAgent: "agent-a"}

	reqA := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	reqA.RemoteAddr = "203.0.113.10:5555"
	reqB := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	reqB.RemoteAddr = "203.0.113.20:5555"

	// Same client, new connection: the source port differs on every connection,
	// so a key that varied with it would hand each request a fresh budget.
	reqARepeat := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	reqARepeat.RemoteAddr = "203.0.113.10:61234"

	keyA := trustedDoWSubjectKey(reqA, opts)
	keyARepeat := trustedDoWSubjectKey(reqARepeat, opts)
	keyB := trustedDoWSubjectKey(reqB, opts)

	if keyA == "" || keyB == "" {
		t.Fatalf("empty subject key collapses clients into the shared bucket: %q / %q", keyA, keyB)
	}
	if keyA == keyB {
		t.Fatalf("distinct clients share subject key %q", keyA)
	}
	// Distinctness alone is satisfied by a per-request random key, which would
	// defeat budget accounting entirely, so stability is asserted separately.
	if keyARepeat != keyA {
		t.Fatalf("same client received unstable subject keys across connections: %q / %q", keyA, keyARepeat)
	}
}

// The strict gate must still fail closed on an unknown session.
func TestTrustedDoWSubjectKeyEmptyForUnknownSessionWhenGateOn(t *testing.T) {
	opts := MCPProxyOpts{
		DoWRequireTrustedSession: true,
		DoWSubjectAgent:          "agent-a",
		DoWSessionKnown:          func(string) bool { return false },
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.10:5555"
	req.Header.Set("Mcp-Session-Id", "not-registered")

	if got := trustedDoWSubjectKey(req, opts); got != "" {
		t.Fatalf("unknown session produced subject key %q, want empty so the gate fails closed", got)
	}
}

func TestTrustedDoWSubjectKeyUsesClientKeyWhenLiveDoWDisabled(t *testing.T) {
	opts := MCPProxyOpts{
		DoWRequireTrustedSession: true,
		DoWSubjectAgent:          "agent-a",
		DoWEnabledFn:             func() bool { return false },
		DoWSessionKnown:          func(string) bool { return false },
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.10:5555"
	req.Header.Set("Mcp-Session-Id", "not-registered")

	if got := trustedDoWSubjectKey(req, opts); got == "" {
		t.Fatal("disabled live DoW state still produced an empty subject key for the trusted-session gate")
	}
}

// Gate-on coverage cannot be negative-only. An implementation that always
// returned "" under DoWRequireTrustedSession would satisfy the unknown-session
// test while turning every tool call from a known session into a fail-closed
// block, which is an outage rather than a security win.
func TestTrustedDoWSubjectKeyReturnsStableKeyForKnownSessionWhenGateOn(t *testing.T) {
	opts := MCPProxyOpts{
		DoWRequireTrustedSession: true,
		DoWSubjectAgent:          "agent-a",
		DoWSessionKnown:          func(string) bool { return true },
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	req.RemoteAddr = "203.0.113.10:5555"
	req.Header.Set("Mcp-Session-Id", "registered")

	// Same client on a new connection: the source port differs every time, so
	// a key derived from it would hand each request a fresh budget.
	repeat := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	repeat.RemoteAddr = "203.0.113.10:61234"
	repeat.Header.Set("Mcp-Session-Id", "registered")

	key := trustedDoWSubjectKey(req, opts)
	if key == "" {
		t.Fatal("known session produced an empty key, so every call from it fails closed")
	}
	if got := trustedDoWSubjectKey(repeat, opts); got != key {
		t.Fatalf("known session key unstable across connections: %q / %q", key, got)
	}
}
