// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"net/http"
	"testing"
	"time"
)

// The session id is the caller-supplied run nonce, so a second request can name
// a session that is already running. Overwriting the map entry would orphan the
// first session: its timer closes over the same id and would finalize the
// replacement, leaving the original alive with nothing able to reap it. The
// second request is refused and the first stays exactly where it was.
func TestServer_DuplicateRunNonceDoesNotDisplaceTheActiveSession(t *testing.T) {
	t.Parallel()

	g, err := NewGate(GateConfig{
		Secret:   testSecret(t),
		Codes:    []CodeSpec{{Code: "good", MaxSessions: 5}},
		TokenTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	srv, err := NewServer(ServerConfig{
		Gate:          g,
		MaxConcurrent: 4,
		IPRate:        RateConfig{RefillPerSec: 1000, Burst: 1000},
		CodeRate:      RateConfig{RefillPerSec: 1000, Burst: 1000},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptestServer(t, srv)

	const nonce = "aa" + "bbccddeeff00112233445566778899"

	first := postJSON(t, ts+RouteSession, createReq{Code: "good", RunNonce: nonce})
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first session status = %d, want 200", first.StatusCode)
	}

	srv.mu.Lock()
	original, ok := srv.sessions[nonce]
	srv.mu.Unlock()
	if !ok {
		t.Fatal("the first session was not stored under its run nonce")
	}

	second := postJSON(t, ts+RouteSession, createReq{Code: "good", RunNonce: nonce})
	_ = second.Body.Close()
	if second.StatusCode == http.StatusOK {
		t.Fatal("a duplicate run nonce must not start a second session")
	}

	srv.mu.Lock()
	current, stillThere := srv.sessions[nonce]
	srv.mu.Unlock()
	if !stillThere {
		t.Fatal("the duplicate request removed the original session")
	}
	if current != original {
		t.Fatal("the duplicate request displaced the original session entry")
	}
}
