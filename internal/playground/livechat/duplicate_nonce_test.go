// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"fmt"
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
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate session status = %d, want 409; any other status lets a regression pass", second.StatusCode)
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

// Concurrent starts on one run nonce must cost exactly one invite allocation.
// Gate.Redeem keys its refund record by the session id, so before the nonce was
// reserved ahead of redemption both racers incremented the code's issued count
// while only the loser's refund could still find a record to undo. Repeating a
// nonce then exhausted a shared code, which is a denial of the demo rather than
// a leak, and it is exactly what an attendee sharing a code would trip.
func TestServer_ConcurrentDuplicateNonceConsumesOneAllocation(t *testing.T) {
	const maxSessions = 3
	g, err := NewGate(GateConfig{
		Secret:   testSecret(t),
		Codes:    []CodeSpec{{Code: "good", MaxSessions: maxSessions}},
		TokenTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	srv, err := NewServer(ServerConfig{
		Gate:          g,
		MaxConcurrent: 8,
		IPRate:        RateConfig{RefillPerSec: 1000, Burst: 1000},
		CodeRate:      RateConfig{RefillPerSec: 1000, Burst: 1000},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptestServer(t, srv)

	const nonce = "cc" + "ddeeff00112233445566778899aabb"

	reserved := make(chan struct{})
	releaseFirst := make(chan struct{})
	defer func() {
		select {
		case <-releaseFirst:
		default:
			close(releaseFirst)
		}
	}()
	srv.beforeGateRedeem = func() {
		close(reserved)
		<-releaseFirst
	}

	firstDone := make(chan int, 1)
	go func() {
		resp := postJSON(t, ts+RouteSession, createReq{Code: "good", RunNonce: nonce})
		_ = resp.Body.Close()
		firstDone <- resp.StatusCode
	}()
	select {
	case <-reserved:
	case <-time.After(time.Second):
		t.Fatal("first request did not reserve its nonce before redeeming the invite")
	}

	secondDone := make(chan int, 1)
	go func() {
		resp := postJSON(t, ts+RouteSession, createReq{Code: "good", RunNonce: nonce})
		_ = resp.Body.Close()
		secondDone <- resp.StatusCode
	}()
	select {
	case status := <-secondDone:
		if status != http.StatusConflict {
			t.Fatalf("duplicate status = %d, want 409 before the first request redeems", status)
		}
	case <-time.After(time.Second):
		t.Fatal("duplicate request reached redemption instead of being refused by the nonce reservation")
	}

	close(releaseFirst)
	select {
	case status := <-firstDone:
		if status != http.StatusOK {
			t.Fatalf("first request status = %d, want 200", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first request did not finish after redemption was released")
	}

	// The refused racer must not have spent budget. Drain the remaining
	// allocations: one was legitimately used, so exactly maxSessions-1 remain.
	for i := 0; i < maxSessions-1; i++ {
		if _, _, err := g.Redeem("good", fmt.Sprintf("drain-%d", i)); err != nil {
			t.Fatalf("allocation %d of the code was consumed by the refused duplicate: %v", i, err)
		}
	}
	if _, _, err := g.Redeem("good", "one-too-many"); err == nil {
		t.Fatal("the code handed out more allocations than it has")
	}
}
