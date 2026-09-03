// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"fmt"
	"net/http"
	"sync"
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
	t.Parallel()

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

	var wg sync.WaitGroup
	codes := make([]int, 2)
	start := make(chan struct{})
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp := postJSON(t, ts+RouteSession, createReq{Code: "good", RunNonce: nonce})
			_ = resp.Body.Close()
			codes[i] = resp.StatusCode
		}()
	}
	close(start)
	wg.Wait()

	var accepted, conflicted int
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			accepted++
		case http.StatusConflict:
			conflicted++
		default:
			t.Fatalf("unexpected status %d; want one 200 and one 409", c)
		}
	}
	if accepted != 1 || conflicted != 1 {
		t.Fatalf("accepted=%d conflicted=%d, want exactly one of each", accepted, conflicted)
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
