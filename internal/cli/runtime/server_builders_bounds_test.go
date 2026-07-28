// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"testing"
	"time"
)

func newClockedRegistry(now *time.Time) *mcpTrustedSessionRegistry {
	return &mcpTrustedSessionRegistry{
		sessions: make(map[string]time.Time),
		now:      func() time.Time { return *now },
	}
}

// An abandoned session must not pin an entry forever: this registry gates the
// trusted-session requirement for denial-of-wallet, so unbounded growth is a
// denial of service against the enforcement path itself.
func TestMCPTrustedSessionRegistryExpiresIdleSessions(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	registry := newClockedRegistry(&now)

	registry.Register("abandoned")
	if !registry.Known("abandoned") {
		t.Fatal("session unknown immediately after register")
	}

	now = now.Add(mcpTrustedSessionIdleTTL + time.Minute)
	if registry.Known("abandoned") {
		t.Fatal("idle session still trusted past the TTL")
	}
	if len(registry.sessions) != 0 {
		t.Fatalf("expired entry retained: %d", len(registry.sessions))
	}
}

// The TTL is idle-based. A session in continuous use must never expire out from
// under its client, or the client is blocked mid-work by its own liveness.
func TestMCPTrustedSessionRegistryKeepsActiveSessionAlive(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	registry := newClockedRegistry(&now)
	registry.Register("busy")

	// Use it well past the TTL, refreshing each time.
	for range 5 {
		now = now.Add(mcpTrustedSessionIdleTTL - time.Minute)
		if !registry.Known("busy") {
			t.Fatal("active session expired despite continuous use")
		}
	}
}

// At the cap the registry refuses NEW sessions instead of evicting a live one.
// Evicting would let a flood of new sessions silently un-trust sessions already
// in use, which is the eviction bug the subject manager already had to fix.
func TestMCPTrustedSessionRegistryRefusesAtCapWithoutEvictingLiveSessions(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	registry := newClockedRegistry(&now)

	for i := range mcpTrustedSessionMaxEntries {
		registry.Register(fmt.Sprintf("session-%05d", i))
	}
	if len(registry.sessions) != mcpTrustedSessionMaxEntries {
		t.Fatalf("registry holds %d entries, want %d", len(registry.sessions), mcpTrustedSessionMaxEntries)
	}

	registry.Register("overflow")
	if registry.Known("overflow") {
		t.Fatal("registry admitted a session past the cap")
	}
	if len(registry.sessions) != mcpTrustedSessionMaxEntries {
		t.Fatalf("cap exceeded: %d entries", len(registry.sessions))
	}
	// The critical property: the flood did not disturb an existing session.
	if !registry.Known("session-00000") {
		t.Fatal("a live session was evicted to make room for a new one")
	}
}

// Once idle entries age out, the freed space is reusable. Otherwise a single
// burst would wedge the registry closed permanently.
func TestMCPTrustedSessionRegistryReusesSpaceAfterExpiry(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	registry := newClockedRegistry(&now)

	for i := range mcpTrustedSessionMaxEntries {
		registry.Register(fmt.Sprintf("session-%05d", i))
	}
	registry.Register("refused")
	if registry.Known("refused") {
		t.Fatal("admitted past the cap")
	}

	now = now.Add(mcpTrustedSessionIdleTTL + time.Minute)
	registry.Register("after-expiry")
	if !registry.Known("after-expiry") {
		t.Fatal("registry stayed wedged after the earlier entries went idle")
	}
}
