// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var resetAuthorityTestNow = time.Date(2026, time.August, 14, 12, 0, 0, 0, time.UTC)

func resetAuthorityEpoch(value uint64) *atomic.Uint64 {
	var epoch atomic.Uint64
	epoch.Store(value)
	return &epoch
}

func TestResetAuthorityRejectsInvalidDelegations(t *testing.T) {
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const target = "mcp://fixture-listener"
	const instanceID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	authority, err := newResetAuthority(pub, target, instanceID, func() time.Time { return resetAuthorityTestNow })
	if err != nil {
		t.Fatal(err)
	}

	mint := func(t *testing.T, private ed25519.PrivateKey, kind ResetKind, delegationTarget, delegationInstance string, epoch uint64, issued, expires time.Time, nonce int) ResetDelegation {
		t.Helper()
		d, err := MintResetDelegation(
			private, ResetDelegationRequest{Issuer: "operator-primary", Kind: kind, Target: delegationTarget, InstanceID: delegationInstance, Epoch: epoch, IssuedAt: issued, ExpiresAt: expires, Nonce: fmt.Sprintf("%032x", nonce)})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	valid := mint(t, privateKey, ResetKindDrift, target, instanceID, 7, resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), 1)

	otherPub, otherPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(otherPub) != ed25519.PublicKeySize {
		t.Fatal("generated alternate key has wrong size")
	}

	tests := []struct {
		name string
		raw  func(t *testing.T) []byte
		want ResetAuthorityResult
	}{
		{
			name: "unsigned",
			raw: func(t *testing.T) []byte {
				d := valid
				d.Signature = ""
				return resetDelegationRaw(t, d)
			},
			want: ResetAuthorityUnsigned,
		},
		{
			// An operator machine running ahead of the proxy mints a delegation
			// stamped in the future. Inside the skew tolerance it must still be
			// accepted, because refusing it strands the operator with a control
			// they cannot reset and no way to tell why.
			name: "future issue time within clock skew is accepted",
			raw: func(t *testing.T) []byte {
				issued := resetAuthorityTestNow.Add(resetDelegationClockSkew / 2)
				return resetDelegationBytes(t, mint(t, privateKey, ResetKindDrift, target, instanceID, 7, issued, issued.Add(time.Minute), 21))
			},
			want: ResetAuthorityAccepted,
		},
		{
			name: "issued beyond clock skew",
			raw: func(t *testing.T) []byte {
				issued := resetAuthorityTestNow.Add(2 * resetDelegationClockSkew)
				return resetDelegationBytes(t, mint(t, privateKey, ResetKindDrift, target, instanceID, 7, issued, issued.Add(time.Minute), 22))
			},
			want: ResetAuthorityNotYetValid,
		},
		{
			name: "expired",
			raw: func(t *testing.T) []byte {
				return resetDelegationBytes(t, mint(t, privateKey, ResetKindDrift, target, instanceID, 7, resetAuthorityTestNow.Add(-2*time.Minute), resetAuthorityTestNow.Add(-time.Minute), 2))
			},
			want: ResetAuthorityExpired,
		},
		{
			name: "wrong kind",
			raw: func(t *testing.T) []byte {
				return resetDelegationBytes(t, mint(t, privateKey, ResetKindAdaptive, target, instanceID, 7, resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), 3))
			},
			want: ResetAuthorityWrongKind,
		},
		{
			name: "wrong target",
			raw: func(t *testing.T) []byte {
				return resetDelegationBytes(t, mint(t, privateKey, ResetKindDrift, "mcp://other-listener", instanceID, 7, resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), 4))
			},
			want: ResetAuthorityWrongTarget,
		},
		{
			name: "wrong instance",
			raw: func(t *testing.T) []byte {
				return resetDelegationBytes(t, mint(t, privateKey, ResetKindDrift, target, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 7, resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), 5))
			},
			want: ResetAuthorityWrongInstance,
		},
		{
			name: "wrong epoch",
			raw: func(t *testing.T) []byte {
				return resetDelegationBytes(t, mint(t, privateKey, ResetKindDrift, target, instanceID, 8, resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), 6))
			},
			want: ResetAuthorityWrongEpoch,
		},
		{
			name: "wrong key",
			raw: func(t *testing.T) []byte {
				return resetDelegationBytes(t, mint(t, otherPrivate, ResetKindDrift, target, instanceID, 7, resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), 7))
			},
			want: ResetAuthorityWrongKey,
		},
		{
			name: "signature tampered",
			raw: func(t *testing.T) []byte {
				d := valid
				d.Target = "mcp://other-listener"
				return resetDelegationRaw(t, d)
			},
			want: ResetAuthorityWrongKey,
		},
		{
			name: "issuer fingerprint mismatch",
			raw: func(t *testing.T) []byte {
				d := valid
				d.IssuerFingerprint = "sha256:" + strings.Repeat("0", 64)
				return resetDelegationBytes(t, resignResetDelegation(t, privateKey, d))
			},
			want: ResetAuthorityWrongKey,
		},
		{
			name: "wrong purpose",
			raw: func(t *testing.T) []byte {
				d := valid
				d.Purpose = "receipt-signing"
				return resetDelegationRaw(t, d)
			},
			want: ResetAuthorityWrongPurpose,
		},
		{
			name: "truncated",
			raw: func(t *testing.T) []byte {
				return []byte("{\"schema_version\":1,\"purpose\":\"mcp-reset-authority\"")
			},
			want: ResetAuthorityMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "reset.json")
			if err := os.WriteFile(path, tt.raw(t), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(resetAuthorityEpoch(7))).Result; got != tt.want {
				t.Fatalf("result = %q, want %q", got, tt.want)
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("rejected delegation remained at control path: %v", err)
			}
		})
	}
}

func TestResetAuthorityConsumesNonceOnceAndRejectsAfterRestart(t *testing.T) {
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const target = "mcp://fixture-listener"
	const instanceID = "cccccccccccccccccccccccccccccccc"
	authority, err := newResetAuthority(pub, target, instanceID, func() time.Time { return resetAuthorityTestNow })
	if err != nil {
		t.Fatal(err)
	}
	d, err := MintResetDelegation(
		privateKey, ResetDelegationRequest{Issuer: "operator-primary", Kind: ResetKindDrift, Target: target, InstanceID: instanceID, Epoch: 7, IssuedAt: resetAuthorityTestNow, ExpiresAt: resetAuthorityTestNow.Add(time.Minute), Nonce: strings.Repeat("d", 32)})
	if err != nil {
		t.Fatal(err)
	}
	raw := resetDelegationBytes(t, d)
	path := filepath.Join(t.TempDir(), "reset.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(resetAuthorityEpoch(7))).Result; got != ResetAuthorityAccepted {
		t.Fatalf("first consume = %q, want accepted", got)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(resetAuthorityEpoch(7))).Result; got != ResetAuthorityReplayed {
		t.Fatalf("replay consume = %q, want replayed", got)
	}

	restarted, err := newResetAuthority(pub, target, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", func() time.Time { return resetAuthorityTestNow })
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := restarted.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(resetAuthorityEpoch(7))).Result; got != ResetAuthorityWrongInstance {
		t.Fatalf("post-restart consume = %q, want wrong instance", got)
	}
}

func TestResetAuthorityConsumesEpochExactlyOnceUnderConcurrentDelegations(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newResetAuthority(publicKey, "mcp://concurrent-reset", strings.Repeat("a", 32), func() time.Time {
		return resetAuthorityTestNow
	})
	if err != nil {
		t.Fatal(err)
	}

	paths := make([]string, 2)
	for i := range paths {
		paths[i] = filepath.Join(t.TempDir(), fmt.Sprintf("reset-%d", i))
		delegation, err := MintResetDelegation(
			privateKey, ResetDelegationRequest{Issuer: "operator-primary", Kind: ResetKindDrift, Target: authority.Target(), InstanceID: authority.InstanceID(), Epoch: 0, IssuedAt: resetAuthorityTestNow, ExpiresAt: resetAuthorityTestNow.Add(time.Minute), Nonce: fmt.Sprintf("%032x", i+1)})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(paths[i], resetDelegationBytes(t, delegation), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var epoch atomic.Uint64
	gate := make(chan struct{})
	results := make(chan ResetAuthorityResult, len(paths))
	var wg sync.WaitGroup
	for _, path := range paths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			<-gate
			results <- authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(&epoch)).Result
		}(path)
	}
	close(gate)
	wg.Wait()
	close(results)

	var accepted, wrongEpoch int
	for result := range results {
		switch result {
		case ResetAuthorityAccepted:
			accepted++
		case ResetAuthorityWrongEpoch:
			wrongEpoch++
		default:
			t.Fatalf("concurrent reset result = %q, want accepted or wrong_epoch", result)
		}
	}
	if accepted != 1 || wrongEpoch != 1 || epoch.Load() != 1 {
		t.Fatalf("concurrent reset accepted=%d wrong_epoch=%d epoch=%d, want 1/1/1", accepted, wrongEpoch, epoch.Load())
	}
}

func TestResetAuthorityRejectsDelegationAfterEpochAdvances(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newResetAuthority(publicKey, "mcp://advanced-epoch", strings.Repeat("a", 32), func() time.Time {
		return resetAuthorityTestNow
	})
	if err != nil {
		t.Fatal(err)
	}
	var epoch atomic.Uint64
	path := filepath.Join(t.TempDir(), "reset")
	writeDelegation := func(nonce string) {
		t.Helper()
		delegation, err := MintResetDelegation(
			privateKey, ResetDelegationRequest{Issuer: "operator-primary", Kind: ResetKindDrift, Target: authority.Target(), InstanceID: authority.InstanceID(), Epoch: 0, IssuedAt: resetAuthorityTestNow, ExpiresAt: resetAuthorityTestNow.Add(time.Minute), Nonce: nonce})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, resetDelegationBytes(t, delegation), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	writeDelegation(strings.Repeat("b", 32))
	if decision := authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(&epoch)); decision.Result != ResetAuthorityAccepted {
		t.Fatalf("first delegation result = %+v", decision)
	}
	writeDelegation(strings.Repeat("c", 32))
	if decision := authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(&epoch)); decision.Result != ResetAuthorityWrongEpoch || decision.ExpectedEpoch != 1 {
		t.Fatalf("delegation for spent epoch result = %+v, want wrong_epoch at 1", decision)
	}
	if got := epoch.Load(); got != 1 {
		t.Fatalf("stale delegation advanced epoch to %d, want 1", got)
	}
}

func TestResetAuthorityConsumesSamePathExactlyOnceConcurrently(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newResetAuthority(publicKey, "mcp://same-path-reset", strings.Repeat("a", 32), func() time.Time {
		return resetAuthorityTestNow
	})
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := MintResetDelegation(
		privateKey, ResetDelegationRequest{Issuer: "operator-primary", Kind: ResetKindDrift, Target: authority.Target(), InstanceID: authority.InstanceID(), Epoch: 0, IssuedAt: resetAuthorityTestNow, ExpiresAt: resetAuthorityTestNow.Add(time.Minute), Nonce: strings.Repeat("b", 32)})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "reset")
	if err := os.WriteFile(path, resetDelegationBytes(t, delegation), 0o600); err != nil {
		t.Fatal(err)
	}
	var epoch atomic.Uint64
	start := make(chan struct{})
	results := make(chan ResetAuthorityResult, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(&epoch)).Result
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	accepted := 0
	for result := range results {
		if result == ResetAuthorityAccepted {
			accepted++
		}
	}
	if accepted != 1 || epoch.Load() != 1 {
		t.Fatalf("same-path concurrent accepted=%d epoch=%d, want 1/1", accepted, epoch.Load())
	}
}

func TestResetAuthorityRejectsMissingEpoch(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newResetAuthority(publicKey, "mcp://missing-epoch", strings.Repeat("a", 32), func() time.Time {
		return resetAuthorityTestNow
	})
	if err != nil {
		t.Fatal(err)
	}
	if epoch := newResetAtomicEpoch(nil); epoch != nil {
		t.Fatal("nil atomic epoch produced a reset epoch")
	}
	if decision := authority.ConsumeFile(filepath.Join(t.TempDir(), "reset"), ResetKindDrift, nil); decision.Result != ResetAuthorityUnreadable {
		t.Fatalf("missing epoch decision = %+v, want unreadable", decision)
	}
}

func TestResetAuthorityEvictsExpiredNonceWithoutPermittingExpiredReplay(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := resetAuthorityTestNow
	authority, err := newResetAuthority(publicKey, "mcp://expired-nonce", strings.Repeat("a", 32), func() time.Time {
		return now
	})
	if err != nil {
		t.Fatal(err)
	}

	expiredNonce := strings.Repeat("b", 32)
	expired, err := MintResetDelegation(
		privateKey, ResetDelegationRequest{Issuer: "operator-primary", Kind: ResetKindDrift, Target: authority.Target(), InstanceID: authority.InstanceID(), Epoch: 0, IssuedAt: now, ExpiresAt: now.Add(time.Second), Nonce: expiredNonce})
	if err != nil {
		t.Fatal(err)
	}
	expiredRaw := resetDelegationBytes(t, expired)
	path := filepath.Join(t.TempDir(), "reset")
	if err := os.WriteFile(path, expiredRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	var epoch atomic.Uint64
	if decision := authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(&epoch)); decision.Result != ResetAuthorityAccepted {
		t.Fatalf("consume expiring delegation = %+v", decision)
	}

	now = now.Add(2 * time.Second)
	fresh, err := MintResetDelegation(
		privateKey, ResetDelegationRequest{Issuer: "operator-primary", Kind: ResetKindDrift, Target: authority.Target(), InstanceID: authority.InstanceID(), Epoch: epoch.Load(), IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: strings.Repeat("c", 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, resetDelegationBytes(t, fresh), 0o600); err != nil {
		t.Fatal(err)
	}
	if decision := authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(&epoch)); decision.Result != ResetAuthorityAccepted {
		t.Fatalf("consume after expiry eviction = %+v", decision)
	}
	authority.mu.Lock()
	_, retained := authority.consumed[expiredNonce]
	authority.mu.Unlock()
	if retained {
		t.Fatal("expired nonce remained in the consumed ledger")
	}

	if err := os.WriteFile(path, expiredRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if decision := authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(resetAuthorityEpoch(0))); decision.Result != ResetAuthorityExpired {
		t.Fatalf("expired delegation after eviction = %+v, want expired", decision)
	}
}

func TestResetAuthorityDeniesLiveNonceLedgerCapacity(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newResetAuthority(publicKey, "mcp://nonce-capacity", strings.Repeat("a", 32), func() time.Time {
		return resetAuthorityTestNow
	})
	if err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	for i := 0; i < maxResetConsumedNonces; i++ {
		authority.consumed[fmt.Sprintf("%032x", i)] = resetAuthorityTestNow.Add(time.Minute)
	}
	authority.mu.Unlock()

	delegation, err := MintResetDelegation(
		privateKey, ResetDelegationRequest{Issuer: "operator-primary", Kind: ResetKindDrift, Target: authority.Target(), InstanceID: authority.InstanceID(), Epoch: 0, IssuedAt: resetAuthorityTestNow, ExpiresAt: resetAuthorityTestNow.Add(time.Minute), Nonce: strings.Repeat("f", 32)})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "reset")
	if err := os.WriteFile(path, resetDelegationBytes(t, delegation), 0o600); err != nil {
		t.Fatal(err)
	}
	var epoch atomic.Uint64
	if decision := authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(&epoch)); decision.Result != ResetAuthorityCapacity {
		t.Fatalf("capacity decision = %+v, want %q", decision, ResetAuthorityCapacity)
	}
	if epoch.Load() != 0 {
		t.Fatalf("capacity denial advanced epoch to %d", epoch.Load())
	}
	authority.mu.Lock()
	count := len(authority.consumed)
	_, retained := authority.consumed[fmt.Sprintf("%032x", 0)]
	authority.mu.Unlock()
	if count != maxResetConsumedNonces || !retained {
		t.Fatalf("capacity denial retained %d live nonces and first=%v, want %d/true", count, retained, maxResetConsumedNonces)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("capacity-denied delegation remained at control path: %v", err)
	}
}

func TestResetAuthorityNonceLedgerCapacityPurgesOnlyExpiredEntries(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := resetAuthorityTestNow
	authority, err := newResetAuthority(publicKey, "mcp://nonce-capacity-boundary", strings.Repeat("a", 32), func() time.Time {
		return now
	})
	if err != nil {
		t.Fatal(err)
	}

	const expiredEntries = 2
	authority.mu.Lock()
	for i := 0; i < expiredEntries; i++ {
		authority.consumed[fmt.Sprintf("expired-%030x", i)] = now.Add(-time.Second)
	}
	for i := 0; i < maxResetConsumedNonces-expiredEntries; i++ {
		authority.consumed[fmt.Sprintf("live-%033x", i)] = now.Add(time.Minute)
	}
	authority.mu.Unlock()

	var epoch atomic.Uint64
	path := filepath.Join(t.TempDir(), "reset")
	consume := func(nonce string) ResetAuthorityDecision {
		t.Helper()
		delegation, err := MintResetDelegation(
			privateKey, ResetDelegationRequest{Issuer: "operator-primary", Kind: ResetKindDrift, Target: authority.Target(), InstanceID: authority.InstanceID(), Epoch: epoch.Load(), IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: nonce})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, resetDelegationBytes(t, delegation), 0o600); err != nil {
			t.Fatal(err)
		}
		return authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(&epoch))
	}

	if decision := consume(strings.Repeat("b", 32)); decision.Result != ResetAuthorityAccepted {
		t.Fatalf("consume below capacity after expiry purge = %+v", decision)
	}
	authority.mu.Lock()
	count := len(authority.consumed)
	_, expiredRetained := authority.consumed[fmt.Sprintf("expired-%030x", 0)]
	_, liveRetained := authority.consumed[fmt.Sprintf("live-%033x", 0)]
	authority.mu.Unlock()
	if count != maxResetConsumedNonces-1 || expiredRetained || !liveRetained {
		t.Fatalf("post-purge ledger count=%d expired_retained=%v live_retained=%v, want %d/false/true", count, expiredRetained, liveRetained, maxResetConsumedNonces-1)
	}

	if decision := consume(strings.Repeat("c", 32)); decision.Result != ResetAuthorityAccepted {
		t.Fatalf("consume at capacity boundary = %+v", decision)
	}
	if decision := consume(strings.Repeat("d", 32)); decision.Result != ResetAuthorityCapacity {
		t.Fatalf("consume over capacity = %+v, want capacity_exceeded", decision)
	}
	if got := epoch.Load(); got != 2 {
		t.Fatalf("capacity denial advanced epoch to %d, want 2", got)
	}
	authority.mu.Lock()
	count = len(authority.consumed)
	_, liveRetained = authority.consumed[fmt.Sprintf("live-%033x", 0)]
	authority.mu.Unlock()
	if count != maxResetConsumedNonces || !liveRetained {
		t.Fatalf("capacity denial ledger count=%d live_retained=%v, want %d/true", count, liveRetained, maxResetConsumedNonces)
	}

	overfull, err := newResetAuthority(publicKey, "mcp://nonce-capacity-overfull", strings.Repeat("b", 32), func() time.Time {
		return now
	})
	if err != nil {
		t.Fatal(err)
	}
	overfull.mu.Lock()
	for i := 0; i < maxResetConsumedNonces+1; i++ {
		overfull.consumed[fmt.Sprintf("live-%033x", i)] = now.Add(time.Minute)
	}
	overfull.mu.Unlock()
	overfullPath := filepath.Join(t.TempDir(), "overfull-reset")
	overfullDelegation, err := MintResetDelegation(
		privateKey, ResetDelegationRequest{Issuer: "operator-primary", Kind: ResetKindDrift, Target: overfull.Target(), InstanceID: overfull.InstanceID(), Epoch: 0, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: strings.Repeat("e", 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overfullPath, resetDelegationBytes(t, overfullDelegation), 0o600); err != nil {
		t.Fatal(err)
	}
	var overfullEpoch atomic.Uint64
	if decision := overfull.ConsumeFile(overfullPath, ResetKindDrift, newResetAtomicEpoch(&overfullEpoch)); decision.Result != ResetAuthorityCapacity {
		t.Fatalf("overfull ledger decision = %+v, want capacity_exceeded", decision)
	}
	overfull.mu.Lock()
	count = len(overfull.consumed)
	overfull.mu.Unlock()
	if count != maxResetConsumedNonces+1 || overfullEpoch.Load() != 0 {
		t.Fatalf("overfull ledger count=%d epoch=%d, want %d/0", count, overfullEpoch.Load(), maxResetConsumedNonces+1)
	}
}

func TestResetAuthorityMalformedRejectionReportsCurrentBinding(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newResetAuthority(publicKey, "mcp://diagnostic-binding", strings.Repeat("a", 32), func() time.Time {
		return resetAuthorityTestNow
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "reset")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if decision := authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(resetAuthorityEpoch(9))); decision.Result != ResetAuthorityMalformed ||
		decision.ExpectedTarget != authority.Target() || decision.ExpectedInstanceID != authority.InstanceID() || decision.ExpectedEpoch != 9 {
		t.Fatalf("malformed rejection diagnostics = %+v", decision)
	}
}

func TestResetDelegationRejectsMalformedArtifactsAndMissingRemovalPath(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newResetAuthority(publicKey, "mcp://fixture-listener", strings.Repeat("e", 32), func() time.Time {
		return resetAuthorityTestNow
	})
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := MintResetDelegation(
		privateKey, ResetDelegationRequest{Issuer: "operator-primary", Kind: ResetKindDrift, Target: authority.Target(), InstanceID: authority.InstanceID(), Epoch: 0, IssuedAt: resetAuthorityTestNow, ExpiresAt: resetAuthorityTestNow.Add(time.Minute), Nonce: strings.Repeat("f", 32)})
	if err != nil {
		t.Fatal(err)
	}

	invalidInput := delegation
	invalidInput.Kind = "unknown"
	if got := authority.verify(invalidInput, ResetKindDrift, 0); got != ResetAuthorityMalformed {
		t.Fatalf("malformed delegation verification = %q, want malformed", got)
	}
	if _, err := MarshalResetDelegation(invalidInput); err == nil {
		t.Fatal("MarshalResetDelegation accepted an invalid delegation kind")
	}

	invalidSignature := delegation
	invalidSignature.Signature = "not-base64"
	if err := VerifyResetDelegationSignature(publicKey, invalidSignature); err == nil {
		t.Fatal("VerifyResetDelegationSignature accepted malformed signature encoding")
	}

	path := filepath.Join(t.TempDir(), "reset.json")
	if err := os.WriteFile(path, []byte("delegation"), 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := removeResetDelegationFile(path, opened); err == nil {
		t.Fatal("remove reset delegation accepted a vanished control path")
	}
}

func TestResetDelegationCanonicalInputIsStable(t *testing.T) {
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	d, err := MintResetDelegation(
		privateKey, ResetDelegationRequest{Issuer: "operator-primary", Kind: ResetKindAdaptive, Target: "mcp://stdio/code-assistant", InstanceID: "ffffffffffffffffffffffffffffffff", Epoch: 0, IssuedAt: resetAuthorityTestNow, ExpiresAt: resetAuthorityTestNow.Add(time.Minute), Nonce: strings.Repeat("1", 32)})
	if err != nil {
		t.Fatal(err)
	}
	input, err := CanonicalResetDelegationInput(d)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, input, mustResetSignature(t, d.Signature)) {
		t.Fatal("canonical reset delegation input did not verify")
	}
	var decoded ResetDelegation
	if err := json.Unmarshal(resetDelegationBytes(t, d), &decoded); err != nil {
		t.Fatal(err)
	}
	roundTrip, err := CanonicalResetDelegationInput(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(input) != string(roundTrip) {
		t.Fatalf("canonical input changed across JSON round trip:\n%s\n%s", input, roundTrip)
	}
}

func resetDelegationBytes(t *testing.T, d ResetDelegation) []byte {
	t.Helper()
	raw, err := MarshalResetDelegation(d)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func resetDelegationRaw(t *testing.T, d ResetDelegation) []byte {
	t.Helper()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustResetSignature(t *testing.T, encoded string) []byte {
	t.Helper()
	sig, err := decodeResetSignature(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func resignResetDelegation(t *testing.T, privateKey ed25519.PrivateKey, d ResetDelegation) ResetDelegation {
	t.Helper()
	input, err := CanonicalResetDelegationInput(d)
	if err != nil {
		t.Fatal(err)
	}
	d.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, input))
	return d
}

func TestNewResetAuthorityValidatesLiveBindings(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		publicKey  ed25519.PublicKey
		target     string
		instanceID string
		now        func() time.Time
	}{
		{name: "short public key", publicKey: pub[:ed25519.PublicKeySize-1], target: "mcp://fixture", instanceID: strings.Repeat("a", 32), now: time.Now},
		{name: "blank target", publicKey: pub, target: " ", instanceID: strings.Repeat("a", 32), now: time.Now},
		{name: "invalid instance", publicKey: pub, target: "mcp://fixture", instanceID: "not-hex", now: time.Now},
		{name: "nil clock", publicKey: pub, target: "mcp://fixture", instanceID: strings.Repeat("a", 32), now: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if authority, err := newResetAuthority(test.publicKey, test.target, test.instanceID, test.now); err == nil || authority != nil {
				t.Fatalf("newResetAuthority() = %v, %v; want validation failure", authority, err)
			}
		})
	}

	authority, err := newResetAuthority(pub, "mcp://fixture", strings.Repeat("b", 32), func() time.Time { return resetAuthorityTestNow })
	if err != nil {
		t.Fatalf("newResetAuthority: %v", err)
	}
	if authority.Target() != "mcp://fixture" || authority.InstanceID() != strings.Repeat("b", 32) {
		t.Fatalf("live bindings = target=%q instance=%q", authority.Target(), authority.InstanceID())
	}
	if (*ResetAuthority)(nil).Target() != "" || (*ResetAuthority)(nil).InstanceID() != "" {
		t.Fatal("nil reset authority exposed live bindings")
	}

	generated, err := NewResetAuthority(pub, "mcp://generated")
	if err != nil {
		t.Fatalf("NewResetAuthority: %v", err)
	}
	if err := validateResetHex("instance_id", generated.InstanceID()); err != nil {
		t.Fatalf("generated instance ID = %q: %v", generated.InstanceID(), err)
	}
	if nonce, err := NewResetNonce(); err != nil || validateResetHex("nonce", nonce) != nil {
		t.Fatalf("NewResetNonce() = %q, %v", nonce, err)
	}
}

func TestMintResetDelegationRejectsInvalidAuthorityInputs(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issued := resetAuthorityTestNow
	validInstance := strings.Repeat("a", 32)
	validNonce := strings.Repeat("b", 32)

	tests := []struct {
		name       string
		privateKey ed25519.PrivateKey
		kind       ResetKind
		target     string
		instanceID string
		nonce      string
		issuer     string
		expires    time.Time
	}{
		{name: "short private key", privateKey: privateKey[:ed25519.PrivateKeySize-1], kind: ResetKindDrift, target: "mcp://fixture", instanceID: validInstance, nonce: validNonce, issuer: "operator", expires: issued.Add(time.Minute)},
		{name: "inconsistent private key", privateKey: ed25519.PrivateKey(bytes.Repeat([]byte{1}, ed25519.PrivateKeySize)), kind: ResetKindDrift, target: "mcp://fixture", instanceID: validInstance, nonce: validNonce, issuer: "operator", expires: issued.Add(time.Minute)},
		{name: "invalid kind", privateKey: privateKey, kind: ResetKind("other"), target: "mcp://fixture", instanceID: validInstance, nonce: validNonce, issuer: "operator", expires: issued.Add(time.Minute)},
		{name: "invalid target", privateKey: privateKey, kind: ResetKindDrift, target: "bad\nvalue", instanceID: validInstance, nonce: validNonce, issuer: "operator", expires: issued.Add(time.Minute)},
		{name: "invalid instance", privateKey: privateKey, kind: ResetKindDrift, target: "mcp://fixture", instanceID: "bad", nonce: validNonce, issuer: "operator", expires: issued.Add(time.Minute)},
		{name: "invalid nonce", privateKey: privateKey, kind: ResetKindDrift, target: "mcp://fixture", instanceID: validInstance, nonce: "bad", issuer: "operator", expires: issued.Add(time.Minute)},
		{name: "invalid issuer", privateKey: privateKey, kind: ResetKindDrift, target: "mcp://fixture", instanceID: validInstance, nonce: validNonce, issuer: "", expires: issued.Add(time.Minute)},
		{name: "expired at issue", privateKey: privateKey, kind: ResetKindDrift, target: "mcp://fixture", instanceID: validInstance, nonce: validNonce, issuer: "operator", expires: issued},
		{name: "ttl too long", privateKey: privateKey, kind: ResetKindDrift, target: "mcp://fixture", instanceID: validInstance, nonce: validNonce, issuer: "operator", expires: issued.Add(resetDelegationMaxTTL + time.Second)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if delegation, err := MintResetDelegation(test.privateKey, ResetDelegationRequest{Issuer: test.issuer, Kind: test.kind, Target: test.target, InstanceID: test.instanceID, Epoch: 0, IssuedAt: issued, ExpiresAt: test.expires, Nonce: test.nonce}); err == nil || delegation != (ResetDelegation{}) {
				t.Fatalf("MintResetDelegation() = %+v, %v; want validation failure", delegation, err)
			}
		})
	}
}

func TestResetDelegationFileOperationsAreBoundedAndPathSafe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission and symlink semantics")
	}
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newResetAuthority(pub, "mcp://fixture", strings.Repeat("c", 32), func() time.Time { return resetAuthorityTestNow })
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := MintResetDelegation(privateKey, ResetDelegationRequest{Issuer: "operator", Kind: ResetKindDrift, Target: authority.Target(), InstanceID: authority.InstanceID(), Epoch: 0, IssuedAt: resetAuthorityTestNow, ExpiresAt: resetAuthorityTestNow.Add(time.Minute), Nonce: strings.Repeat("d", 32)})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "delegation")
	raw := resetDelegationBytes(t, delegation)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, opened, err := readResetDelegationFile(path); err != nil || !bytes.Equal(got, raw) || opened == nil {
		t.Fatalf("read reset file = %q, %v, %v", got, opened, err)
	}

	unreadable := filepath.Join(dir, "unreadable")
	if err := os.WriteFile(unreadable, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readResetDelegationFile(unreadable); err == nil {
		t.Fatal("unreadable reset delegation was accepted")
	}
	if err := os.Chmod(unreadable, 0o600); err != nil {
		t.Fatal(err)
	}

	oversized := filepath.Join(dir, "oversized")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, resetDelegationMaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readResetDelegationFile(oversized); err == nil {
		t.Fatal("oversized reset delegation was accepted")
	}
	if _, _, err := readResetDelegationFile(dir); err == nil {
		t.Fatal("directory reset delegation was accepted")
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readResetDelegationFile(link); err == nil {
		t.Fatal("symlink reset delegation was accepted")
	}

	opened, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeResetDelegationFile(path, opened); err == nil {
		t.Fatal("replacement at reset path was removed")
	}

	if decision := authority.ConsumeFile("", ResetKindDrift, newResetAtomicEpoch(resetAuthorityEpoch(0))); decision.Result != ResetAuthorityAbsent {
		t.Fatalf("empty reset path decision = %+v", decision)
	}
	if decision := (*ResetAuthority)(nil).ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(resetAuthorityEpoch(0))); decision.Result != ResetAuthorityAbsent {
		t.Fatalf("nil reset authority decision = %+v", decision)
	}
}

func TestResetDelegationParsingAndVerificationRejectsMalformedArtifacts(t *testing.T) {
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := MintResetDelegation(privateKey, ResetDelegationRequest{Issuer: "operator", Kind: ResetKindAdaptive, Target: "mcp://fixture", InstanceID: strings.Repeat("e", 32), Epoch: 3, IssuedAt: resetAuthorityTestNow, ExpiresAt: resetAuthorityTestNow.Add(time.Minute), Nonce: strings.Repeat("f", 32)})
	if err != nil {
		t.Fatal(err)
	}
	raw := resetDelegationBytes(t, delegation)
	if parsed, err := ParseResetDelegation(raw); err != nil || parsed.Nonce != delegation.Nonce {
		t.Fatalf("ParseResetDelegation() = %+v, %v", parsed, err)
	}
	if err := VerifyResetDelegationSignature(pub, delegation); err != nil {
		t.Fatalf("VerifyResetDelegationSignature(valid) = %v", err)
	}

	withoutSignature := delegation
	withoutSignature.Signature = ""
	if _, err := MarshalResetDelegation(withoutSignature); err == nil {
		t.Fatal("MarshalResetDelegation accepted unsigned delegation")
	}
	if err := VerifyResetDelegationSignature(pub[:ed25519.PublicKeySize-1], delegation); err == nil {
		t.Fatal("VerifyResetDelegationSignature accepted short public key")
	}
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResetDelegationSignature(otherPub, delegation); err == nil {
		t.Fatal("VerifyResetDelegationSignature accepted another authority key")
	}
	if _, err := ParseResetDelegation(append(bytes.TrimSpace(raw), []byte(" trailing")...)); err == nil {
		t.Fatal("ParseResetDelegation accepted trailing data")
	}
	if _, err := ParseResetDelegation([]byte(`{"schema_version":1,"purpose":"mcp-reset-authority","extra":true}`)); err == nil {
		t.Fatal("ParseResetDelegation accepted unknown fields")
	}

	tests := []struct {
		name string
		mut  func(*ResetDelegation)
	}{
		{name: "schema version", mut: func(d *ResetDelegation) { d.SchemaVersion++ }},
		{name: "purpose", mut: func(d *ResetDelegation) { d.Purpose = "other" }},
		{name: "kind", mut: func(d *ResetDelegation) { d.Kind = "other" }},
		{name: "target", mut: func(d *ResetDelegation) { d.Target = "\x00" }},
		{name: "instance", mut: func(d *ResetDelegation) { d.InstanceID = "bad" }},
		{name: "nonce", mut: func(d *ResetDelegation) { d.Nonce = "bad" }},
		{name: "issuer", mut: func(d *ResetDelegation) { d.Issuer = "\n" }},
		{name: "fingerprint", mut: func(d *ResetDelegation) { d.IssuerFingerprint = "not-a-fingerprint" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := delegation
			test.mut(&invalid)
			if _, err := invalid.signingInput(); err == nil {
				t.Fatalf("signingInput accepted invalid %s", test.name)
			}
		})
	}

	for _, encoded := range []string{"", "not-base64", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := decodeResetSignature(encoded); err == nil {
			t.Fatalf("decodeResetSignature(%q) succeeded", encoded)
		}
	}
}

func TestResetAuthorityRejectsSignedOverlongDelegationAndPreservesRemovalFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX non-removable directory semantics")
	}
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newResetAuthority(pub, "mcp://fixture", strings.Repeat("a", 32), func() time.Time { return resetAuthorityTestNow })
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := MintResetDelegation(privateKey, ResetDelegationRequest{Issuer: "operator", Kind: ResetKindDrift, Target: authority.Target(), InstanceID: authority.InstanceID(), Epoch: 0, IssuedAt: resetAuthorityTestNow, ExpiresAt: resetAuthorityTestNow.Add(time.Minute), Nonce: strings.Repeat("b", 32)})
	if err != nil {
		t.Fatal(err)
	}

	overlong := delegation
	overlong.ExpiresUnix = resetAuthorityTestNow.Add(resetDelegationMaxTTL + time.Second).Unix()
	overlong = resignResetDelegation(t, privateKey, overlong)
	if got := authority.verify(overlong, ResetKindDrift, 0); got != ResetAuthorityMalformed {
		t.Fatalf("signed overlong delegation result = %q, want malformed", got)
	}
	raw := resetDelegationRaw(t, overlong)
	if parsed, err := ParseResetDelegation(raw); err != nil || parsed.ExpiresUnix != overlong.ExpiresUnix {
		t.Fatalf("ParseResetDelegation(signed overlong) = %+v, %v", parsed, err)
	}

	invalid := delegation
	invalid.Kind = ResetKind("invalid")
	if err := VerifyResetDelegationSignature(pub, invalid); err == nil {
		t.Fatal("VerifyResetDelegationSignature accepted an invalid signed payload")
	}
	if _, err := ParseResetDelegation(resetDelegationRaw(t, invalid)); err == nil {
		t.Fatal("ParseResetDelegation accepted invalid signed fields")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "reset")
	if err := os.WriteFile(path, resetDelegationBytes(t, delegation), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { // #nosec G302 -- test needs a searchable but unwritable directory.
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restores the directory so t.TempDir cleanup can remove it.
	if decision := authority.ConsumeFile(path, ResetKindDrift, newResetAtomicEpoch(resetAuthorityEpoch(0))); decision.Result != ResetAuthorityRemoveFailed {
		t.Fatalf("readable but non-removable reset decision = %+v", decision)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("remove failure deleted the delegation: %v", err)
	}

	if got := resetReadResult(os.ErrNotExist); got != ResetAuthorityAbsent {
		t.Fatalf("not-exist read result = %q", got)
	}
	if got := resetReadResult(errors.New("read denied")); got != ResetAuthorityUnreadable {
		t.Fatalf("read failure result = %q", got)
	}
	if got := removeResetResult(fmt.Errorf("wrapped path race: %w", errResetPathChanged)); got != ResetAuthorityPathChanged {
		t.Fatalf("path-changed remove result = %q", got)
	}
	if got := removeResetResult(errors.New("remove denied")); got != ResetAuthorityRemoveFailed {
		t.Fatalf("remove failure result = %q", got)
	}
}
