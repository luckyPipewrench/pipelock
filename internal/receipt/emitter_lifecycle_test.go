// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// SignerKeyHex is how reload code decides whether a config change is a
// policy-only reload or a signer rotation, and a rotation retires the live
// emitter. A wrong answer in either direction is consequential: a missed
// rotation keeps signing under a key the operator replaced, and a spurious
// rotation retires a healthy emitter. It had no test.
func TestEmitter_SignerKeyHex(t *testing.T) {
	t.Parallel()

	t.Run("nil emitter reports empty", func(t *testing.T) {
		t.Parallel()
		var e *Emitter
		if got := e.SignerKeyHex(); got != "" {
			t.Errorf("SignerKeyHex() on nil emitter = %q, want empty", got)
		}
	})

	t.Run("short key reports empty rather than a truncated key", func(t *testing.T) {
		t.Parallel()
		e := &Emitter{privKey: ed25519.PrivateKey("too-short")}
		if got := e.SignerKeyHex(); got != "" {
			t.Errorf("SignerKeyHex() with a short key = %q, want empty", got)
		}
	})

	t.Run("reports the public key matching the signing key", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		pub, priv := generateTestKey(t)
		rec := newTestRecorder(t, dir, priv)
		defer func() { _ = rec.Close() }()

		e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv})
		if e == nil {
			t.Fatal("NewEmitter returned nil")
		}

		want := hex.EncodeToString(pub)
		if got := e.SignerKeyHex(); got != want {
			t.Fatalf("SignerKeyHex() = %q, want %q", got, want)
		}
		// A different key must produce a different answer, or the comparison
		// reload relies on could never detect a rotation.
		otherPub, otherPriv := generateTestKey(t)
		other := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: otherPriv})
		if other == nil {
			t.Fatal("NewEmitter returned nil for the second key")
		}
		if got := other.SignerKeyHex(); got != hex.EncodeToString(otherPub) {
			t.Fatalf("second emitter SignerKeyHex() = %q, want %q", got, hex.EncodeToString(otherPub))
		}
		if e.SignerKeyHex() == other.SignerKeyHex() {
			t.Fatal("two distinct signing keys reported the same hex; a rotation would be invisible")
		}
	})
}

// RetireNativeAEL bricks the emitter after a signer rotation so that a stale
// caller, or one already admitted past the policy check, cannot append a
// receipt signed by the retired key. The brick is the security property; that
// the call returns nil is not. Assert the refusal.
func TestEmitter_RetireNativeAELBricksFurtherEmission(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()

	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv})
	if e == nil {
		t.Fatal("NewEmitter returned nil")
	}

	emit := func() error {
		return e.Emit(EmitOpts{
			ActionID:  NewActionID(),
			Target:    testTarget,
			Verdict:   config.ActionAllow,
			Transport: testTransport,
			Method:    http.MethodGet,
		})
	}

	// Control: emission works before retirement, so a later failure is
	// attributable to the retirement and not to a broken fixture.
	if err := emit(); err != nil {
		t.Fatalf("Emit before retirement failed: %v", err)
	}
	// Calibrate the counter used below. A reader that always returned the same
	// number would make the no-append assertion vacuous, so require it to
	// observe this known-good emit before trusting it to observe an absence.
	if got := len(readReceiptsRaw(t, dir)); got == 0 {
		t.Fatal("receipt reader saw 0 receipts after a successful emit; it cannot detect an append, so the assertion below would be vacuous")
	}

	if err := e.RetireNativeAEL(); err != nil {
		t.Fatalf("RetireNativeAEL: %v", err)
	}

	// Count what is on disk before the refused emit. Asserting only that Emit
	// returns an error would still pass an implementation that appended the
	// receipt and reported unhealthy afterwards, and the receipt landing is
	// the thing retirement exists to prevent.
	before := len(readReceiptsRaw(t, dir))

	err := emit()
	if err == nil {
		t.Fatal("Emit succeeded after RetireNativeAEL; a retired emitter must not append under the rotated-out key")
	}
	if after := len(readReceiptsRaw(t, dir)); after != before {
		t.Fatalf("receipt count went %d -> %d after a refused emit; a retired emitter appended under the rotated-out key", before, after)
	}
	if !strings.Contains(err.Error(), "unhealthy") {
		t.Fatalf("Emit error after retirement = %v, want it to report the emitter unhealthy", err)
	}
	if !strings.Contains(err.Error(), "retired") {
		t.Fatalf("Emit error after retirement = %v, want it to name retirement as the cause", err)
	}

	// Retiring twice must stay safe: reload paths can race a second rotation.
	if err := e.RetireNativeAEL(); err != nil {
		t.Fatalf("second RetireNativeAEL: %v", err)
	}
}

// The nil-receiver contracts are load-bearing because receipt emission is
// optional: with the flight recorder off, every call site holds a nil emitter
// and must not panic or report a false failure.
func TestEmitter_NilReceiverLifecycleContracts(t *testing.T) {
	t.Parallel()

	var e *Emitter

	if got := e.DurabilityBlocks(); got != 0 {
		t.Errorf("DurabilityBlocks() on nil emitter = %d, want 0", got)
	}
	if err := e.AbortNativeAEL(); err != nil {
		t.Errorf("AbortNativeAEL() on nil emitter = %v, want nil", err)
	}
	if err := e.RetireNativeAEL(); err != nil {
		t.Errorf("RetireNativeAEL() on nil emitter = %v, want nil", err)
	}
	if err := e.EmitHeartbeat(); err != nil {
		t.Errorf("EmitHeartbeat() on nil emitter = %v, want nil", err)
	}
}

// A configured emitter with no staged native run has nothing to abort. This is
// the ordinary path when native AEL is not enabled, and it must not be
// reported as a failure.
func TestEmitter_AbortNativeAELWithoutStagedRun(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()

	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv})
	if e == nil {
		t.Fatal("NewEmitter returned nil")
	}
	if err := e.AbortNativeAEL(); err != nil {
		t.Fatalf("AbortNativeAEL() with no staged native run = %v, want nil", err)
	}
	if got := e.DurabilityBlocks(); got != 0 {
		t.Fatalf("DurabilityBlocks() on a fresh emitter = %d, want 0", got)
	}
}
