// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func newDurableTestEmitter(t *testing.T) *Emitter {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	e := NewEmitter(rec, priv, "0123456789abcdef0123456789abcdef", 30)
	if e == nil {
		t.Fatal("NewEmitter returned nil")
	}
	return e
}

// A reservation confirms the records already written, and a failed sync stays
// failed: no later reservation can confirm over the unconfirmed prefix.
func TestReserveDurabilityConfirmsThenFailsSticky(t *testing.T) {
	var none *Emitter
	none.SetSyncForTest(func(*os.File) error { return nil })
	confirm, err := none.ReserveDurability()
	if err != nil || confirm() != nil {
		t.Fatalf("nil emitter reservation = %v, want a no-op confirmation", err)
	}

	closed := newDurableTestEmitter(t)
	if err := closed.EmitOpen(); err != nil {
		t.Fatal(err)
	}
	if err := closed.EmitClose(); err != nil {
		t.Fatal(err)
	}
	if _, err := closed.ReserveDurability(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("reservation after the run closed = %v, want a closed-run refusal", err)
	}

	e := newDurableTestEmitter(t)
	if err := e.EmitOpen(); err != nil {
		t.Fatal(err)
	}
	confirm, err = e.ReserveDurability()
	if err != nil {
		t.Fatal(err)
	}
	if err := confirm(); err != nil {
		t.Fatalf("real sync confirmation: %v", err)
	}

	injected := errors.New("injected AEL sync failure")
	e.SetSyncForTest(func(*os.File) error { return injected })
	confirm, err = e.ReserveDurability()
	if err != nil {
		t.Fatal(err)
	}
	if err := confirm(); !errors.Is(err, injected) {
		t.Fatalf("failed sync confirmation = %v, want the injected failure", err)
	}
	e.SetSyncForTest(nil)
	if _, err := e.ReserveDurability(); !errors.Is(err, injected) || !strings.Contains(err.Error(), "unhealthy") {
		t.Fatalf("reservation after a failed sync = %v, want a sticky refusal", err)
	}
}
