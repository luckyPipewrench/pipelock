// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"slices"
	"testing"
)

// The proxy remembers every key it loaded to sign receipts, once each, so a
// reload can resume a session tail written under any of them.
func TestReceiptSignerKeysHeld(t *testing.T) {
	e, rec, pub := newCoverageEmitter(t, t.TempDir())
	t.Cleanup(func() { _ = rec.Close() })
	if e == nil {
		t.Fatal("premise: the emitter must be constructed")
	}
	p := &Proxy{}
	WithReceiptEmitter(e)(p)
	p.noteReceiptSignerKey(e.SignerKeyHex())
	p.noteReceiptSignerKey("")
	p.noteReceiptSignerKey("second")
	want := []string{fmt.Sprintf("%x", pub), "second"}
	got := p.receiptSignerKeysHeld()
	if !slices.Equal(got, want) {
		t.Fatalf("held keys = %v, want %v", got, want)
	}
	got[0] = "tampered"
	if p.receiptSignerKeysHeld()[0] == "tampered" {
		t.Fatal("receiptSignerKeysHeld returned the internal slice")
	}
	var nilProxy Proxy
	WithReceiptEmitter(nil)(&nilProxy)
	if held := nilProxy.receiptSignerKeysHeld(); len(held) != 0 {
		t.Fatalf("a nil emitter recorded %v", held)
	}
}
