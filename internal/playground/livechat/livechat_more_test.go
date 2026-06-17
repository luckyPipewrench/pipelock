// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"errors"
	"testing"
	"time"
)

func TestNewRandomCode(t *testing.T) {
	t.Parallel()
	// Short request is bumped to the floor; output is non-empty and url-safe.
	a, err := NewRandomCode(2)
	if err != nil {
		t.Fatalf("NewRandomCode: %v", err)
	}
	b, err := NewRandomCode(18)
	if err != nil {
		t.Fatalf("NewRandomCode: %v", err)
	}
	if a == "" || b == "" {
		t.Fatal("empty code")
	}
	if a == b {
		t.Error("two random codes collided")
	}
}

func TestDefaultLimits(t *testing.T) {
	t.Parallel()
	l := DefaultLimits()
	if l.MaxInputBytes != defaultMaxInputBytes || l.SessionTTL != defaultSessionTTL {
		t.Errorf("DefaultLimits = %+v", l)
	}
	if err := l.CheckInput("hi"); err != nil {
		t.Errorf("default CheckInput rejected normal input: %v", err)
	}
}

func TestNewConcurrencyLimiter_ZeroBecomesOne(t *testing.T) {
	t.Parallel()
	cl := NewConcurrencyLimiter(0)
	if cl.Cap() != 1 {
		t.Errorf("Cap = %d, want 1 (never unlimited)", cl.Cap())
	}
	if _, ok := cl.Acquire(); !ok {
		t.Fatal("first acquire failed")
	}
	if _, ok := cl.Acquire(); ok {
		t.Error("second acquire succeeded; cap should be 1")
	}
}

func TestNewGate_BlankCodeIgnored(t *testing.T) {
	t.Parallel()
	g, err := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: ""}, {Code: "real"}}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	// The blank code must not act as a wildcard.
	if _, _, err := g.Redeem("", "s"); !errors.Is(err, ErrUnknownCode) {
		t.Errorf("blank-code Redeem err = %v, want ErrUnknownCode", err)
	}
	if _, _, err := g.Redeem("real", "s"); err != nil {
		t.Errorf("real-code Redeem err = %v, want nil", err)
	}
}

func TestGate_Validate_EmptyClaimsRejected(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "c"}}})
	// A correctly-signed token with an empty SessionID must still be rejected.
	tok, err := g.sign(SessionClaims{ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := g.Validate(tok); !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("empty-claims Validate err = %v, want ErrTokenMalformed", err)
	}
}
