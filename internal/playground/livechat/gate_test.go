// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testSecret(t *testing.T) []byte {
	t.Helper()
	s, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	return s
}

func TestNewGate_ShortSecretRejected(t *testing.T) {
	t.Parallel()
	if _, err := NewGate(GateConfig{Secret: []byte("too-short")}); err == nil {
		t.Fatal("NewGate accepted a short secret; want error (fail-closed)")
	}
}

func TestNewGate_TTLClamped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"below-min", time.Second, minTokenTTL},
		{"zero", 0, minTokenTTL},
		{"above-max", time.Hour, maxTokenTTL},
		{"in-range", 5 * time.Minute, 5 * time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g, err := NewGate(GateConfig{
				Secret:   testSecret(t),
				Codes:    []CodeSpec{{Code: "abc"}},
				TokenTTL: tc.in,
			})
			if err != nil {
				t.Fatalf("NewGate: %v", err)
			}
			if g.ttl != tc.want {
				t.Errorf("ttl = %v, want %v", g.ttl, tc.want)
			}
		})
	}
}

func TestGate_NoCodes_IsClosed(t *testing.T) {
	t.Parallel()
	g, err := NewGate(GateConfig{Secret: testSecret(t)})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	if g.Open() {
		t.Error("gate with no codes reports Open(); want closed")
	}
	if _, _, err := g.Redeem("anything", "s1"); !errors.Is(err, ErrGateClosed) {
		t.Errorf("Redeem on codeless gate err = %v, want ErrGateClosed", err)
	}
}

func TestGate_NilReceiver_FailsClosed(t *testing.T) {
	t.Parallel()
	var g *Gate
	if g.Open() {
		t.Error("nil gate Open() = true")
	}
	if _, _, err := g.Redeem("x", "s"); !errors.Is(err, ErrGateClosed) {
		t.Errorf("nil gate Redeem err = %v, want ErrGateClosed", err)
	}
	if _, err := g.Validate("x.y"); !errors.Is(err, ErrGateClosed) {
		t.Errorf("nil gate Validate err = %v, want ErrGateClosed", err)
	}
}

func TestGate_Redeem_UnknownCode(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "valid"}}})
	if _, _, err := g.Redeem("invalid", "s1"); !errors.Is(err, ErrUnknownCode) {
		t.Errorf("err = %v, want ErrUnknownCode", err)
	}
}

func TestGate_Redeem_RoundTrip(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{
		Secret:   testSecret(t),
		Codes:    []CodeSpec{{Code: "letmein", ID: "vip"}},
		TokenTTL: 5 * time.Minute,
	})
	tok, claims, err := g.Redeem("letmein", "sess-1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if claims.SessionID != "sess-1" || claims.CodeID != "vip" {
		t.Errorf("claims = %+v", claims)
	}
	got, err := g.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.SessionID != "sess-1" || got.CodeID != "vip" {
		t.Errorf("validated claims = %+v", got)
	}
}

func TestGate_Redeem_BudgetEnforced(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "two", MaxSessions: 2}}})
	for i := 0; i < 2; i++ {
		if _, _, err := g.Redeem("two", "s"); err != nil {
			t.Fatalf("Redeem %d: %v", i, err)
		}
	}
	if _, _, err := g.Redeem("two", "s"); !errors.Is(err, ErrCodeExhausted) {
		t.Errorf("third Redeem err = %v, want ErrCodeExhausted", err)
	}
}

func TestGate_RefundRestoresFiniteBudget(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "one", MaxSessions: 1}}})
	if _, claims, err := g.Redeem("one", "s1"); err != nil {
		t.Fatalf("Redeem: %v", err)
	} else {
		g.Refund(claims)
		g.Refund(claims) // idempotent: must not underflow the budget
	}
	if _, _, err := g.Redeem("one", "s2"); err != nil {
		t.Fatalf("Redeem after refund: %v", err)
	}
	if _, _, err := g.Redeem("one", "s3"); !errors.Is(err, ErrCodeExhausted) {
		t.Fatalf("third Redeem err = %v, want ErrCodeExhausted", err)
	}
}

func TestGate_CommitPreventsRefund(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "one", MaxSessions: 1}}})
	_, claims, err := g.Redeem("one", "s1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	g.Commit(claims)
	g.Refund(claims)
	if _, _, err := g.Redeem("one", "s2"); !errors.Is(err, ErrCodeExhausted) {
		t.Fatalf("Redeem after committed refund err = %v, want ErrCodeExhausted", err)
	}
}

func TestGate_Redeem_UnlimitedWhenMaxZero(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "open", MaxSessions: 0}}})
	for i := 0; i < 50; i++ {
		if _, _, err := g.Redeem("open", "s"); err != nil {
			t.Fatalf("Redeem %d on unlimited code: %v", i, err)
		}
	}
}

func TestGate_Validate_Expired(t *testing.T) {
	t.Parallel()
	now := time.Now()
	clock := now
	g, _ := NewGate(GateConfig{
		Secret:   testSecret(t),
		Codes:    []CodeSpec{{Code: "c"}},
		TokenTTL: time.Minute,
		Now:      func() time.Time { return clock },
	})
	tok, _, err := g.Redeem("c", "s1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	// Still valid just before expiry.
	clock = now.Add(59 * time.Second)
	if _, err := g.Validate(tok); err != nil {
		t.Fatalf("Validate before expiry: %v", err)
	}
	// Expired after TTL.
	clock = now.Add(2 * time.Minute)
	if _, err := g.Validate(tok); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("Validate after expiry err = %v, want ErrTokenExpired", err)
	}
}

func TestGate_Validate_Malformed(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "c"}}})
	for _, tok := range []string{
		"",
		"nodot",
		"a.b.c",            // two dots
		".onlysig",         // empty payload
		"onlypayload.",     // empty sig
		"!!!.###",          // bad base64
		"YWJj.notbase64!!", // bad sig base64
	} {
		if _, err := g.Validate(tok); !errors.Is(err, ErrTokenMalformed) && !errors.Is(err, ErrBadSignature) {
			t.Errorf("Validate(%q) err = %v, want malformed/bad-sig", tok, err)
		}
	}
}

func TestGate_Validate_TamperedPayloadAndSig(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "c"}}})
	tok, _, err := g.Redeem("c", "s1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	payloadB64, sigB64, ok := splitToken(tok)
	if !ok {
		t.Fatal("splitToken failed on a freshly minted token")
	}

	// Flip a byte in the payload: claims change, MAC no longer matches.
	tamperedPayload := flipFirstChar(payloadB64) + "." + sigB64
	if _, err := g.Validate(tamperedPayload); !errors.Is(err, ErrBadSignature) && !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("tampered payload err = %v, want bad-sig/malformed", err)
	}

	// Flip a byte in the signature.
	tamperedSig := payloadB64 + "." + flipFirstChar(sigB64)
	if _, err := g.Validate(tamperedSig); !errors.Is(err, ErrBadSignature) && !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("tampered sig err = %v, want bad-sig/malformed", err)
	}
}

func TestGate_Validate_WrongSecretRejected(t *testing.T) {
	t.Parallel()
	g1, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "c"}}})
	g2, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "c"}}})
	tok, _, err := g1.Redeem("c", "s1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if _, err := g2.Validate(tok); !errors.Is(err, ErrBadSignature) {
		t.Errorf("cross-gate Validate err = %v, want ErrBadSignature", err)
	}
}

func TestGate_Redeem_ConcurrentBudget(t *testing.T) {
	t.Parallel()
	const budget = 20
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "c", MaxSessions: budget}}})

	var success, exhausted int64
	var wg sync.WaitGroup
	const attempts = 100
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			_, _, err := g.Redeem("c", "s")
			switch {
			case err == nil:
				atomic.AddInt64(&success, 1)
			case errors.Is(err, ErrCodeExhausted):
				atomic.AddInt64(&exhausted, 1)
			default:
				t.Errorf("unexpected Redeem err: %v", err)
			}
		}()
	}
	wg.Wait()
	if success != budget {
		t.Errorf("successful redeems = %d, want exactly %d", success, budget)
	}
	if exhausted != attempts-budget {
		t.Errorf("exhausted = %d, want %d", exhausted, attempts-budget)
	}
}

func flipFirstChar(s string) string {
	if s == "" {
		return "x"
	}
	c := s[0]
	if c == 'A' {
		c = 'B'
	} else {
		c = 'A'
	}
	return string(c) + s[1:]
}

// sanity: ensure codes are not stored or surfaced in the clear anywhere obvious.
func TestGate_CodeIDNotEqualToCode(t *testing.T) {
	t.Parallel()
	g, _ := NewGate(GateConfig{Secret: testSecret(t), Codes: []CodeSpec{{Code: "super-secret-code"}}})
	_, claims, err := g.Redeem("super-secret-code", "s1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if strings.Contains(claims.CodeID, "super-secret-code") {
		t.Errorf("CodeID %q leaks the raw code", claims.CodeID)
	}
}
