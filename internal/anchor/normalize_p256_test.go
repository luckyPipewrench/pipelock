// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

// TestNormalizeECDSAP256PublicKey_CurveEquivalenceAndDegenerateKeys covers the
// two directions the P-256 normalization has to get right at once.
//
// Availability: a mathematically-equivalent P-256 curve carried on a DIFFERENT
// elliptic.Curve value must still verify. An identity comparison against the
// stdlib singleton rejects such a key, which looks like a bad signature and
// silently breaks a legitimately configured log.
//
// Security: the curve is only trusted after its DOMAIN PARAMETERS are compared
// by value, so a curve that merely CLAIMS Name "P-256" while carrying another
// curve's parameters is refused. Reducing the check to a Name comparison makes
// the spoofed-name case below fail, which is what keeps this test honest.
//
// Degenerate keys (nil key, nil Curve, nil or negative or oversize coordinates,
// the point at infinity, off-curve points) must be refused WITHOUT panicking:
// this runs on a verification path reached from remote transparency-log input,
// so a panic here is a denial of service.
func TestNormalizeECDSAP256PublicKey_CurveEquivalenceAndDegenerateKeys(t *testing.T) {
	good, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("nil key does not panic", func(t *testing.T) {
		if _, ok := normalizeECDSAP256PublicKey(nil); ok {
			t.Fatal("nil accepted")
		}
	})
	t.Run("nil Curve does not panic", func(t *testing.T) {
		k := &ecdsa.PublicKey{Curve: nil, X: good.X, Y: good.Y}
		if _, ok := normalizeECDSAP256PublicKey(k); ok {
			t.Fatal("nil curve accepted")
		}
	})
	t.Run("nil coords do not panic", func(t *testing.T) {
		for _, k := range []*ecdsa.PublicKey{
			{Curve: elliptic.P256(), X: nil, Y: good.Y},
			{Curve: elliptic.P256(), X: good.X, Y: nil},
			{Curve: elliptic.P256(), X: nil, Y: nil},
		} {
			if _, ok := normalizeECDSAP256PublicKey(k); ok {
				t.Fatal("nil coord accepted")
			}
		}
	})
	t.Run("point at infinity rejected", func(t *testing.T) {
		k := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(0), Y: big.NewInt(0)}
		if _, ok := normalizeECDSAP256PublicKey(k); ok {
			t.Fatal("infinity accepted")
		}
	})
	t.Run("off-curve point rejected", func(t *testing.T) {
		k := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}
		if _, ok := normalizeECDSAP256PublicKey(k); ok {
			t.Fatal("off-curve accepted")
		}
	})
	t.Run("negative coord rejected", func(t *testing.T) {
		k := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).Neg(good.X), Y: good.Y}
		if _, ok := normalizeECDSAP256PublicKey(k); ok {
			t.Fatal("negative accepted")
		}
	})
	t.Run("oversize coord rejected without panic", func(t *testing.T) {
		huge := new(big.Int).Lsh(big.NewInt(1), 600)
		k := &ecdsa.PublicKey{Curve: elliptic.P256(), X: huge, Y: good.Y}
		if _, ok := normalizeECDSAP256PublicKey(k); ok {
			t.Fatal("oversize accepted")
		}
	})
	t.Run("wrong curve rejected", func(t *testing.T) {
		for _, c := range []elliptic.Curve{elliptic.P384(), elliptic.P521(), elliptic.P224()} {
			bad, err := ecdsa.GenerateKey(c, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := normalizeECDSAP256PublicKey(&bad.PublicKey); ok {
				t.Fatalf("curve %v accepted", c.Params().Name)
			}
		}
	})
	t.Run("curve LYING about its name is rejected", func(t *testing.T) {
		// A P-384 curve whose params claim to be P-256: Name/BitSize spoofed,
		// domain params real. Must be caught by the value comparison.
		p := *elliptic.P384().Params()
		p.Name = "P-256"
		p.BitSize = 256
		k := &ecdsa.PublicKey{Curve: &p, X: good.X, Y: good.Y}
		if _, ok := normalizeECDSAP256PublicKey(k); ok {
			t.Fatal("spoofed-name curve accepted")
		}
	})
	t.Run("equivalent P-256 curve IS accepted and normalized", func(t *testing.T) {
		p := *elliptic.P256().Params() // distinct pointer, identical params
		k := &ecdsa.PublicKey{Curve: &p, X: good.X, Y: good.Y}
		got, ok := normalizeECDSAP256PublicKey(k)
		if !ok {
			t.Fatal("equivalent P-256 curve rejected (availability regression)")
		}
		// Asserting only `ok` would let `return pub, true` pass. The contract is that
		// the accepted key comes back carrying the stdlib P-256 singleton, which is what
		// keeps a caller-supplied custom curve implementation out of ecdsa.VerifyASN1.
		if got.Curve != elliptic.P256() {
			t.Fatalf("normalized key kept the caller's curve, want the stdlib P-256 singleton")
		}
		if got.X.Cmp(good.X) != 0 || got.Y.Cmp(good.Y) != 0 {
			t.Fatal("normalization altered the key coordinates")
		}
	})
	t.Run("genuine key still accepted and normalized", func(t *testing.T) {
		got, ok := normalizeECDSAP256PublicKey(&good.PublicKey)
		if !ok {
			t.Fatal("real key rejected")
		}
		if got.Curve != elliptic.P256() {
			t.Fatal("normalized key does not carry the stdlib P-256 singleton")
		}
	})
}
