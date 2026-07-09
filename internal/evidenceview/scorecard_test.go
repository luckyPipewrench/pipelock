// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidenceview

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	testTarget = "https://api.vendor.example/evidence"
)

func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func buildTestChain(t *testing.T, priv ed25519.PrivateKey, count int) []receipt.Receipt {
	t.Helper()
	chain := make([]receipt.Receipt, 0, count)
	prevHash := receipt.GenesisHash
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

	for i := range count {
		r := signTestReceipt(t, priv, uint64(i), prevHash, base.Add(time.Duration(i)*time.Second))
		hash, err := receipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash: %v", err)
		}
		chain = append(chain, r)
		prevHash = hash
	}
	return chain
}

func signTestReceipt(t *testing.T, priv ed25519.PrivateKey, seq uint64, prevHash string, ts time.Time) receipt.Receipt {
	t.Helper()
	ar := receipt.ActionRecord{
		Version:         1,
		ActionID:        "act-test",
		ActionType:      receipt.ActionRead,
		Timestamp:       ts,
		Target:          testTarget,
		Verdict:         "allow",
		Transport:       "fetch",
		PolicyHash:      "test-policy-hash",
		SideEffectClass: receipt.SideEffectNone,
		Reversibility:   receipt.ReversibilityFull,
		ChainSeq:        seq,
		ChainPrevHash:   prevHash,
	}
	r, err := receipt.Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return r
}

func TestComputeScorecard(t *testing.T) {
	pub, priv := generateTestKey(t)
	keyHex := hex.EncodeToString(pub)

	tests := []struct {
		name           string
		receipts       []receipt.Receipt
		trustedKeys    map[string]TrustedKey
		wantAuthentic  string
		wantUntampered string
		wantAnchored   string
		wantComplete   string
	}{
		{
			name:           "absent - no receipts",
			receipts:       nil,
			trustedKeys:    nil,
			wantAuthentic:  StateFail,
			wantUntampered: StateFail,
			wantAnchored:   StateWarn,
			wantComplete:   StateLimited,
		},
		{
			name:           "untrusted signer",
			receipts:       buildTestChain(t, priv, 1),
			trustedKeys:    nil,
			wantAuthentic:  StateWarn,
			wantUntampered: StateVerify,
			wantAnchored:   StateWarn,
			wantComplete:   StateLimited,
		},
		{
			name:           "trusted signer",
			receipts:       buildTestChain(t, priv, 1),
			trustedKeys:    map[string]TrustedKey{keyHex: {Source: "operator config"}},
			wantAuthentic:  StateVerify,
			wantUntampered: StateVerify,
			wantAnchored:   StateWarn,
			wantComplete:   StateLimited,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeScorecard(tt.receipts, tt.trustedKeys, "test-session")
			sc := result.Scorecard
			if sc.Authentic.State != tt.wantAuthentic {
				t.Errorf("Authentic.State = %q, want %q; detail=%s", sc.Authentic.State, tt.wantAuthentic, sc.Authentic.Detail)
			}
			if sc.Untampered.State != tt.wantUntampered {
				t.Errorf("Untampered.State = %q, want %q; detail=%s", sc.Untampered.State, tt.wantUntampered, sc.Untampered.Detail)
			}
			if sc.Anchored.State != tt.wantAnchored {
				t.Errorf("Anchored.State = %q, want %q", sc.Anchored.State, tt.wantAnchored)
			}
			if sc.Completeness.State != tt.wantComplete {
				t.Errorf("Completeness.State = %q, want %q", sc.Completeness.State, tt.wantComplete)
			}
		})
	}
}

func TestAbsentScorecard(t *testing.T) {
	sc := AbsentScorecard()
	if sc.Authentic.State != StateFail {
		t.Errorf("absent Authentic.State = %q, want %q", sc.Authentic.State, StateFail)
	}
	if sc.Authentic.Chip != chipAbsent {
		t.Errorf("absent Authentic.Chip = %q, want %q", sc.Authentic.Chip, chipAbsent)
	}
}

func TestReadLimitedScorecard(t *testing.T) {
	sc := ReadLimitedScorecard(100, 100)
	if sc.Authentic.State != StateLimited {
		t.Errorf("ReadLimited Authentic.State = %q, want %q", sc.Authentic.State, StateLimited)
	}
	if sc.Untampered.State != StateLimited {
		t.Errorf("ReadLimited Untampered.State = %q, want %q", sc.Untampered.State, StateLimited)
	}
}

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{name: "short key", key: "abc", want: "abc"},
		{name: "exact 12", key: "123456789012", want: "123456789012"},
		{name: "long key", key: "1234567890123456", want: "123456789012"},
		{name: "whitespace", key: "  abc  ", want: "abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Fingerprint(tt.key)
			if got != tt.want {
				t.Errorf("Fingerprint(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestFormatKeyList(t *testing.T) {
	tests := []struct {
		name string
		keys []string
		want string
	}{
		{name: "empty", keys: nil, want: "none"},
		{name: "single short", keys: []string{"abc"}, want: "abc"},
		{name: "two keys", keys: []string{"abc", "def"}, want: "abc, def"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatKeyList(tt.keys)
			if got != tt.want {
				t.Errorf("FormatKeyList = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSignerKeys(t *testing.T) {
	_, priv := generateTestKey(t)
	chain := buildTestChain(t, priv, 3)

	keys := SignerKeys(chain)
	if len(keys) != 1 {
		t.Fatalf("SignerKeys returned %d keys, want 1 (same signer)", len(keys))
	}
}

func TestTrustedKeysForSession(t *testing.T) {
	signers := []string{"key-a", "key-b", "key-c"}
	trusted := map[string]TrustedKey{"key-b": {Source: "test"}}

	got := TrustedKeysForSession(signers, trusted)
	if len(got) != 1 || got[0] != "key-b" {
		t.Errorf("TrustedKeysForSession = %v, want [key-b]", got)
	}

	// No trusted keys returns nil.
	if got := TrustedKeysForSession(signers, nil); got != nil {
		t.Errorf("TrustedKeysForSession(nil trusted) = %v, want nil", got)
	}
}
