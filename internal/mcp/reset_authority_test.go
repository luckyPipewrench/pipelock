// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var resetAuthorityTestNow = time.Date(2026, time.August, 14, 12, 0, 0, 0, time.UTC)

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
			private, "operator-primary", kind, delegationTarget, delegationInstance, epoch,
			issued, expires, fmt.Sprintf("%032x", nonce),
		)
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
			if got := authority.ConsumeFile(path, ResetKindDrift, 7).Result; got != tt.want {
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
		privateKey, "operator-primary", ResetKindDrift, target, instanceID, 7,
		resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), strings.Repeat("d", 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw := resetDelegationBytes(t, d)
	path := filepath.Join(t.TempDir(), "reset.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := authority.ConsumeFile(path, ResetKindDrift, 7).Result; got != ResetAuthorityAccepted {
		t.Fatalf("first consume = %q, want accepted", got)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := authority.ConsumeFile(path, ResetKindDrift, 7).Result; got != ResetAuthorityReplayed {
		t.Fatalf("replay consume = %q, want replayed", got)
	}

	restarted, err := newResetAuthority(pub, target, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", func() time.Time { return resetAuthorityTestNow })
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := restarted.ConsumeFile(path, ResetKindDrift, 7).Result; got != ResetAuthorityWrongInstance {
		t.Fatalf("post-restart consume = %q, want wrong instance", got)
	}
}

func TestResetDelegationCanonicalInputIsStable(t *testing.T) {
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	d, err := MintResetDelegation(
		privateKey, "operator-primary", ResetKindAdaptive, "mcp://stdio/code-assistant",
		"ffffffffffffffffffffffffffffffff", 0, resetAuthorityTestNow,
		resetAuthorityTestNow.Add(time.Minute), strings.Repeat("1", 32),
	)
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
