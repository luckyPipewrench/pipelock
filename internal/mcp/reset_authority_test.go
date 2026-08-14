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
			if delegation, err := MintResetDelegation(test.privateKey, test.issuer, test.kind, test.target, test.instanceID, 0, issued, test.expires, test.nonce); err == nil || delegation != (ResetDelegation{}) {
				t.Fatalf("MintResetDelegation() = %+v, %v; want validation failure", delegation, err)
			}
		})
	}
}

func TestResetDelegationFileOperationsAreBoundedAndPathSafe(t *testing.T) {
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newResetAuthority(pub, "mcp://fixture", strings.Repeat("c", 32), func() time.Time { return resetAuthorityTestNow })
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := MintResetDelegation(privateKey, "operator", ResetKindDrift, authority.Target(), authority.InstanceID(), 0, resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), strings.Repeat("d", 32))
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

	if decision := authority.ConsumeFile("", ResetKindDrift, 0); decision.Result != ResetAuthorityAbsent {
		t.Fatalf("empty reset path decision = %+v", decision)
	}
	if decision := (*ResetAuthority)(nil).ConsumeFile(path, ResetKindDrift, 0); decision.Result != ResetAuthorityAbsent {
		t.Fatalf("nil reset authority decision = %+v", decision)
	}
}

func TestResetDelegationParsingAndVerificationRejectsMalformedArtifacts(t *testing.T) {
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := MintResetDelegation(privateKey, "operator", ResetKindAdaptive, "mcp://fixture", strings.Repeat("e", 32), 3, resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), strings.Repeat("f", 32))
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
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newResetAuthority(pub, "mcp://fixture", strings.Repeat("a", 32), func() time.Time { return resetAuthorityTestNow })
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := MintResetDelegation(privateKey, "operator", ResetKindDrift, authority.Target(), authority.InstanceID(), 0, resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), strings.Repeat("b", 32))
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
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if decision := authority.ConsumeFile(path, ResetKindDrift, 0); decision.Result != ResetAuthorityRemoveFailed {
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
	if got := removeResetResult(errors.New("reset delegation path changed before removal")); got != ResetAuthorityPathChanged {
		t.Fatalf("path-changed remove result = %q", got)
	}
	if got := removeResetResult(errors.New("remove denied")); got != ResetAuthorityRemoveFailed {
		t.Fatalf("remove failure result = %q", got)
	}
}
