// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package activation

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

var fixedNow = time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)

type testSigner struct {
	keyID string
	priv  ed25519.PrivateKey
}

func (s testSigner) KeyID() string { return s.keyID }

func (s testSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

type failingSigner struct {
	keyID string
	sig   []byte
	err   error
}

func (s failingSigner) KeyID() string { return s.keyID }

func (s failingSigner) Sign([]byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.sig, nil
}

func TestRequiredSignaturesDefaults(t *testing.T) {
	if got := RequiredSignatures(Policy{}); got != 1 {
		t.Fatalf("non-production signatures = %d, want 1", got)
	}
	if got := RequiredSignatures(Policy{Production: true}); got != 2 {
		t.Fatalf("production signatures = %d, want 2", got)
	}
	if got := RequiredSignatures(Policy{Production: true, RequiredSignatures: 4}); got != 4 {
		t.Fatalf("explicit signatures = %d, want 4", got)
	}
}

func TestProductionPolicyRequiresThreeActivationAuthorities(t *testing.T) {
	if err := ValidateProductionAuthorityPool(nil, fixedNow, Policy{}); err != nil {
		t.Fatalf("non-production nil roster err = %v", err)
	}
	if err := ValidateProductionAuthorityPool(nil, fixedNow, Policy{Production: true}); !errors.Is(err, ErrRosterRequired) {
		t.Fatalf("production nil roster err = %v, want ErrRosterRequired", err)
	}

	alice := newSigner(t, "act-alice")
	bob := newSigner(t, "act-bob")
	roster := loadedRoster(
		rosterKey(alice, "alice", signing.PurposeContractActivationSigning),
		rosterKey(bob, "bob", signing.PurposeContractActivationSigning),
	)
	err := ValidateProductionAuthorityPool(roster, fixedNow, Policy{Production: true})
	if !errors.Is(err, ErrProductionAuthorityPool) {
		t.Fatalf("ValidateProductionAuthorityPool err = %v, want ErrProductionAuthorityPool", err)
	}

	carol := newSigner(t, "act-carol")
	compile := newSigner(t, "compile-key")
	expired := rosterKey(newSigner(t, "act-expired"), "expired", signing.PurposeContractActivationSigning)
	expired.ValidUntil = stringPtr(fixedNow.Add(-time.Minute).Format(time.RFC3339))
	blankPrincipal := rosterKey(newSigner(t, "act-blank"), "", signing.PurposeContractActivationSigning)
	roster.Body.Keys = append(roster.Body.Keys,
		rosterKey(carol, "carol", signing.PurposeContractActivationSigning),
		rosterKey(compile, "compile", signing.PurposeContractCompileSigning),
		expired,
		blankPrincipal,
	)
	if err := ValidateProductionAuthorityPool(roster, fixedNow, Policy{Production: true}); err != nil {
		t.Fatalf("ValidateProductionAuthorityPool with three authorities: %v", err)
	}
}

func TestValidateManifestDualControlRejectsSingleSignerInProduction(t *testing.T) {
	if err := ValidateManifestDualControl(nil, nil, fixedNow, Policy{}); !errors.Is(err, ErrRosterRequired) {
		t.Fatalf("nil roster err = %v, want ErrRosterRequired", err)
	}

	alice := newSigner(t, "act-alice")
	bob := newSigner(t, "act-bob")
	carol := newSigner(t, "act-carol")
	roster := loadedRoster(
		rosterKey(alice, "alice", signing.PurposeContractActivationSigning),
		rosterKey(bob, "bob", signing.PurposeContractActivationSigning),
		rosterKey(carol, "carol", signing.PurposeContractActivationSigning),
	)
	one := []contract.ManifestSignature{manifestSig("act-alice", "alice")}
	err := ValidateManifestDualControl(one, roster, fixedNow, Policy{Production: true})
	if !errors.Is(err, ErrDualControl) {
		t.Fatalf("ValidateManifestDualControl single err = %v, want ErrDualControl", err)
	}

	two := []contract.ManifestSignature{
		manifestSig("act-alice", "alice"),
		manifestSig("act-bob", "bob"),
	}
	if err := ValidateManifestDualControl(two, roster, fixedNow, Policy{Production: true}); err != nil {
		t.Fatalf("ValidateManifestDualControl two signers: %v", err)
	}
}

func TestValidateManifestDualControlReturnsProductionPoolError(t *testing.T) {
	alice := newSigner(t, "act-alice")
	roster := loadedRoster(rosterKey(alice, "alice", signing.PurposeContractActivationSigning))
	err := ValidateManifestDualControl([]contract.ManifestSignature{manifestSig("act-alice", "alice")}, roster, fixedNow, Policy{Production: true})
	if !errors.Is(err, ErrProductionAuthorityPool) {
		t.Fatalf("ValidateManifestDualControl err = %v, want ErrProductionAuthorityPool", err)
	}
}

func TestValidateManifestDualControlDedupesPrincipals(t *testing.T) {
	aliceA := newSigner(t, "act-alice-a")
	aliceB := newSigner(t, "act-alice-b")
	bob := newSigner(t, "act-bob")
	roster := loadedRoster(
		rosterKey(aliceA, "alice", signing.PurposeContractActivationSigning),
		rosterKey(aliceB, "alice", signing.PurposeContractActivationSigning),
		rosterKey(bob, "bob", signing.PurposeContractActivationSigning),
	)
	sigs := []contract.ManifestSignature{
		manifestSig("act-alice-a", "alice"),
		manifestSig("act-alice-b", "alice"),
	}
	err := ValidateManifestDualControl(sigs, roster, fixedNow, Policy{RequiredSignatures: 2})
	if !errors.Is(err, ErrDualControl) {
		t.Fatalf("ValidateManifestDualControl duplicate principal err = %v, want ErrDualControl", err)
	}
}

func TestValidateManifestDualControlSkipsInvalidClaims(t *testing.T) {
	alice := newSigner(t, "act-alice")
	bob := newSigner(t, "act-bob")
	compile := newSigner(t, "compile-key")
	roster := loadedRoster(
		rosterKey(alice, "alice", signing.PurposeContractActivationSigning),
		rosterKey(bob, "bob", signing.PurposeContractActivationSigning),
		rosterKey(compile, "compile", signing.PurposeContractCompileSigning),
	)
	sigs := []contract.ManifestSignature{
		manifestSig("act-alice", "alice"),
		manifestSig("missing", "missing"),
		manifestSig("compile-key", "compile"),
		manifestSig("act-alice", "mallory"),
		manifestSig("act-alice", "alice"),
		{KeyID: "act-bob", Principal: "bob", KeyPurpose: signing.PurposeReceiptSigning.String()},
		manifestSig("act-bob", "bob"),
	}
	err := ValidateManifestDualControl(sigs, roster, fixedNow, Policy{RequiredSignatures: 2})
	if err != nil {
		t.Fatalf("ValidateManifestDualControl with invalid claims plus two valid signers: %v", err)
	}
}

func TestRollbackAuthorizationRequired(t *testing.T) {
	if _, err := RollbackAuthorizedPayload("sha256:target", 4, nil, "auth-1"); !errors.Is(err, ErrRollbackAuthorization) {
		t.Fatalf("RollbackAuthorizedPayload nil signatures err = %v, want ErrRollbackAuthorization", err)
	}
	if _, err := RollbackCommittedPayload("sha256:target", "sha256:prior", "", "accepted", ""); !errors.Is(err, ErrRollbackAuthorization) {
		t.Fatalf("RollbackCommittedPayload empty auth err = %v, want ErrRollbackAuthorization", err)
	}
	if _, err := RollbackAuthorizedPayload("sha256:target", 4, []string{"ed25519:sig"}, "auth-1"); err != nil {
		t.Fatalf("RollbackAuthorizedPayload valid: %v", err)
	}
	if _, err := RollbackCommittedPayload("sha256:target", "sha256:prior", "auth-1", "accepted", ""); err != nil {
		t.Fatalf("RollbackCommittedPayload valid: %v", err)
	}
}

func TestLifecycleReceiptsValidateAuthorityMatrix(t *testing.T) {
	signer := newSigner(t, "act-alice")
	intent := PromoteIntentPayload("sha256:target", 2, "sha256:prior", "intent-1")
	rcpt, err := SignReceipt(contractreceipt.PayloadContractPromoteIntent, intent, ReceiptContext{
		EventID:   "018f0000-0000-7000-8000-000000000001",
		Timestamp: fixedNow,
		Principal: "alice",
		Actor:     "learn promote",
	}, signer, signing.PurposeContractActivationSigning)
	if err != nil {
		t.Fatalf("SignReceipt promote intent: %v", err)
	}
	if rcpt.Signature.KeyPurpose != signing.PurposeContractActivationSigning.String() {
		t.Fatalf("intent key_purpose = %q", rcpt.Signature.KeyPurpose)
	}

	receiptSigner := newSigner(t, "receipt-key")
	committed := PromoteCommittedPayload("sha256:target", "sha256:prior", "intent-1", "accepted", "")
	rcpt, err = SignReceipt(contractreceipt.PayloadContractPromoteCommitted, committed, ReceiptContext{
		EventID:   "018f0000-0000-7000-8000-000000000002",
		Timestamp: fixedNow,
		Principal: "learn",
		Actor:     "learn promote",
	}, receiptSigner, signing.PurposeReceiptSigning)
	if err != nil {
		t.Fatalf("SignReceipt promote committed: %v", err)
	}
	if rcpt.Signature.KeyPurpose != signing.PurposeReceiptSigning.String() {
		t.Fatalf("committed key_purpose = %q", rcpt.Signature.KeyPurpose)
	}

	_, err = SignReceipt(contractreceipt.PayloadContractPromoteCommitted, committed, ReceiptContext{
		EventID:   "018f0000-0000-7000-8000-000000000003",
		Timestamp: fixedNow,
	}, signer, signing.PurposeContractActivationSigning)
	if err == nil {
		t.Fatal("SignReceipt with wrong purpose succeeded")
	}
}

func TestSignReceiptGeneratesDefaultsAndPropagatesFailures(t *testing.T) {
	signer := newSigner(t, "receipt-key")
	payload := PromoteCommittedPayload("sha256:target", "sha256:prior", "intent-1", "accepted", "")
	rcpt, err := SignReceipt(contractreceipt.PayloadContractPromoteCommitted, payload, ReceiptContext{}, signer, signing.PurposeReceiptSigning)
	if err != nil {
		t.Fatalf("SignReceipt defaults: %v", err)
	}
	if rcpt.EventID == "" || rcpt.Timestamp.IsZero() {
		t.Fatalf("receipt missing generated event id or timestamp: %+v", rcpt)
	}
	rcpt, err = SignReceipt(contractreceipt.PayloadContractPromoteCommitted, payload, ReceiptContext{
		DeterministicEventID: "deterministic-event",
	}, signer, signing.PurposeReceiptSigning)
	if err != nil {
		t.Fatalf("SignReceipt deterministic event id: %v", err)
	}
	if rcpt.EventID != "deterministic-event" {
		t.Fatalf("event_id = %q, want deterministic-event", rcpt.EventID)
	}

	_, err = SignReceipt(contractreceipt.PayloadContractPromoteCommitted, func() {}, ReceiptContext{}, signer, signing.PurposeReceiptSigning)
	if err == nil {
		t.Fatal("SignReceipt function payload succeeded")
	}
	_, err = SignReceipt(contractreceipt.PayloadContractPromoteCommitted, payload, ReceiptContext{}, failingSigner{keyID: "receipt-key", err: fmt.Errorf("boom")}, signing.PurposeReceiptSigning)
	if err == nil {
		t.Fatal("SignReceipt signer error succeeded")
	}
	_, err = SignReceipt(contractreceipt.PayloadContractPromoteCommitted, payload, ReceiptContext{}, failingSigner{keyID: "receipt-key", sig: []byte("short")}, signing.PurposeReceiptSigning)
	if err == nil {
		t.Fatal("SignReceipt short signature succeeded")
	}
}

func newSigner(t *testing.T, keyID string) testSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return testSigner{keyID: keyID, priv: priv}
}

func rosterKey(signer testSigner, principal string, purpose signing.KeyPurpose) contract.KeyInfo {
	return contract.KeyInfo{
		KeyID:        signer.keyID,
		KeyPurpose:   purpose.String(),
		PublicKeyHex: hex.EncodeToString(signer.priv.Public().(ed25519.PublicKey)),
		Status:       contract.KeyStatusActive,
		Principal:    principal,
		ValidFrom:    fixedNow.Add(-time.Hour).Format(time.RFC3339),
	}
}

func loadedRoster(keys ...contract.KeyInfo) *signing.LoadedRoster {
	return &signing.LoadedRoster{Body: contract.KeyRoster{Keys: keys}}
}

func stringPtr(s string) *string {
	return &s
}

func manifestSig(keyID, principal string) contract.ManifestSignature {
	return contract.ManifestSignature{
		KeyID:      keyID,
		Principal:  principal,
		KeyPurpose: signing.PurposeContractActivationSigning.String(),
		Algorithm:  "ed25519",
		Signature:  "ed25519:" + stringsOf("0", 128),
	}
}

func stringsOf(s string, count int) string {
	out := ""
	for range count {
		out += s
	}
	return out
}
