// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These cover the state a crashed or killed generation leaves behind. The
// transaction is only worth having if the NEXT run reads that state correctly,
// so each case builds the residue by hand and asserts which pair survives.

func seedAgentPair(t *testing.T, dir string, pub, priv []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, dirPermission); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), priv, 0o600); err != nil {
		t.Fatalf("writing private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, publicKeyFile), pub, 0o600); err != nil {
		t.Fatalf("writing public key: %v", err)
	}
}

func encodedPair(t *testing.T) (pubPEM, privPEM []byte) {
	t.Helper()
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return []byte(EncodePublicKey(pub)), []byte(EncodePrivateKey(priv))
}

func TestAgentKeyPairExists_RejectsMismatchedPair(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	// A private key from one generation and a public key from another is
	// exactly what an interleaved concurrent write produced before this
	// transaction existed. Every signature made with it fails verification, so
	// the keystore must not report it as a usable identity.
	_, privA := encodedPair(t)
	pubB, _ := encodedPair(t)
	seedAgentPair(t, ks.agentDir("mixed"), pubB, privA)

	if ks.agentKeyPairExists("mixed") {
		t.Error("a mismatched key pair was reported as an existing identity")
	}
}

func TestAgentKeyPairExists_AcceptsCoherentPair(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	pub, priv := encodedPair(t)
	seedAgentPair(t, ks.agentDir("coherent"), pub, priv)

	if !ks.agentKeyPairExists("coherent") {
		t.Error("a coherent key pair was not recognized")
	}
}

func TestRecoverAgentTransaction_NoBackupIsNoop(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	pub, priv := encodedPair(t)
	seedAgentPair(t, ks.agentDir("agent"), pub, priv)

	if err := ks.recoverAgentTransaction("agent"); err != nil {
		t.Fatalf("recoverAgentTransaction: %v", err)
	}
	if !ks.agentKeyPairExists("agent") {
		t.Error("recovery disturbed an agent with no transaction in flight")
	}
}

func TestRecoverAgentTransaction_DropsBackupWhenActivePairIsComplete(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	// The crash happened AFTER the new pair was published. The active pair is
	// the newer one and the backup is dead weight; restoring it would silently
	// roll the operator back to a superseded key.
	newPub, newPriv := encodedPair(t)
	oldPub, oldPriv := encodedPair(t)
	seedAgentPair(t, ks.agentDir("agent"), newPub, newPriv)
	seedAgentPair(t, ks.agentBackupDir("agent"), oldPub, oldPriv)

	if err := ks.recoverAgentTransaction("agent"); err != nil {
		t.Fatalf("recoverAgentTransaction: %v", err)
	}

	if _, err := os.Stat(ks.agentBackupDir("agent")); !os.IsNotExist(err) {
		t.Errorf("backup survived recovery of a committed pair (stat err = %v)", err)
	}
	got, err := os.ReadFile(filepath.Clean(filepath.Join(ks.agentDir("agent"), publicKeyFile)))
	if err != nil {
		t.Fatalf("reading active public key: %v", err)
	}
	if string(got) != string(newPub) {
		t.Error("recovery replaced the committed pair with the backup")
	}
}

func TestRecoverAgentTransaction_RestoresBackupWhenActivePairIsIncomplete(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	// The crash happened MID-publication: the active directory holds a torn or
	// partial pair. The backup is the last coherent identity and must come back,
	// because the alternative is an operator who can no longer sign at all.
	oldPub, oldPriv := encodedPair(t)
	seedAgentPair(t, ks.agentBackupDir("agent"), oldPub, oldPriv)

	torn := ks.agentDir("agent")
	if err := os.MkdirAll(torn, dirPermission); err != nil {
		t.Fatalf("creating torn agent dir: %v", err)
	}
	_, orphanPriv := encodedPair(t)
	if err := os.WriteFile(filepath.Join(torn, privateKeyFile), orphanPriv, 0o600); err != nil {
		t.Fatalf("writing orphan private key: %v", err)
	}

	if err := ks.recoverAgentTransaction("agent"); err != nil {
		t.Fatalf("recoverAgentTransaction: %v", err)
	}

	if !ks.agentKeyPairExists("agent") {
		t.Fatal("recovery did not restore a usable identity")
	}
	got, err := os.ReadFile(filepath.Clean(filepath.Join(ks.agentDir("agent"), publicKeyFile)))
	if err != nil {
		t.Fatalf("reading restored public key: %v", err)
	}
	if string(got) != string(oldPub) {
		t.Error("restored identity is not the backed-up pair")
	}
	if _, err := os.Stat(ks.agentBackupDir("agent")); !os.IsNotExist(err) {
		t.Errorf("backup remained after being restored (stat err = %v)", err)
	}
}

func TestRecoverAgentTransaction_RefusesMismatchedBackup(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	// A backup whose halves came from different key pairs is not a recoverable
	// identity. Recovery used to check only containment, so it would delete the
	// incomplete active directory and promote this, leaving an agent whose
	// public key does not match its private key and destroying the evidence of
	// what went wrong. Refusing keeps both directories for an operator.
	pubA, _ := encodedPair(t)
	_, privB := encodedPair(t)
	seedAgentPair(t, ks.agentBackupDir("agent"), pubA, privB)

	torn := ks.agentDir("agent")
	if err := os.MkdirAll(torn, dirPermission); err != nil {
		t.Fatalf("creating torn agent dir: %v", err)
	}
	_, orphanPriv := encodedPair(t)
	if err := os.WriteFile(filepath.Join(torn, privateKeyFile), orphanPriv, 0o600); err != nil {
		t.Fatalf("writing orphan private key: %v", err)
	}

	err := ks.recoverAgentTransaction("agent")
	if err == nil {
		t.Fatal("recovery promoted a backup whose key halves do not match")
	}
	if !strings.Contains(err.Error(), "not a coherent key pair") {
		t.Errorf("error = %q, want it to name the incoherent backup", err)
	}

	// Both directories must survive, or the refusal has still destroyed the
	// operator's ability to investigate.
	if _, statErr := os.Stat(ks.agentBackupDir("agent")); statErr != nil {
		t.Errorf("backup was removed despite the refusal: %v", statErr)
	}
	if _, statErr := os.Stat(torn); statErr != nil {
		t.Errorf("incomplete active directory was removed despite the refusal: %v", statErr)
	}
}

func TestRecoverAgentTransaction_RefusesUnreadableBackupHalf(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	// Same refusal when a half is missing outright rather than mismatched, which
	// is the shape a crash mid-write leaves behind.
	pub, _ := encodedPair(t)
	backup := ks.agentBackupDir("agent")
	if err := os.MkdirAll(backup, dirPermission); err != nil {
		t.Fatalf("creating backup dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(backup, publicKeyFile), pub, 0o600); err != nil {
		t.Fatalf("writing lone public key: %v", err)
	}

	torn := ks.agentDir("agent")
	if err := os.MkdirAll(torn, dirPermission); err != nil {
		t.Fatalf("creating torn agent dir: %v", err)
	}

	if err := ks.recoverAgentTransaction("agent"); err == nil {
		t.Fatal("recovery promoted a backup missing its private key")
	}
	if _, statErr := os.Stat(backup); statErr != nil {
		t.Errorf("backup was removed despite the refusal: %v", statErr)
	}
}

func TestGenerateAgent_RecoversInterruptedTransactionFirst(t *testing.T) {
	ks := NewKeystore(t.TempDir())
	// Generation on a keystore holding crash residue must resolve the residue
	// before deciding whether the agent already exists. Otherwise the torn
	// directory reads as "no agent" and the prior identity is overwritten.
	oldPub, oldPriv := encodedPair(t)
	seedAgentPair(t, ks.agentBackupDir("agent"), oldPub, oldPriv)
	torn := ks.agentDir("agent")
	if err := os.MkdirAll(torn, dirPermission); err != nil {
		t.Fatalf("creating torn agent dir: %v", err)
	}

	_, err := ks.GenerateAgent("agent")
	if err == nil {
		t.Fatal("generation overwrote a recoverable prior identity")
	}
	if !ks.agentKeyPairExists("agent") {
		t.Error("prior identity was not recovered")
	}
	got, readErr := os.ReadFile(filepath.Clean(filepath.Join(ks.agentDir("agent"), publicKeyFile)))
	if readErr != nil {
		t.Fatalf("reading recovered public key: %v", readErr)
	}
	if string(got) != string(oldPub) {
		t.Error("recovered identity is not the backed-up pair")
	}
}
