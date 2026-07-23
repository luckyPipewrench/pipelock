// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnchorProofBackendRekorConsistency(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-07-23T12:00:00Z")
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}

	localLog := LocalLog{Path: filepath.Join(t.TempDir(), "anchor.jsonl"), LogID: "test-log"}
	localProof, err := localLog.Submit(checkpoint)
	if err != nil {
		t.Fatalf("local Submit: %v", err)
	}
	cleanLocalBundle := NewBundle(checkpoint, localProof)
	cleanLocalJSON, err := json.Marshal(cleanLocalBundle)
	if err != nil {
		t.Fatalf("marshal clean local bundle: %v", err)
	}

	forgedLocalBundle := cleanLocalBundle
	forgedLocalBundle.Proof.Rekor = &RekorProof{
		URL:  "https://rekor.vendor.example",
		UUID: "forged-entry",
	}
	forgedLocalJSON, err := json.Marshal(forgedLocalBundle)
	if err != nil {
		t.Fatalf("marshal forged local bundle: %v", err)
	}

	t.Run("loader rejects local proof carrying Rekor material", func(t *testing.T) {
		if _, err := LoadBundleBytes(forgedLocalJSON); err == nil || !strings.Contains(err.Error(), "must not carry rekor proof material") {
			t.Fatalf("LoadBundleBytes error = %v, want Rekor/backend consistency rejection", err)
		}
	})

	t.Run("bundle verifier rejects local proof carrying Rekor material", func(t *testing.T) {
		report := VerifyBundle(forgedLocalBundle, receipts, []string{keyHex}, localLog)
		if report.Valid || !strings.Contains(report.Error, "must not carry rekor proof material") {
			t.Fatalf("VerifyBundle report = %+v, want Rekor/backend consistency rejection", report)
		}
	})

	t.Run("local verifier rejects Rekor material directly", func(t *testing.T) {
		if err := localLog.Verify(forgedLocalBundle.Proof, checkpoint); err == nil || !strings.Contains(err.Error(), "must not carry rekor proof material") {
			t.Fatalf("LocalLog.Verify error = %v, want Rekor/backend consistency rejection", err)
		}
	})

	t.Run("clean local bundle still loads and verifies", func(t *testing.T) {
		loaded, err := LoadBundleBytes(cleanLocalJSON)
		if err != nil {
			t.Fatalf("LoadBundleBytes clean local bundle: %v", err)
		}
		if report := VerifyBundle(loaded, receipts, []string{keyHex}, localLog); !report.Valid {
			t.Fatalf("VerifyBundle clean local bundle invalid: %s", report.Error)
		}
	})

	t.Run("real Rekor bundle still loads and verifies", func(t *testing.T) {
		_, entrySigner, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate Rekor entry key: %v", err)
		}
		logPublic, logSigner, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate Rekor log key: %v", err)
		}
		rekorProof := selfConsistentRekorProof(t, checkpoint, entrySigner, logSigner)
		rekorJSON, err := json.Marshal(NewBundle(checkpoint, rekorProof))
		if err != nil {
			t.Fatalf("marshal Rekor bundle: %v", err)
		}
		loaded, err := LoadBundleBytes(rekorJSON)
		if err != nil {
			t.Fatalf("LoadBundleBytes Rekor bundle: %v", err)
		}
		backend := RekorLog{TrustedLogKeys: []crypto.PublicKey{logPublic}}
		if report := VerifyBundle(loaded, receipts, []string{keyHex}, backend); !report.Valid {
			t.Fatalf("VerifyBundle Rekor bundle invalid: %s", report.Error)
		}
	})

	t.Run("loader rejects rekor proof missing Rekor material", func(t *testing.T) {
		strippedRekorBundle := cleanLocalBundle
		strippedRekorBundle.Backend = RekorBackend
		strippedRekorBundle.Proof.Backend = RekorBackend
		strippedRekorBundle.Proof.Rekor = nil
		strippedJSON, err := json.Marshal(strippedRekorBundle)
		if err != nil {
			t.Fatalf("marshal stripped rekor bundle: %v", err)
		}
		if _, err := LoadBundleBytes(strippedJSON); err == nil || !strings.Contains(err.Error(), "requires rekor proof material") {
			t.Fatalf("LoadBundleBytes error = %v, want rekor-material-required rejection", err)
		}
	})

	t.Run("bundle verifier rejects rekor proof missing Rekor material", func(t *testing.T) {
		strippedRekorBundle := cleanLocalBundle
		strippedRekorBundle.Backend = RekorBackend
		strippedRekorBundle.Proof.Backend = RekorBackend
		strippedRekorBundle.Proof.Rekor = nil
		report := VerifyBundle(strippedRekorBundle, receipts, []string{keyHex}, RekorLog{})
		if report.Valid || !strings.Contains(report.Error, "requires rekor proof material") {
			t.Fatalf("VerifyBundle report = %+v, want rekor-material-required rejection", report)
		}
	})
}
