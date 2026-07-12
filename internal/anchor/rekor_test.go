// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	fakeRekorIntegratedTime int64 = 1780000000
)

func TestRekorLogSubmitRecordsSubmissionProof(t *testing.T) {
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	server, logPub := fakeTrustedRekorServer(t)
	proof, err := (RekorLog{URL: server.URL, Signer: priv}).Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if proof.Backend != RekorBackend || proof.Rekor == nil {
		t.Fatalf("incomplete proof: %+v", proof)
	}
	if proof.LogID != "fake-rekor-log" || proof.LogIndex != 0 || proof.LogRootHash == "" || proof.EntryHash == "" {
		t.Fatalf("unexpected Rekor log metadata: %+v", proof)
	}
	if proof.Rekor.URL != server.URL ||
		proof.Rekor.UUID != "fake-uuid" ||
		proof.Rekor.Body == "" ||
		proof.Rekor.PublicKey == "" ||
		proof.Rekor.Signature == "" ||
		proof.Rekor.IntegratedTime != fakeRekorIntegratedTime ||
		proof.Rekor.SignedEntryTimestamp == "" ||
		proof.Rekor.InclusionProof == nil ||
		proof.Rekor.InclusionProof.RootHash != proof.LogRootHash ||
		proof.Rekor.InclusionProof.TreeSize != 1 {
		t.Fatalf("unexpected Rekor proof metadata: %+v", proof.Rekor)
	}
	if err := validateRekorSubmissionRecord(proof, checkpoint); err != nil {
		t.Fatalf("validateRekorSubmissionRecord: %v", err)
	}
	report := VerifyBundle(NewBundle(checkpoint, proof), receipts, []string{keyHex}, RekorLog{})
	if report.Valid || !strings.Contains(report.Error, "trusted Rekor log public key") {
		t.Fatalf("VerifyBundle report = %+v, want missing Rekor key error", report)
	}
	report = VerifyBundle(NewBundle(checkpoint, proof), receipts, []string{keyHex}, RekorLog{TrustedLogKeys: []crypto.PublicKey{logPub}})
	if !report.Valid {
		t.Fatalf("VerifyBundle with trusted Rekor key invalid: %s", report.Error)
	}
}

func TestRekorLogSubmitHashAlgorithm(t *testing.T) {
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	checkpointBytes, err := checkpointBytes(checkpoint)
	if err != nil {
		t.Fatalf("checkpointBytes: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Default (HashAlgorithm unset) submits SHA-512: Rekor v1 verifies
	// Ed25519 hashedrekord entries as Ed25519ph over a SHA-512 digest.
	defProof, err := (RekorLog{URL: fakeRekorServer(t).URL, Signer: priv}).Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit(default): %v", err)
	}
	defBody := decodeSubmittedRekorBody(t, defProof)
	if defBody.Spec.Data.Hash.Algorithm != rekorSHA512Algorithm {
		t.Fatalf("default hash algorithm = %q, want %q", defBody.Spec.Data.Hash.Algorithm, rekorSHA512Algorithm)
	}
	defSum := sha512.Sum512(checkpointBytes)
	if got, want := defBody.Spec.Data.Hash.Value, hex.EncodeToString(defSum[:]); got != want {
		t.Fatalf("default hash value = %q, want SHA-512 %q", got, want)
	}
	if err := validateRekorSubmissionRecord(defProof, checkpoint); err != nil {
		t.Fatalf("validateRekorSubmissionRecord(default): %v", err)
	}

	// Explicit SHA-512 remains accepted.
	proof, err := (RekorLog{URL: fakeRekorServer(t).URL, Signer: priv, HashAlgorithm: rekorSHA512Algorithm}).Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit(sha512): %v", err)
	}
	body := decodeSubmittedRekorBody(t, proof)
	if body.Spec.Data.Hash.Algorithm != rekorSHA512Algorithm {
		t.Fatalf("hash algorithm = %q, want %q", body.Spec.Data.Hash.Algorithm, rekorSHA512Algorithm)
	}
	sum := sha512.Sum512(checkpointBytes)
	if got, want := body.Spec.Data.Hash.Value, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("hash value = %q, want SHA-512 %q", got, want)
	}
	if err := validateRekorSubmissionRecord(proof, checkpoint); err != nil {
		t.Fatalf("validateRekorSubmissionRecord: %v", err)
	}

	// An unsupported algorithm fails closed at submit (never sends).
	if _, err := (RekorLog{URL: fakeRekorServer(t).URL, Signer: priv, HashAlgorithm: "sha3-256"}).Submit(checkpoint); err == nil || !strings.Contains(err.Error(), "unsupported rekor hash algorithm") {
		t.Fatalf("Submit(unsupported algorithm) err = %v, want unsupported algorithm error", err)
	}
	if _, err := (RekorLog{URL: fakeRekorServer(t).URL, Signer: priv, HashAlgorithm: rekorSHA256Algorithm}).Submit(checkpoint); err == nil || !strings.Contains(err.Error(), "unsupported rekor hash algorithm") {
		t.Fatalf("Submit(sha256) err = %v, want unsupported algorithm error", err)
	}

	legacyWithWrongSignature := proofWithRekorBody(t, proof, func(body *rekorSubmitRequest) {
		body.Spec.Data.Hash.Algorithm = rekorSHA256Algorithm
		body.Spec.Data.Hash.Value = sha256Hex(checkpointBytes)
	})
	if err := validateRekorSubmissionRecord(legacyWithWrongSignature, checkpoint); err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("validateRekorSubmissionRecord err = %v, want signature invalid", err)
	}

	mismatched := proofWithRekorBody(t, proof, func(body *rekorSubmitRequest) {
		body.Spec.Data.Hash.Value = sha256Hex(checkpointBytes)
	})
	if err := validateRekorSubmissionRecord(mismatched, checkpoint); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("validateRekorSubmissionRecord err = %v, want digest mismatch", err)
	}

	tampered := proofWithRekorBody(t, proof, func(body *rekorSubmitRequest) {
		body.Spec.Data.Hash.Value = strings.Repeat("0", sha512.Size*2)
	})
	if err := validateRekorSubmissionRecord(tampered, checkpoint); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("validateRekorSubmissionRecord err = %v, want digest mismatch", err)
	}
	if err := validateRekorSubmissionRecord(proof, checkpoint); err != nil {
		t.Fatalf("validateRekorSubmissionRecord after restore: %v", err)
	}
}

func TestRekorLogSubmitHashedRekordSignatureCoversArtifactDigest(t *testing.T) {
	receipts, keyHex := testReceiptChain(t, 2)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	checkpointBytes, err := checkpointBytes(checkpoint)
	if err != nil {
		t.Fatalf("checkpointBytes: %v", err)
	}
	logPub, logPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey log: %v", err)
	}
	_, entryPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey entry: %v", err)
	}

	checkpointPublicKey, checkpointSignature, err := signRekorCheckpoint(checkpointBytes, entryPriv)
	if err != nil {
		t.Fatalf("signRekorCheckpoint: %v", err)
	}
	checkpointSignedBody := rekorSubmitRequest{
		APIVersion: rekorHashedRekordAPIVersion,
		Kind:       rekorHashedRekordKind,
		Spec: rekorSubmitSpec{
			Data: rekorData{Hash: rekorHash{
				Algorithm: rekorSHA512Algorithm,
				Value:     rekorDigestHex(rekorSHA512Algorithm, checkpointBytes),
			}},
			Signature: rekorSignature{
				Content:   checkpointSignature,
				PublicKey: rekorPublicKey{Content: checkpointPublicKey},
			},
		},
	}
	if verifyRekorV1HashedRekordEd25519Signature(t, checkpointSignedBody, checkpointBytes) {
		t.Fatal("Rekor v1 verifier accepted checkpoint signature as hashedrekord artifact signature")
	}

	server := rekorServerWithEntryValidation(t, logPriv, func(body rekorSubmitRequest) error {
		if !verifyRekorV1HashedRekordEd25519Signature(t, body, checkpointBytes) {
			return errors.New("verifying signature: failed to verify signature: ed25519: invalid signature")
		}
		return nil
	})
	proof, err := (RekorLog{
		URL:           server.URL,
		Signer:        entryPriv,
		HashAlgorithm: rekorSHA512Algorithm,
	}).Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	body := decodeSubmittedRekorBody(t, proof)
	if !verifyRekorV1HashedRekordEd25519Signature(t, body, checkpointBytes) {
		t.Fatal("submitted hashedrekord signature does not verify under Rekor v1 rules")
	}

	tamperedArtifact := append([]byte(nil), checkpointBytes...)
	tamperedArtifact[len(tamperedArtifact)-1] ^= 0x01
	if verifyRekorV1HashedRekordEd25519Signature(t, body, tamperedArtifact) {
		t.Fatal("Rekor v1 verifier accepted signature for tampered artifact")
	}

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey wrong: %v", err)
	}
	wrongKeyBody := body
	wrongKeyBody.Spec.Signature.PublicKey.Content = rekorPublicKeyForTest(t, otherPub)
	if verifyRekorV1HashedRekordEd25519Signature(t, wrongKeyBody, checkpointBytes) {
		t.Fatal("Rekor v1 verifier accepted signature under wrong key")
	}

	if err := (RekorLog{TrustedLogKeys: []crypto.PublicKey{logPub}}).Verify(proof, checkpoint); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestRekorLogVerifyAcceptsLegacySHA256Ed25519CheckpointSignature(t *testing.T) {
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	logPub, logPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, entryPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey entry: %v", err)
	}
	proof := selfConsistentLegacySHA256RekorProof(t, checkpoint, entryPriv, logPriv)
	checkpointBytes, err := checkpointBytes(checkpoint)
	if err != nil {
		t.Fatalf("checkpointBytes: %v", err)
	}

	if err := (RekorLog{TrustedLogKeys: []crypto.PublicKey{logPub}}).Verify(proof, checkpoint); err != nil {
		t.Fatalf("Verify legacy SHA-256 raw Ed25519 proof: %v", err)
	}

	publicKey, signature, err := signRekorArtifact(checkpointBytes, rekorSHA512Algorithm, entryPriv)
	if err != nil {
		t.Fatalf("signRekorArtifact: %v", err)
	}
	candidate := proofWithRekorBody(t, proof, func(body *rekorSubmitRequest) {
		body.Spec.Signature.Content = signature
		body.Spec.Signature.PublicKey.Content = publicKey
	})
	candidate.Rekor.PublicKey = publicKey
	candidate.Rekor.Signature = signature
	if err := validateRekorSubmissionRecord(candidate, checkpoint); err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("validate SHA-256 proof with SHA-512ph signature err = %v, want signature invalid", err)
	}
}

func TestRekorArtifactSignatureRoundTripAndTampering(t *testing.T) {
	artifact := []byte("checkpoint artifact bytes")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	publicKey, signature, err := signRekorArtifact(artifact, rekorSHA512Algorithm, priv)
	if err != nil {
		t.Fatalf("signRekorArtifact: %v", err)
	}
	if got := decodeRekorEd25519PublicKeyForTest(t, publicKey); !got.Equal(pub) {
		t.Fatal("encoded Rekor public key does not match signer")
	}
	if err := verifyRekorSignature(artifact, rekorSHA512Algorithm, publicKey, signature); err != nil {
		t.Fatalf("verifyRekorSignature: %v", err)
	}

	tamperedArtifact := append([]byte(nil), artifact...)
	tamperedArtifact[0] ^= 0x01
	if err := verifyRekorSignature(tamperedArtifact, rekorSHA512Algorithm, publicKey, signature); err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("verifyRekorSignature tampered artifact err = %v, want signature invalid", err)
	}

	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey wrong: %v", err)
	}
	wrongPublicKey := rekorPublicKeyForTest(t, wrongPub)
	if err := verifyRekorSignature(artifact, rekorSHA512Algorithm, wrongPublicKey, signature); err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("verifyRekorSignature wrong key err = %v, want signature invalid", err)
	}
}

func TestRekorArtifactSignatureRejectsUnsupportedAlgorithms(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, _, err := signRekorArtifact([]byte("artifact"), rekorSHA256Algorithm, priv); err == nil || !strings.Contains(err.Error(), "unsupported rekor hash algorithm") {
		t.Fatalf("signRekorArtifact SHA-256 err = %v, want unsupported algorithm", err)
	}
	if _, _, err := signRekorArtifact([]byte("artifact"), "sha3-512", priv); err == nil || !strings.Contains(err.Error(), "unsupported rekor hash algorithm") {
		t.Fatalf("signRekorArtifact sha3 err = %v, want unsupported algorithm", err)
	}
	publicKey, signature, err := signRekorArtifact([]byte("artifact"), rekorSHA512Algorithm, priv)
	if err != nil {
		t.Fatalf("signRekorArtifact SHA-512: %v", err)
	}
	if err := verifyRekorSignature([]byte("artifact"), rekorSHA256Algorithm, publicKey, signature); err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("verifyRekorSignature SHA-256 with SHA-512ph signature err = %v, want signature invalid", err)
	}
}

func TestRekorArtifactSignatureRejectsMalformedInputs(t *testing.T) {
	artifact := []byte("checkpoint artifact bytes")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	publicKey, signature, err := signRekorArtifact(artifact, rekorSHA512Algorithm, priv)
	if err != nil {
		t.Fatalf("signRekorArtifact: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa GenerateKey: %v", err)
	}
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey rsa: %v", err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaDER})

	badDERPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not der")})
	cases := []struct {
		name      string
		publicKey string
		signature string
		want      string
	}{
		{name: "missing public key", publicKey: "", signature: signature, want: "required"},
		{name: "bad public key base64", publicKey: "not base64!", signature: signature, want: "decode rekor public key"},
		{name: "bad public key pem", publicKey: base64.StdEncoding.EncodeToString([]byte("not pem")), signature: signature, want: "parse rekor public key PEM"},
		{name: "bad public key der", publicKey: base64.StdEncoding.EncodeToString(badDERPEM), signature: signature, want: "parse rekor public key"},
		{name: "non ed25519 public key", publicKey: base64.StdEncoding.EncodeToString(rsaPEM), signature: signature, want: "not ed25519"},
		{name: "bad signature base64", publicKey: publicKey, signature: "not base64!", want: "decode rekor signature"},
		{name: "malformed signature", publicKey: publicKey, signature: base64.StdEncoding.EncodeToString([]byte("short signature")), want: "signature invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyRekorSignature(artifact, rekorSHA512Algorithm, tc.publicKey, tc.signature); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("verifyRekorSignature err = %v, want %q", err, tc.want)
			}
		})
	}

	corruptPriv := ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))
	if _, _, err := signRekorArtifact(artifact, rekorSHA512Algorithm, corruptPriv); err == nil || !strings.Contains(err.Error(), "validate rekor signing key") {
		t.Fatalf("signRekorArtifact corrupt key err = %v, want validation error", err)
	}
}

func TestRekorLogVerifyRejectsCheckpointSubstitution(t *testing.T) {
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	tamperedCheckpoint := checkpoint
	tamperedCheckpoint.RootHash = strings.Repeat("f", sha256.Size*2)
	if tamperedCheckpoint.RootHash == checkpoint.RootHash {
		t.Fatal("tampered checkpoint did not change root hash")
	}
	logPub, logPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey log: %v", err)
	}
	_, entryPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey entry: %v", err)
	}
	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey attacker: %v", err)
	}
	verifier := RekorLog{TrustedLogKeys: []crypto.PublicKey{logPub}}

	proof := selfConsistentRekorProofWithAlgorithm(t, checkpoint, entryPriv, logPriv, rekorSHA512Algorithm)
	if err := verifier.Verify(proof, checkpoint); err != nil {
		t.Fatalf("Verify original proof: %v", err)
	}
	if err := verifier.Verify(proof, tamperedCheckpoint); err == nil {
		t.Fatal("Verify accepted original proof for tampered checkpoint")
	}

	forged := proofWithRekorBodyForCheckpoint(t, proof, tamperedCheckpoint, attackerPriv, rekorSHA512Algorithm)
	if err := validateRekorSubmissionRecord(forged, tamperedCheckpoint); err != nil {
		t.Fatalf("validate forged submission record: %v", err)
	}
	if err := verifier.Verify(forged, tamperedCheckpoint); err == nil || !strings.Contains(err.Error(), "signed_entry_timestamp") {
		t.Fatalf("Verify forged logged body err = %v, want SET failure", err)
	}
}

func TestRekorSubmissionRecordRejectsUnsupportedHashAlgorithmBeforeDigestFallback(t *testing.T) {
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	checkpointBytes, err := checkpointBytes(checkpoint)
	if err != nil {
		t.Fatalf("checkpointBytes: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	proof, err := (RekorLog{URL: fakeRekorServer(t).URL, Signer: priv}).Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	candidate := proofWithRekorBody(t, proof, func(body *rekorSubmitRequest) {
		body.Spec.Data.Hash.Algorithm = "sha3-512"
		body.Spec.Data.Hash.Value = sha256Hex(checkpointBytes)
	})
	if err := validateRekorSubmissionRecord(candidate, checkpoint); err == nil || !strings.Contains(err.Error(), "unsupported rekor hash algorithm") {
		t.Fatalf("validateRekorSubmissionRecord err = %v, want unsupported algorithm", err)
	}
}

func TestRekorSubmissionRecordRejectsTampering(t *testing.T) {
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	proof, err := (RekorLog{URL: fakeRekorServer(t).URL, Signer: priv}).Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	if proof.Rekor == nil {
		t.Fatal("proof.Rekor nil")
	}
	tampered := proofWithRekorBody(t, proof, func(body *rekorSubmitRequest) {
		body.Spec.Data.Hash.Value = strings.Repeat("0", sha512.Size*2)
	})
	if err := validateRekorSubmissionRecord(tampered, checkpoint); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("validateRekorSubmissionRecord err = %v, want digest mismatch", err)
	}

	tamperedSig := proof
	tamperedSig.Rekor = cloneRekorProof(proof.Rekor)
	tamperedSig.Rekor.Signature = base64.StdEncoding.EncodeToString([]byte("not-a-valid-ed25519-signature"))
	if err := validateRekorSubmissionRecord(tamperedSig, checkpoint); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("validateRekorSubmissionRecord err = %v, want signature mismatch", err)
	}
}

func TestRekorSubmissionRecordRequiresMetadata(t *testing.T) {
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	proof, err := (RekorLog{URL: fakeRekorServer(t).URL, Signer: priv}).Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	cases := []struct {
		name string
		edit func(*Proof)
		want string
	}{
		{name: "url", edit: func(p *Proof) { p.Rekor.URL = "" }, want: "URL"},
		{name: "url whitespace", edit: func(p *Proof) { p.Rekor.URL = " \t" }, want: "URL"},
		{name: "url http remote", edit: func(p *Proof) { p.Rekor.URL = "http://rekor.example.invalid" }, want: "https"},
		{name: "url query", edit: func(p *Proof) { p.Rekor.URL = "https://rekor.example.invalid?debug=true" }, want: "query"},
		{name: "url fragment", edit: func(p *Proof) { p.Rekor.URL = "https://rekor.example.invalid#anchor" }, want: "fragment"},
		{name: "url userinfo", edit: func(p *Proof) { p.Rekor.URL = "https://user@rekor.example.invalid" }, want: "userinfo"},
		{name: "url noncanonical", edit: func(p *Proof) { p.Rekor.URL = "https://rekor.example.invalid/" }, want: "canonical"},
		{name: "uuid", edit: func(p *Proof) { p.Rekor.UUID = "" }, want: "UUID"},
		{name: "uuid whitespace", edit: func(p *Proof) { p.Rekor.UUID = " \t" }, want: "UUID"},
		{name: "log id", edit: func(p *Proof) { p.LogID = "" }, want: "log_id"},
		{name: "log id whitespace", edit: func(p *Proof) { p.LogID = " \t" }, want: "log_id"},
		{name: "body", edit: func(p *Proof) { p.Rekor.Body = "" }, want: "body"},
		{name: "body whitespace", edit: func(p *Proof) { p.Rekor.Body = " \t" }, want: "body"},
		{name: "entry hash", edit: func(p *Proof) { p.EntryHash = "" }, want: "entry_hash"},
		{name: "entry hash whitespace", edit: func(p *Proof) { p.EntryHash = " \t" }, want: "entry_hash"},
		{name: "root hash", edit: func(p *Proof) { p.LogRootHash = "" }, want: "log_root_hash"},
		{name: "root hash whitespace", edit: func(p *Proof) { p.LogRootHash = " \t" }, want: "log_root_hash"},
		{name: "integrated time", edit: func(p *Proof) { p.Rekor.IntegratedTime = 0 }, want: "integrated_time"},
		{name: "set", edit: func(p *Proof) { p.Rekor.SignedEntryTimestamp = "" }, want: "signed_entry_timestamp"},
		{name: "set whitespace", edit: func(p *Proof) { p.Rekor.SignedEntryTimestamp = " \t" }, want: "signed_entry_timestamp"},
		{name: "inclusion proof", edit: func(p *Proof) { p.Rekor.InclusionProof = nil }, want: "inclusion_proof"},
		{name: "inclusion root mismatch", edit: func(p *Proof) { p.Rekor.InclusionProof.RootHash = strings.Repeat("0", 64) }, want: "root_hash"},
		{name: "inclusion log index mismatch", edit: func(p *Proof) {
			p.Rekor.InclusionProof.TreeSize = 2
			p.Rekor.InclusionProof.LogIndex = 1
		}, want: "log_index"},
		{name: "inclusion tree size", edit: func(p *Proof) { p.Rekor.InclusionProof.TreeSize = 0 }, want: "tree_size"},
		{name: "inclusion checkpoint", edit: func(p *Proof) { p.Rekor.InclusionProof.Checkpoint = "" }, want: "checkpoint"},
		{name: "inclusion root hash short", edit: func(p *Proof) {
			p.LogRootHash = "aabb"
			p.Rekor.InclusionProof.RootHash = "aabb"
		}, want: "root_hash length"},
		{name: "inclusion proof hash short", edit: func(p *Proof) {
			p.Rekor.InclusionProof.Hashes = append(p.Rekor.InclusionProof.Hashes, "aabb")
		}, want: "proof hash 0 length"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proof
			candidate.Rekor = cloneRekorProof(proof.Rekor)
			tc.edit(&candidate)
			if err := validateRekorSubmissionRecord(candidate, checkpoint); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateRekorSubmissionRecord err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNormalizeRekorBaseURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		err  string
	}{
		{name: "default", raw: "", want: DefaultRekorURL},
		{name: "trim and canonicalize", raw: " HTTPS://Rekor.Example.Invalid/path/ ", want: "https://rekor.example.invalid/path"},
		{name: "local http allowed", raw: "http://127.0.0.1:3000/", want: "http://127.0.0.1:3000"},
		{name: "localhost http allowed", raw: "http://localhost:3000/", want: "http://localhost:3000"},
		{name: "remote http", raw: "http://rekor.example.invalid", err: "https"},
		{name: "query", raw: "https://rekor.example.invalid?debug=true", err: "query"},
		{name: "fragment", raw: "https://rekor.example.invalid#frag", err: "fragment"},
		{name: "userinfo", raw: "https://user@rekor.example.invalid", err: "userinfo"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeRekorBaseURL(tc.raw)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("normalizeRekorBaseURL err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeRekorBaseURL: %v", err)
			}
			if got != tc.want {
				t.Fatalf("normalizeRekorBaseURL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoadRekorPrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "rekor.key")
	if err := domsigning.SavePrivateKey(priv, path); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	loaded, err := LoadRekorPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadRekorPrivateKey: %v", err)
	}
	if !loaded.Equal(priv) {
		t.Fatal("loaded Rekor key does not match saved key")
	}
	if _, err := LoadRekorPrivateKey(filepath.Join(t.TempDir(), "missing.key")); err == nil || !strings.Contains(err.Error(), "load rekor signing key") {
		t.Fatalf("LoadRekorPrivateKey missing err = %v, want wrapped load error", err)
	}
}

func TestLoadRekorPublicKeyAcceptsPEMAndPipelockFormats(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	inline, err := LoadRekorPublicKey(pemText)
	if err != nil {
		t.Fatalf("LoadRekorPublicKey inline PEM: %v", err)
	}
	if !inline.(ed25519.PublicKey).Equal(pub) {
		t.Fatal("inline PEM key mismatch")
	}
	path := filepath.Join(t.TempDir(), "rekor.pub")
	if err := os.WriteFile(path, []byte(pemText), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fromFile, err := LoadRekorPublicKey(path)
	if err != nil {
		t.Fatalf("LoadRekorPublicKey file: %v", err)
	}
	if !fromFile.(ed25519.PublicKey).Equal(pub) {
		t.Fatal("file PEM key mismatch")
	}
	pipelockKey, err := LoadRekorPublicKey(domsigning.EncodePublicKey(pub))
	if err != nil {
		t.Fatalf("LoadRekorPublicKey pipelock: %v", err)
	}
	if !pipelockKey.(ed25519.PublicKey).Equal(pub) {
		t.Fatal("pipelock key mismatch")
	}
	keys, err := LoadRekorPublicKeys([]string{pemText, domsigning.EncodePublicKey(pub)})
	if err != nil {
		t.Fatalf("LoadRekorPublicKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("LoadRekorPublicKeys len = %d, want 2", len(keys))
	}
}

func TestLoadRekorPublicKeyRejectsMalformedInputs(t *testing.T) {
	dir := t.TempDir()
	badFile := filepath.Join(dir, "bad.pub")
	if err := os.WriteFile(badFile, []byte("not-a-key"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: " \t", want: "empty"},
		{name: "unsupported pem", input: "-----BEGIN TRUST ANCHOR-----\nAA==\n-----END TRUST ANCHOR-----", want: "unsupported PEM"},
		{name: "missing file path", input: filepath.Join(dir, "missing.pub"), want: "file does not exist"},
		{name: "bad file contents", input: badFile, want: "parse rekor log public key file"},
		{name: "bad inline value", input: "not-a-key", want: "parse rekor log public key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadRekorPublicKey(tc.input); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadRekorPublicKey err = %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := LoadRekorPublicKeys([]string{domsigning.EncodePublicKey(mustEd25519PublicKey(t)), "not-a-key"}); err == nil || !strings.Contains(err.Error(), "parse rekor log public key") {
		t.Fatalf("LoadRekorPublicKeys err = %v, want wrapped parse error", err)
	}
}

func TestRekorLogVerifyRejectsForgedSelfConsistentProof(t *testing.T) {
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	trustedLogPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey trusted: %v", err)
	}
	proof := selfConsistentRekorProof(t, checkpoint, attackerPriv, attackerPriv)
	if err := validateRekorSubmissionRecord(proof, checkpoint); err != nil {
		t.Fatalf("forged self-consistent submission record did not validate: %v", err)
	}
	report := VerifyBundle(NewBundle(checkpoint, proof), receipts, []string{keyHex}, RekorLog{TrustedLogKeys: []crypto.PublicKey{trustedLogPub}})
	if report.Valid || !strings.Contains(report.Error, "signed_entry_timestamp") {
		t.Fatalf("forged Rekor proof report = %+v, want SET verification failure", report)
	}
}

func TestRekorLogVerifyRejectsMalformedVerificationArtifacts(t *testing.T) {
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	logPub, logPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	proof := selfConsistentRekorProof(t, checkpoint, logPriv, logPriv)
	root, err := hex.DecodeString(proof.Rekor.InclusionProof.RootHash)
	if err != nil {
		t.Fatalf("DecodeString root: %v", err)
	}
	cases := []struct {
		name string
		edit func(*Proof)
		want string
	}{
		{name: "set base64", edit: func(p *Proof) {
			p.Rekor.SignedEntryTimestamp = "not base64!"
		}, want: "signed_entry_timestamp"},
		{name: "checkpoint root mismatch", edit: func(p *Proof) {
			p.Rekor.InclusionProof.Checkpoint = signedCheckpointForTest(t, 1, make([]byte, sha256.Size), logPriv)
		}, want: "checkpoint root hash"},
		{name: "checkpoint tree size mismatch", edit: func(p *Proof) {
			p.Rekor.InclusionProof.Checkpoint = signedCheckpointForTest(t, 2, root, logPriv)
		}, want: "checkpoint tree size"},
		{name: "checkpoint wrong signer", edit: func(p *Proof) {
			_, wrongPriv, genErr := ed25519.GenerateKey(rand.Reader)
			if genErr != nil {
				t.Fatalf("GenerateKey wrong: %v", genErr)
			}
			p.Rekor.InclusionProof.Checkpoint = signedCheckpointForTest(t, 1, root, wrongPriv)
		}, want: "checkpoint signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proof
			candidate.Rekor = cloneRekorProof(proof.Rekor)
			tc.edit(&candidate)
			err := (RekorLog{TrustedLogKeys: []crypto.PublicKey{logPub}}).Verify(candidate, checkpoint)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify err = %v, want %q", err, tc.want)
			}
		})
	}
	setOverflow := proof
	setOverflow.Rekor = cloneRekorProof(proof.Rekor)
	setOverflow.LogIndex = math.MaxUint64
	if err := verifyRekorSET(setOverflow, []crypto.PublicKey{logPub}); err == nil || !strings.Contains(err.Error(), "overflows SET payload") {
		t.Fatalf("verifyRekorSET overflow err = %v, want overflow", err)
	}
}

func TestVerifyRekorInclusionRejectsMalformedInputs(t *testing.T) {
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	_, logPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	proof := selfConsistentRekorProof(t, checkpoint, logPriv, logPriv)
	cases := []struct {
		name string
		edit func(*Proof)
		want string
	}{
		{name: "body base64", edit: func(p *Proof) {
			p.Rekor.Body = "not base64!"
		}, want: "decode rekor body"},
		{name: "root hex", edit: func(p *Proof) {
			p.Rekor.InclusionProof.RootHash = "not-hex"
		}, want: "decode rekor inclusion root_hash"},
		{name: "path hex", edit: func(p *Proof) {
			p.Rekor.InclusionProof.Hashes = []string{"not-hex"}
		}, want: "decode rekor inclusion proof hash 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proof
			candidate.Rekor = cloneRekorProof(proof.Rekor)
			tc.edit(&candidate)
			if err := verifyRekorInclusion(candidate); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("verifyRekorInclusion err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseSignedRekorCheckpointRejectsMalformedNotes(t *testing.T) {
	validRoot := base64.StdEncoding.EncodeToString([]byte("root"))
	validSig := base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 1, 's'})
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "no signature split", raw: "origin\n1\n" + validRoot + "\n", want: "malformed signed note"},
		{name: "signature block no trailing newline", raw: "origin\n1\n" + validRoot + "\n\n— fake " + validSig, want: "malformed signature block"},
		{name: "too few note lines", raw: "origin\n1\n\n— fake " + validSig + "\n", want: "too few lines"},
		{name: "empty origin", raw: "\n1\n" + validRoot + "\n\n— fake " + validSig + "\n", want: "origin is empty"},
		{name: "empty tree size", raw: "origin\n\n" + validRoot + "\n\n— fake " + validSig + "\n", want: "tree size is empty"},
		{name: "nonnumeric tree size", raw: "origin\none\n" + validRoot + "\n\n— fake " + validSig + "\n", want: "tree size is not numeric"},
		{name: "overflow tree size", raw: "origin\n18446744073709551616\n" + validRoot + "\n\n— fake " + validSig + "\n", want: "tree size overflows"},
		{name: "bad root", raw: "origin\n1\nnot-base64!\n\n— fake " + validSig + "\n", want: "decode rekor checkpoint root hash"},
		{name: "bad signature prefix", raw: "origin\n1\n" + validRoot + "\n\nbad\n", want: "signature line malformed"},
		{name: "bad signature base64", raw: "origin\n1\n" + validRoot + "\n\n— fake not-base64!\n", want: "decode rekor checkpoint signature"},
		{name: "small signature", raw: "origin\n1\n" + validRoot + "\n\n— fake AA==\n", want: "signature too small"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseSignedRekorCheckpoint(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseSignedRekorCheckpoint err = %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := parseRekorNoteSignatures([]byte("\n")); err == nil || !strings.Contains(err.Error(), "no signatures") {
		t.Fatalf("parseRekorNoteSignatures err = %v, want no signatures", err)
	}
}

func TestVerifySignature_RSAAndUnsupportedKeys(t *testing.T) {
	t.Parallel()
	msg := []byte("rekor checkpoint bytes")
	digest := sha256.Sum256(msg)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa GenerateKey: %v", err)
	}
	pss, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("SignPSS: %v", err)
	}
	if !verifySignature(&key.PublicKey, msg, pss) {
		t.Fatal("rsa pss: valid signature rejected")
	}
	pkcs1, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}
	if !verifySignature(&key.PublicKey, msg, pkcs1) {
		t.Fatal("rsa pkcs1v15: valid signature rejected")
	}
	if verifySignature(&key.PublicKey, []byte("wrong message"), pss) {
		t.Fatal("rsa: wrong-message signature accepted")
	}
	if verifySignature(struct{}{}, msg, pss) {
		t.Fatal("unsupported key type accepted")
	}
	if publicKeyHash(struct{}{}) != 0 {
		t.Fatal("unsupported key hash did not fail closed to zero")
	}
}

func TestRekorLogSubmitRejectsMalformedResponses(t *testing.T) {
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cases := []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{
			name: "status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "nope", http.StatusBadGateway)
			},
			want: "status 502",
		},
		{
			name: "missing uuid",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeDirectRekorEntry(t, w, r, "fake-rekor-log", "body")
			},
			want: "UUID required",
		},
		{
			name: "missing log id",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeMappedRekorEntry(t, w, r, "", "body", "aabb", "set", fakeRekorIntegratedTime)
			},
			want: "logID required",
		},
		{
			name: "missing body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeMappedRekorEntry(t, w, r, "fake-rekor-log", "", "aabb", "set", fakeRekorIntegratedTime)
			},
			want: "body required",
		},
		{
			name: "missing set",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeMappedRekorEntry(t, w, r, "fake-rekor-log", "body", "aabb", "", fakeRekorIntegratedTime)
			},
			want: "signed_entry_timestamp",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			t.Cleanup(server.Close)
			_, err := (RekorLog{URL: server.URL, Signer: priv}).Submit(checkpoint)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Submit err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRekorLogSubmitRejectsRequestFailures(t *testing.T) {
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := (RekorLog{URL: "://bad-url", Signer: priv}).Submit(checkpoint); err == nil || !strings.Contains(err.Error(), "parse rekor URL") {
		t.Fatalf("Submit bad URL err = %v, want parse error", err)
	}
	// Empty URL must fail closed rather than defaulting to the public
	// rekor.sigstore.dev: submission is an egress of checkpoint hash metadata
	// and must stay inside the operator's declared trust boundary.
	if _, err := (RekorLog{URL: "", Signer: priv}).Submit(checkpoint); err == nil || !strings.Contains(err.Error(), "rekor anchor URL is required") {
		t.Fatalf("Submit empty URL err = %v, want required-URL error", err)
	}
	if _, err := (RekorLog{URL: "   ", Signer: priv}).Submit(checkpoint); err == nil || !strings.Contains(err.Error(), "rekor anchor URL is required") {
		t.Fatalf("Submit blank URL err = %v, want required-URL error", err)
	}
	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	url := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := (RekorLog{URL: url, Signer: priv}).Submit(checkpoint); err == nil || !strings.Contains(err.Error(), "submit rekor entry") {
		t.Fatalf("Submit connection err = %v, want submit error", err)
	}
	if _, err := (RekorLog{URL: fakeRekorServer(t).URL}).Submit(checkpoint); err == nil || !strings.Contains(err.Error(), "signing key required") {
		t.Fatalf("Submit missing signer err = %v, want signing key error", err)
	}
}

func TestDecodeRekorEntryAcceptsRealisticUnknownFields(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte(`{"kind":"hashedrekord"}`))
	data := []byte(`{
		"fake-uuid": {
			"logID": "fake-rekor-log",
			"logIndex": 7,
			"integratedTime": 1780000000,
			"body": "` + body + `",
			"attestation": {"data": "ignored"},
			"verification": {
				"signedEntryTimestamp": "set-bytes",
				"inclusionProof": {
					"logIndex": 7,
					"treeSize": 8,
					"rootHash": "fake-root",
					"hashes": ["a", "b"],
					"checkpoint": "signed checkpoint"
				}
			}
		}
	}`)
	entry, uuid, err := decodeRekorEntry(data)
	if err != nil {
		t.Fatalf("decodeRekorEntry: %v", err)
	}
	if uuid != "fake-uuid" || entry.Body != body || entry.Verification.SignedEntryTimestamp != "set-bytes" {
		t.Fatalf("entry = %+v uuid=%q", entry, uuid)
	}
}

func TestDecodeRekorEntryRejectsMalformedResponses(t *testing.T) {
	for name, data := range map[string]string{
		"duplicate":        `{"fake-uuid":{"logID":"a"},"fake-uuid":{"logID":"b"}}`,
		"nested duplicate": `{"fake-uuid":{"logID":"a","verification":{"inclusionProof":{"rootHash":"a","rootHash":"b"}}}}`,
		"multiple":         `{"uuid-a":{"logID":"a"},"uuid-b":{"logID":"b"}}`,
		"mapped type":      `{"fake-uuid":{"logID":123}}`,
		"direct type":      `{"logID":123}`,
		"invalid":          `{not json`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeRekorEntry([]byte(data)); err == nil {
				t.Fatal("decodeRekorEntry err = nil, want failure")
			}
		})
	}
}

func cloneRekorProof(in *RekorProof) *RekorProof {
	if in == nil {
		return nil
	}
	out := *in
	if in.InclusionProof != nil {
		inc := *in.InclusionProof
		inc.Hashes = append([]string(nil), in.InclusionProof.Hashes...)
		out.InclusionProof = &inc
	}
	return &out
}

func decodeSubmittedRekorBody(t *testing.T, proof Proof) rekorSubmitRequest {
	t.Helper()
	if proof.Rekor == nil {
		t.Fatal("proof.Rekor nil")
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(proof.Rekor.Body)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	var body rekorSubmitRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return body
}

func proofWithRekorBody(t *testing.T, proof Proof, edit func(*rekorSubmitRequest)) Proof {
	t.Helper()
	body := decodeSubmittedRekorBody(t, proof)
	edit(&body)
	tamperedBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	candidate := proof
	candidate.Rekor = cloneRekorProof(proof.Rekor)
	candidate.Rekor.Body = base64.StdEncoding.EncodeToString(tamperedBody)
	candidate.EntryHash = sha256Hex([]byte(candidate.Rekor.Body))
	return candidate
}

func proofWithRekorBodyForCheckpoint(t *testing.T, proof Proof, checkpoint Checkpoint, signer ed25519.PrivateKey, algorithm string) Proof {
	t.Helper()
	checkpointBytes, err := checkpointBytes(checkpoint)
	if err != nil {
		t.Fatalf("checkpointBytes: %v", err)
	}
	publicKey, signature, err := signRekorArtifact(checkpointBytes, algorithm, signer)
	if err != nil {
		t.Fatalf("signRekorArtifact: %v", err)
	}
	candidate := proofWithRekorBody(t, proof, func(body *rekorSubmitRequest) {
		body.Spec.Data.Hash.Algorithm = algorithm
		body.Spec.Data.Hash.Value = rekorDigestHex(algorithm, checkpointBytes)
		body.Spec.Signature.Content = signature
		body.Spec.Signature.PublicKey.Content = publicKey
	})
	candidate.Rekor.PublicKey = publicKey
	candidate.Rekor.Signature = signature
	return candidate
}

func mustEd25519PublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub
}

func fakeRekorServer(t *testing.T) *httptest.Server {
	t.Helper()
	server, _ := fakeTrustedRekorServer(t)
	return server
}

func fakeTrustedRekorServer(t *testing.T) (*httptest.Server, ed25519.PublicKey) {
	t.Helper()
	logPub, logPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey log: %v", err)
	}
	server := rekorServerWithEntryValidation(t, logPriv, nil)
	return server, logPub
}

func rekorServerWithEntryValidation(t *testing.T, logPriv ed25519.PrivateKey, validate func(rekorSubmitRequest) error) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/log/entries" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var body rekorSubmitRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if validate != nil {
			if err := validate(body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		raw, err := json.Marshal(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		encodedBody := base64.StdEncoding.EncodeToString(raw)
		rootHashBytes := rfc6962LeafHash(raw)
		rootHash := hex.EncodeToString(rootHashBytes)
		set := signedEntryTimestampForTest(t, "fake-rekor-log", 0, encodedBody, logPriv)
		entry := rekorEntry{
			LogID:          "fake-rekor-log",
			LogIndex:       0,
			IntegratedTime: fakeRekorIntegratedTime,
			Body:           encodedBody,
			Verification: rekorVerification{
				SignedEntryTimestamp: set,
				InclusionProof: rekorInclusionProof{
					RootHash:   rootHash,
					LogIndex:   0,
					TreeSize:   1,
					Checkpoint: signedCheckpointForTest(t, 1, rootHashBytes, logPriv),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(map[string]rekorEntry{"fake-uuid": entry})
	}))
	t.Cleanup(server.Close)
	return server
}

func verifyRekorV1HashedRekordEd25519Signature(t *testing.T, body rekorSubmitRequest, artifact []byte) bool {
	t.Helper()
	if body.Spec.Data.Hash.Algorithm != rekorSHA512Algorithm {
		t.Fatalf("test Rekor v1 Ed25519 helper supports %q, got %q", rekorSHA512Algorithm, body.Spec.Data.Hash.Algorithm)
	}
	sum := sha512.Sum512(artifact)
	if body.Spec.Data.Hash.Value != hex.EncodeToString(sum[:]) {
		return false
	}
	pub := decodeRekorEd25519PublicKeyForTest(t, body.Spec.Signature.PublicKey.Content)
	sig, err := base64.StdEncoding.DecodeString(body.Spec.Signature.Content)
	if err != nil {
		t.Fatalf("DecodeString signature: %v", err)
	}
	return ed25519.VerifyWithOptions(pub, sum[:], sig, &ed25519.Options{Hash: crypto.SHA512}) == nil
}

func decodeRekorEd25519PublicKeyForTest(t *testing.T, encoded string) ed25519.PublicKey {
	t.Helper()
	pemBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString public key: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal("public key is not PEM PUBLIC KEY")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want ed25519.PublicKey", parsed)
	}
	return pub
}

func rekorPublicKeyForTest(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if len(pemBytes) == 0 {
		t.Fatal("EncodeToMemory public key")
	}
	return base64.StdEncoding.EncodeToString(pemBytes)
}

func signRekorCheckpoint(data []byte, priv ed25519.PrivateKey) (publicKey string, signature string, err error) {
	if err := domsigning.ValidatePrivateKeyConsistency(priv); err != nil {
		return "", "", fmt.Errorf("validate rekor signing key: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", "", errors.New("rekor signing key public key is not ed25519")
	}
	publicKey, err = encodeRekorPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	return publicKey, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)), nil
}

func writeDirectRekorEntry(t *testing.T, w http.ResponseWriter, r *http.Request, logID, body string) {
	t.Helper()
	if body == "body" {
		body = encodedRekorRequestBody(t, r)
	}
	_ = json.NewEncoder(w).Encode(rekorEntry{
		LogID:          logID,
		LogIndex:       7,
		IntegratedTime: fakeRekorIntegratedTime,
		Body:           body,
		Verification: rekorVerification{
			SignedEntryTimestamp: "set",
			InclusionProof:       rekorInclusionProof{RootHash: "aabb", TreeSize: 1, Checkpoint: "checkpoint"},
		},
	})
}

func writeMappedRekorEntry(t *testing.T, w http.ResponseWriter, r *http.Request, logID, body, rootHash, set string, integratedTime int64) {
	t.Helper()
	if body == "body" {
		body = encodedRekorRequestBody(t, r)
	}
	_ = json.NewEncoder(w).Encode(map[string]rekorEntry{"fake-uuid": {
		LogID:          logID,
		LogIndex:       7,
		IntegratedTime: integratedTime,
		Body:           body,
		Verification: rekorVerification{
			SignedEntryTimestamp: set,
			InclusionProof:       rekorInclusionProof{RootHash: rootHash, TreeSize: 1, Checkpoint: "checkpoint"},
		},
	}})
}

func encodedRekorRequestBody(t *testing.T, r *http.Request) string {
	t.Helper()
	var body rekorSubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatalf("Decode request: %v", err)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func selfConsistentRekorProof(t *testing.T, checkpoint Checkpoint, entrySigner, logSigner ed25519.PrivateKey) Proof {
	t.Helper()
	return selfConsistentRekorProofWithAlgorithm(t, checkpoint, entrySigner, logSigner, rekorDefaultSubmitHashAlgorithm)
}

func selfConsistentLegacySHA256RekorProof(t *testing.T, checkpoint Checkpoint, entrySigner, logSigner ed25519.PrivateKey) Proof {
	t.Helper()
	checkpointBytes, err := checkpointBytes(checkpoint)
	if err != nil {
		t.Fatalf("checkpointBytes: %v", err)
	}
	publicKey, signature, err := signRekorCheckpoint(checkpointBytes, entrySigner)
	if err != nil {
		t.Fatalf("signRekorCheckpoint: %v", err)
	}
	body := rekorSubmitRequest{
		APIVersion: rekorHashedRekordAPIVersion,
		Kind:       rekorHashedRekordKind,
		Spec: rekorSubmitSpec{
			Data: rekorData{Hash: rekorHash{
				Algorithm: rekorSHA256Algorithm,
				Value:     rekorDigestHex(rekorSHA256Algorithm, checkpointBytes),
			}},
			Signature: rekorSignature{
				Content:   signature,
				PublicKey: rekorPublicKey{Content: publicKey},
			},
		},
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	encodedBody := base64.StdEncoding.EncodeToString(bodyBytes)
	rootHash := rfc6962LeafHash(bodyBytes)
	return Proof{
		Backend:     RekorBackend,
		LogID:       "fake-rekor-log",
		LogIndex:    0,
		EntryHash:   sha256Hex([]byte(encodedBody)),
		LogRootHash: hex.EncodeToString(rootHash),
		Rekor: &RekorProof{
			URL:                  "https://rekor.example.invalid",
			UUID:                 "fake-uuid",
			Body:                 encodedBody,
			PublicKey:            publicKey,
			Signature:            signature,
			IntegratedTime:       fakeRekorIntegratedTime,
			SignedEntryTimestamp: signedEntryTimestampForTest(t, "fake-rekor-log", 0, encodedBody, logSigner),
			InclusionProof: &RekorInclusionProof{
				RootHash:   hex.EncodeToString(rootHash),
				LogIndex:   0,
				TreeSize:   1,
				Checkpoint: signedCheckpointForTest(t, 1, rootHash, logSigner),
			},
		},
	}
}

func selfConsistentRekorProofWithAlgorithm(t *testing.T, checkpoint Checkpoint, entrySigner, logSigner ed25519.PrivateKey, algorithm string) Proof {
	t.Helper()
	checkpointBytes, err := checkpointBytes(checkpoint)
	if err != nil {
		t.Fatalf("checkpointBytes: %v", err)
	}
	publicKey, signature, err := signRekorArtifact(checkpointBytes, algorithm, entrySigner)
	if err != nil {
		t.Fatalf("signRekorArtifact: %v", err)
	}
	body := rekorSubmitRequest{
		APIVersion: rekorHashedRekordAPIVersion,
		Kind:       rekorHashedRekordKind,
		Spec: rekorSubmitSpec{
			Data: rekorData{Hash: rekorHash{
				Algorithm: algorithm,
				Value:     rekorDigestHex(algorithm, checkpointBytes),
			}},
			Signature: rekorSignature{
				Content:   signature,
				PublicKey: rekorPublicKey{Content: publicKey},
			},
		},
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	encodedBody := base64.StdEncoding.EncodeToString(bodyBytes)
	rootHash := rfc6962LeafHash(bodyBytes)
	proof := Proof{
		Backend:     RekorBackend,
		LogID:       "fake-rekor-log",
		LogIndex:    0,
		EntryHash:   sha256Hex([]byte(encodedBody)),
		LogRootHash: hex.EncodeToString(rootHash),
		Rekor: &RekorProof{
			URL:                  "https://rekor.example.invalid",
			UUID:                 "fake-uuid",
			Body:                 encodedBody,
			PublicKey:            publicKey,
			Signature:            signature,
			IntegratedTime:       fakeRekorIntegratedTime,
			SignedEntryTimestamp: signedEntryTimestampForTest(t, "fake-rekor-log", 0, encodedBody, logSigner),
			InclusionProof: &RekorInclusionProof{
				RootHash:   hex.EncodeToString(rootHash),
				LogIndex:   0,
				TreeSize:   1,
				Checkpoint: signedCheckpointForTest(t, 1, rootHash, logSigner),
			},
		},
	}
	return proof
}

func signedEntryTimestampForTest(t *testing.T, logID string, logIndex uint64, body string, priv ed25519.PrivateKey) string {
	t.Helper()
	proof := Proof{
		LogID:    logID,
		LogIndex: logIndex,
		Rekor: &RekorProof{
			Body:           body,
			IntegratedTime: fakeRekorIntegratedTime,
		},
	}
	payload, err := canonicalRekorSETPayload(proof)
	if err != nil {
		t.Fatalf("canonicalRekorSETPayload: %v", err)
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
}

func signedCheckpointForTest(t *testing.T, treeSize uint64, root []byte, priv ed25519.PrivateKey) string {
	t.Helper()
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("private key public half is not Ed25519")
	}
	note := fmt.Sprintf("fake-rekor-log\n%d\n%s\n", treeSize, base64.StdEncoding.EncodeToString(root))
	sig := ed25519.Sign(priv, []byte(note))
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], publicKeyHash(pub))
	encoded := base64.StdEncoding.EncodeToString(append(prefix[:], sig...))
	return note + "\n\u2014 fake-rekor " + encoded + "\n"
}

// TestVerifyRFC6962Inclusion_MultiNodeTrees exercises the inclusion-proof loop
// against multi-leaf Merkle trees, including unbalanced ones. The integration
// tests only build TreeSize=1 trees (empty proof path), so without this the
// fn/sn navigation loop \u2014 exactly where Merkle-proof off-by-ones live \u2014 has no
// coverage. The expected root and audit path are computed independently here,
// straight from the RFC 6962 recursive definitions, so a regression in the
// verifier loop produces a mismatch rather than a self-consistent pass.
func TestVerifyRFC6962Inclusion_MultiNodeTrees(t *testing.T) {
	t.Parallel()
	for _, size := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 16} {
		hashed := make([][]byte, size)
		for i := range hashed {
			hashed[i] = rfc6962LeafHash([]byte(fmt.Sprintf("leaf-%d-of-%d", i, size)))
		}
		root := rfc6962TestMerkleRoot(hashed)
		usize := uint64(len(hashed))
		for idx := range hashed {
			uidx := uint64(idx)
			path := rfc6962TestAuditPath(idx, hashed)
			if err := verifyRFC6962Inclusion(uidx, usize, hashed[idx], path, root); err != nil {
				t.Fatalf("size=%d idx=%d: valid inclusion proof rejected: %v", size, idx, err)
			}
			// Tampered sibling must fail.
			if len(path) > 0 {
				bad := rfc6962TestClonePath(path)
				bad[0][0] ^= 0xFF
				if err := verifyRFC6962Inclusion(uidx, usize, hashed[idx], bad, root); err == nil {
					t.Fatalf("size=%d idx=%d: tampered proof hash accepted", size, idx)
				}
			}
			// Forged leaf must fail.
			if err := verifyRFC6962Inclusion(uidx, usize, rfc6962LeafHash([]byte("forged")), path, root); err == nil {
				t.Fatalf("size=%d idx=%d: forged leaf accepted", size, idx)
			}
			// Over-long proof (extra hash) must fail.
			over := append(rfc6962TestClonePath(path), rfc6962LeafHash([]byte("extra")))
			if err := verifyRFC6962Inclusion(uidx, usize, hashed[idx], over, root); err == nil {
				t.Fatalf("size=%d idx=%d: over-long proof accepted", size, idx)
			}
			// Truncated proof (too short) must fail.
			if len(path) > 0 {
				short := rfc6962TestClonePath(path)[:len(path)-1]
				if err := verifyRFC6962Inclusion(uidx, usize, hashed[idx], short, root); err == nil {
					t.Fatalf("size=%d idx=%d: truncated proof accepted", size, idx)
				}
			}
			// Wrong index against a valid path must fail.
			if wrongIdx := (uidx + 1) % usize; wrongIdx != uidx {
				if err := verifyRFC6962Inclusion(wrongIdx, usize, hashed[idx], path, root); err == nil {
					t.Fatalf("size=%d idx=%d: proof accepted under wrong index %d", size, idx, wrongIdx)
				}
			}
		}
	}
}

// rfc6962TestMerkleRoot computes the RFC 6962 Merkle Tree Hash of pre-hashed
// leaves, independently of the verifier under test.
func rfc6962TestMerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := rfc6962TestSplit(len(leaves))
	return rfc6962NodeHash(rfc6962TestMerkleRoot(leaves[:k]), rfc6962TestMerkleRoot(leaves[k:]))
}

// rfc6962TestAuditPath builds the RFC 6962 inclusion path for leaf m, ordered
// from the leaf level upward (the order the verifier consumes it).
func rfc6962TestAuditPath(m int, leaves [][]byte) [][]byte {
	if len(leaves) == 1 {
		return nil
	}
	k := rfc6962TestSplit(len(leaves))
	if m < k {
		return append(rfc6962TestAuditPath(m, leaves[:k]), rfc6962TestMerkleRoot(leaves[k:]))
	}
	return append(rfc6962TestAuditPath(m-k, leaves[k:]), rfc6962TestMerkleRoot(leaves[:k]))
}

// rfc6962TestSplit returns the largest power of two strictly less than n.
func rfc6962TestSplit(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func rfc6962TestClonePath(path [][]byte) [][]byte {
	out := make([][]byte, len(path))
	for i, h := range path {
		out[i] = append([]byte(nil), h...)
	}
	return out
}

// TestVerifySignature_AcrossKeyTypes exercises the production signature path.
// The public-good Rekor log signs SETs and checkpoints with ECDSA P-256, but
// every other test in this package uses Ed25519, so the ecdsa branch of
// verifySignature ships untested otherwise.
func TestVerifySignature_AcrossKeyTypes(t *testing.T) {
	t.Parallel()
	msg := []byte("rekor set or checkpoint note bytes")
	other := []byte("a different message")

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 GenerateKey: %v", err)
	}
	if !verifySignature(edPub, msg, ed25519.Sign(edPriv, msg)) {
		t.Fatal("ed25519: valid signature rejected")
	}
	if verifySignature(edPub, msg, ed25519.Sign(edPriv, other)) {
		t.Fatal("ed25519: wrong-message signature accepted")
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa GenerateKey: %v", err)
	}
	digest := sha256.Sum256(msg)
	ecSig, err := ecdsa.SignASN1(rand.Reader, ecKey, digest[:])
	if err != nil {
		t.Fatalf("ecdsa SignASN1: %v", err)
	}
	if !verifySignature(&ecKey.PublicKey, msg, ecSig) {
		t.Fatal("ecdsa P-256: valid signature rejected")
	}
	otherDigest := sha256.Sum256(other)
	otherSig, err := ecdsa.SignASN1(rand.Reader, ecKey, otherDigest[:])
	if err != nil {
		t.Fatalf("ecdsa SignASN1 (other): %v", err)
	}
	if verifySignature(&ecKey.PublicKey, msg, otherSig) {
		t.Fatal("ecdsa P-256: wrong-message signature accepted")
	}

	// A different ECDSA key must not validate.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa GenerateKey (other): %v", err)
	}
	if verifySignature(&otherKey.PublicKey, msg, ecSig) {
		t.Fatal("ecdsa P-256: signature accepted under wrong key")
	}
}
