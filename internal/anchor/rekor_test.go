// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	server := fakeRekorServer(t)
	proof, err := (RekorLog{URL: server.URL, Signer: priv}).Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if proof.Backend != RekorBackend || proof.Rekor == nil || proof.Rekor.Body == "" || proof.Rekor.Signature == "" {
		t.Fatalf("incomplete proof: %+v", proof)
	}
	if err := validateRekorSubmissionRecord(proof, checkpoint); err != nil {
		t.Fatalf("validateRekorSubmissionRecord: %v", err)
	}
	report := VerifyBundle(NewBundle(checkpoint, proof), receipts, []string{keyHex}, RekorLog{})
	if report.Valid || !strings.Contains(report.Error, "trusted Rekor SET") {
		t.Fatalf("VerifyBundle report = %+v, want fail-closed SET verification error", report)
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
	bodyBytes, err := base64.StdEncoding.DecodeString(proof.Rekor.Body)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	var body rekorSubmitRequest
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	body.Spec.Data.Hash.Value = strings.Repeat("0", 64)
	tamperedBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	tampered := proof
	tampered.Rekor = cloneRekorProof(proof.Rekor)
	tampered.Rekor.Body = base64.StdEncoding.EncodeToString(tamperedBody)
	tampered.EntryHash = sha256Hex([]byte(tampered.Rekor.Body))
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
	checkpointBytes, err := checkpointBytes(checkpoint)
	if err != nil {
		t.Fatalf("checkpointBytes: %v", err)
	}
	publicKey, signature, err := signRekorCheckpoint(checkpointBytes, attackerPriv)
	if err != nil {
		t.Fatalf("signRekorCheckpoint: %v", err)
	}
	body := rekorSubmitRequest{
		APIVersion: rekorHashedRekordAPIVersion,
		Kind:       rekorHashedRekordKind,
		Spec: rekorSubmitSpec{
			Data: rekorData{Hash: rekorHash{
				Algorithm: rekorSHA256Algorithm,
				Value:     sha256Hex(checkpointBytes),
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
	proof := Proof{
		Backend:     RekorBackend,
		LogID:       "TOTALLY-MADE-UP",
		LogIndex:    999999,
		EntryHash:   sha256Hex([]byte(encodedBody)),
		LogRootHash: "fabricated",
		Rekor: &RekorProof{
			URL:       "https://rekor.example.invalid",
			UUID:      "fake-uuid",
			Body:      encodedBody,
			PublicKey: publicKey,
			Signature: signature,
		},
	}
	if err := validateRekorSubmissionRecord(proof, checkpoint); err != nil {
		t.Fatalf("forged self-consistent submission record did not validate: %v", err)
	}
	report := VerifyBundle(NewBundle(checkpoint, proof), receipts, []string{keyHex}, RekorLog{})
	if report.Valid || !strings.Contains(report.Error, "trusted Rekor SET") {
		t.Fatalf("forged Rekor proof report = %+v, want fail-closed SET verification error", report)
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

func cloneRekorProof(in *RekorProof) *RekorProof {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func fakeRekorServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/log/entries" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var body rekorSubmitRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		raw, err := json.Marshal(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		encodedBody := base64.StdEncoding.EncodeToString(raw)
		entry := rekorEntry{
			LogID:    "fake-rekor-log",
			LogIndex: 7,
			Body:     encodedBody,
			Verification: rekorVerification{InclusionProof: rekorInclusionProof{
				RootHash: sha256Hex([]byte(encodedBody)),
			}},
		}
		_ = json.NewEncoder(w).Encode(map[string]rekorEntry{"fake-uuid": entry})
	}))
}
