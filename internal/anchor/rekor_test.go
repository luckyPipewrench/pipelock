// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	fakeRekorIntegratedTime int64 = 1780000000
	fakeRekorRootHash             = "fake-root"
	fakeRekorSET                  = "fake-set"
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
	if proof.Backend != RekorBackend || proof.Rekor == nil {
		t.Fatalf("incomplete proof: %+v", proof)
	}
	if proof.LogID != "fake-rekor-log" || proof.LogIndex != 7 || proof.LogRootHash != fakeRekorRootHash || proof.EntryHash == "" {
		t.Fatalf("unexpected Rekor log metadata: %+v", proof)
	}
	if proof.Rekor.URL != server.URL ||
		proof.Rekor.UUID != "fake-uuid" ||
		proof.Rekor.Body == "" ||
		proof.Rekor.PublicKey == "" ||
		proof.Rekor.Signature == "" ||
		proof.Rekor.IntegratedTime != fakeRekorIntegratedTime ||
		proof.Rekor.SignedEntryTimestamp != fakeRekorSET {
		t.Fatalf("unexpected Rekor proof metadata: %+v", proof.Rekor)
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
		LogRootHash: "fabricated-root",
		Rekor: &RekorProof{
			URL:                  "https://rekor.example.invalid",
			UUID:                 "fake-uuid",
			Body:                 encodedBody,
			PublicKey:            publicKey,
			Signature:            signature,
			IntegratedTime:       fakeRekorIntegratedTime,
			SignedEntryTimestamp: fakeRekorSET,
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
				writeMappedRekorEntry(t, w, r, "", "body", fakeRekorRootHash, fakeRekorSET, fakeRekorIntegratedTime)
			},
			want: "logID required",
		},
		{
			name: "missing body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeMappedRekorEntry(t, w, r, "fake-rekor-log", "", fakeRekorRootHash, fakeRekorSET, fakeRekorIntegratedTime)
			},
			want: "body required",
		},
		{
			name: "missing set",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeMappedRekorEntry(t, w, r, "fake-rekor-log", "body", fakeRekorRootHash, "", fakeRekorIntegratedTime)
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
	return &out
}

func fakeRekorServer(t *testing.T) *httptest.Server {
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
		raw, err := json.Marshal(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		encodedBody := base64.StdEncoding.EncodeToString(raw)
		entry := rekorEntry{
			LogID:          "fake-rekor-log",
			LogIndex:       7,
			IntegratedTime: fakeRekorIntegratedTime,
			Body:           encodedBody,
			Verification: rekorVerification{
				SignedEntryTimestamp: fakeRekorSET,
				InclusionProof: rekorInclusionProof{
					RootHash: fakeRekorRootHash,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(map[string]rekorEntry{"fake-uuid": entry})
	}))
	t.Cleanup(server.Close)
	return server
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
			SignedEntryTimestamp: fakeRekorSET,
			InclusionProof:       rekorInclusionProof{RootHash: fakeRekorRootHash},
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
			InclusionProof:       rekorInclusionProof{RootHash: rootHash},
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
