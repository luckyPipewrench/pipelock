// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type errorReadCloser struct {
	err error
}

func (r errorReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (errorReadCloser) Close() error               { return nil }

func securityRekorCheckpoint(t *testing.T) (Checkpoint, ed25519.PrivateKey) {
	t.Helper()
	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return checkpoint, signer
}

func TestRekorSubmitFailsClosedOnTransportBoundaries(t *testing.T) {
	checkpoint, signer := securityRekorCheckpoint(t)
	readFailure := errors.New("injected response read failure")

	tests := []struct {
		name      string
		transport roundTripperFunc
		want      string
		wantIs    error
	}{
		{
			name: "cancellation",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, context.Canceled
			},
			want:   "submit rekor entry",
			wantIs: context.Canceled,
		},
		{
			name: "response read failure",
			transport: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       errorReadCloser{err: readFailure},
				}, nil
			},
			want:   "read rekor response",
			wantIs: readFailure,
		},
		{
			name: "malformed response",
			transport: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"uuid":`)),
				}, nil
			},
			want: "EOF",
		},
		{
			name: "response size limit",
			transport: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'x'}, rekorMaxResponseBytes+1))),
				}, nil
			},
			want: "exceeds",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: tc.transport}
			_, err := (RekorLog{
				URL:        "http://localhost",
				HTTPClient: client,
				Signer:     signer,
			}).Submit(checkpoint)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Submit error = %v, want %q", err, tc.want)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("Submit error = %v, want errors.Is(%v)", err, tc.wantIs)
			}
		})
	}
}

func TestRekorSubmissionRecordRejectsMalformedIntegrityFields(t *testing.T) {
	checkpoint, signer := securityRekorCheckpoint(t)
	proof := selfConsistentRekorProof(t, checkpoint, signer, signer)

	tests := []struct {
		name string
		edit func(*Proof)
		want string
	}{
		{name: "wrong backend", edit: func(p *Proof) { p.Backend = LocalBackend }, want: "not \"rekor\""},
		{name: "missing proof", edit: func(p *Proof) { p.Rekor = nil }, want: "rekor proof required"},
		{name: "invalid body base64", edit: func(p *Proof) {
			p.Rekor.Body = "!"
			p.EntryHash = sha256Hex([]byte(p.Rekor.Body))
		}, want: "decode rekor body"},
		{name: "entry hash mismatch", edit: func(p *Proof) {
			p.EntryHash = strings.Repeat("0", sha256.Size*2)
		}, want: "entry_hash"},
		{name: "malformed body JSON", edit: func(p *Proof) {
			p.Rekor.Body = base64.StdEncoding.EncodeToString([]byte(`{"kind":`))
			p.EntryHash = sha256Hex([]byte(p.Rekor.Body))
		}, want: "parse rekor body"},
		{name: "unsupported body kind", edit: func(p *Proof) {
			body := decodeSubmittedRekorBody(t, *p)
			body.Kind = "intoto"
			data, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			p.Rekor.Body = base64.StdEncoding.EncodeToString(data)
			p.EntryHash = sha256Hex([]byte(p.Rekor.Body))
		}, want: "unsupported rekor body"},
		{name: "public key mismatch", edit: func(p *Proof) {
			p.Rekor.PublicKey = base64.StdEncoding.EncodeToString([]byte("different"))
		}, want: "public key does not match"},
		{name: "empty inclusion root", edit: func(p *Proof) {
			p.LogRootHash = ""
			p.Rekor.InclusionProof.RootHash = ""
		}, want: "log_root_hash"},
		{name: "index outside tree", edit: func(p *Proof) {
			p.LogIndex = 1
			p.Rekor.InclusionProof.LogIndex = 1
		}, want: "outside tree_size"},
		{name: "invalid inclusion root hex", edit: func(p *Proof) {
			p.LogRootHash = strings.Repeat("z", sha256.Size*2)
			p.Rekor.InclusionProof.RootHash = p.LogRootHash
		}, want: "decode rekor inclusion root_hash"},
		{name: "invalid inclusion path hex", edit: func(p *Proof) {
			p.Rekor.InclusionProof.Hashes = []string{"zz"}
		}, want: "decode rekor inclusion proof hash"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proof
			candidate.Rekor = cloneRekorProof(proof.Rekor)
			tc.edit(&candidate)
			err := validateRekorSubmissionRecord(candidate, checkpoint)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateRekorSubmissionRecord error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRekorVerifyRejectsCryptographicallyValidWrongInclusionRoot(t *testing.T) {
	checkpoint, logSigner := securityRekorCheckpoint(t)
	logPublic := logSigner.Public().(ed25519.PublicKey)
	proof := selfConsistentRekorProof(t, checkpoint, logSigner, logSigner)

	wrongRoot := sha256.Sum256([]byte("wrong transparency log root"))
	proof.LogRootHash = hex.EncodeToString(wrongRoot[:])
	proof.Rekor.InclusionProof.RootHash = proof.LogRootHash
	proof.Rekor.InclusionProof.Checkpoint = signedCheckpointForTest(t, 1, wrongRoot[:], logSigner)

	err := (RekorLog{TrustedLogKeys: []crypto.PublicKey{logPublic}}).Verify(proof, checkpoint)
	if err == nil || !strings.Contains(err.Error(), "computed root does not match proof root") {
		t.Fatalf("Verify error = %v, want inclusion integrity failure", err)
	}
}

func TestRekorMalformedTrustMaterialAndProofPrimitives(t *testing.T) {
	t.Run("public key files and PEM", func(t *testing.T) {
		if _, err := LoadRekorPublicKey(t.TempDir()); err == nil || !strings.Contains(err.Error(), "read rekor log public key") {
			t.Fatalf("LoadRekorPublicKey(directory) error = %v", err)
		}
		tooLong := filepath.Join(t.TempDir(), strings.Repeat("x", 5000)+".pub")
		if _, err := LoadRekorPublicKey(tooLong); err == nil || !strings.Contains(err.Error(), "read rekor log public key") {
			t.Fatalf("LoadRekorPublicKey(long path) error = %v", err)
		}
		for name, encoded := range map[string]string{
			"empty":      " ",
			"bad public": "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----",
			"bad cert":   "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----",
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := ParseRekorPublicKey(encoded); err == nil {
					t.Fatal("ParseRekorPublicKey error = nil")
				}
			})
		}
	})

	t.Run("signature and checkpoint primitives", func(t *testing.T) {
		if err := verifyRekorSignature([]byte("artifact"), rekorSHA512Algorithm, "", ""); err == nil {
			t.Fatal("verifyRekorSignature accepted missing key and signature")
		}
		proof := Proof{Rekor: &RekorProof{InclusionProof: &RekorInclusionProof{
			Checkpoint: "malformed",
			RootHash:   "zz",
		}}}
		if err := verifyRekorCheckpoint(proof, nil); err == nil || !strings.Contains(err.Error(), "malformed signed note") {
			t.Fatalf("verifyRekorCheckpoint malformed note error = %v", err)
		}
		_, signer := securityRekorCheckpoint(t)
		root := sha256.Sum256([]byte("root"))
		proof.Rekor.InclusionProof.Checkpoint = signedCheckpointForTest(t, 1, root[:], signer)
		if err := verifyRekorCheckpoint(proof, nil); err == nil || !strings.Contains(err.Error(), "decode rekor inclusion root_hash") {
			t.Fatalf("verifyRekorCheckpoint malformed root error = %v", err)
		}
		sig := base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 1, 's'})
		if _, err := parseRekorNoteSignatures([]byte("—  " + sig + "\n")); err == nil || !strings.Contains(err.Error(), "line malformed") {
			t.Fatalf("parseRekorNoteSignatures error = %v", err)
		}
	})

	t.Run("merkle boundaries", func(t *testing.T) {
		leaf := rfc6962LeafHash([]byte("leaf"))
		for name, tc := range map[string]struct {
			index  uint64
			size   uint64
			hashes [][]byte
			root   []byte
			want   string
		}{
			"zero size":       {size: 0, root: leaf, want: "tree size is zero"},
			"outside tree":    {index: 1, size: 1, root: leaf, want: "outside tree size"},
			"too many":        {size: 1, hashes: [][]byte{leaf}, root: leaf, want: "too many proof hashes"},
			"proof too short": {size: 2, root: leaf, want: "proof too short"},
			"wrong root":      {size: 1, root: make([]byte, sha256.Size), want: "computed root"},
		} {
			t.Run(name, func(t *testing.T) {
				err := verifyRFC6962Inclusion(tc.index, tc.size, leaf, tc.hashes, tc.root)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("verifyRFC6962Inclusion error = %v, want %q", err, tc.want)
				}
			})
		}
	})

	t.Run("URL and response decoding", func(t *testing.T) {
		for _, raw := range []string{"rekor.example.invalid", "https:"} {
			if _, err := normalizeRekorBaseURL(raw); err == nil {
				t.Fatalf("normalizeRekorBaseURL(%q) error = nil", raw)
			}
			if _, err := rekorEntriesURL(raw); err == nil {
				t.Fatalf("rekorEntriesURL(%q) error = nil", raw)
			}
		}
		if _, _, err := decodeRekorEntry([]byte(`[]`)); err == nil {
			t.Fatal("decodeRekorEntry(array) error = nil")
		}
		entry, uuid, err := decodeRekorEntry([]byte(`{}`))
		if err != nil || uuid != "" || entry.LogID != "" || entry.Body != "" {
			t.Fatalf("decodeRekorEntry(empty object) = %+v, %q, %v", entry, uuid, err)
		}
	})
}

func TestRekorRejectsInconsistentPrivateKey(t *testing.T) {
	_, _, err := signRekorArtifact([]byte("artifact"), rekorSHA512Algorithm, ed25519.PrivateKey("short"))
	if err == nil || !strings.Contains(err.Error(), "validate rekor signing key") {
		t.Fatalf("signRekorArtifact error = %v, want key consistency failure", err)
	}

	path := filepath.Join(t.TempDir(), "not-a-key")
	if err := os.WriteFile(path, []byte("bad"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadRekorPrivateKey(path); err == nil {
		t.Fatal("LoadRekorPrivateKey accepted malformed key")
	}
}
