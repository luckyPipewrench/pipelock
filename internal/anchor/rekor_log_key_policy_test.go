// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pemPublicKey(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestLoadRekorPublicKey_RefusesUnsupportedKeysAtLoad pins the reason the acceptance
// policy runs at LOAD and not only inside signature verification.
//
// `pipelock-verifier independent --rekor-log-key` and dashboard startup are being
// configured to render a trust verdict. If an unsupported key is accepted here, every
// later verification fails with a generic signature error, which reads to an operator
// like a tampered or forked log rather than a key type this verifier cannot use.
func TestLoadRekorPublicKey_RefusesUnsupportedKeysAtLoad(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p384 key: %v", err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p256 key: %v", err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	refused := []struct {
		name string
		pub  crypto.PublicKey
	}{
		{"rsa", &rsaKey.PublicKey},
		{"ecdsa P-384", &p384.PublicKey},
	}
	for _, tc := range refused {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadRekorPublicKey(pemPublicKey(t, tc.pub))
			if err == nil {
				t.Fatalf("%s log key was accepted at load, want refusal", tc.name)
			}
			if !errors.Is(err, ErrUnsupportedRekorLogKey) {
				t.Fatalf("error does not wrap ErrUnsupportedRekorLogKey, so a caller cannot "+
					"distinguish it from an unparseable key: %v", err)
			}
		})
	}

	accepted := []struct {
		name string
		pub  crypto.PublicKey
	}{
		{"ed25519", edPub},
		{"ecdsa P-256", &p256.PublicKey},
	}
	for _, tc := range accepted {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := LoadRekorPublicKey(pemPublicKey(t, tc.pub)); err != nil {
				t.Fatalf("%s log key rejected, want accepted: %v", tc.name, err)
			}
		})
	}

	t.Run("refuses from a file path too", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "log.pem")
		if err := os.WriteFile(path, []byte(pemPublicKey(t, &rsaKey.PublicKey)), 0o600); err != nil {
			t.Fatalf("write key file: %v", err)
		}
		_, err := LoadRekorPublicKey(path)
		if !errors.Is(err, ErrUnsupportedRekorLogKey) {
			t.Fatalf("file-path load must apply the same policy as inline PEM, got: %v", err)
		}
	})

	t.Run("one bad key fails the whole keyring", func(t *testing.T) {
		t.Parallel()
		// Silently dropping the unsupported entry would leave the verifier trusting
		// fewer keys than the operator configured: a trust-set change nobody asked for.
		_, err := LoadRekorPublicKeys([]string{
			pemPublicKey(t, edPub),
			pemPublicKey(t, &rsaKey.PublicKey),
		})
		if !errors.Is(err, ErrUnsupportedRekorLogKey) {
			t.Fatalf("a keyring containing an unsupported key must fail, got: %v", err)
		}
		if !strings.Contains(err.Error(), "rekor log public key 1") {
			t.Fatalf("keyring load error should identify the bad input index, got: %v", err)
		}
	})
}

// TestSupportedRekorLogPublicKey_ClosesPanicVectors covers keys that reach the policy
// from DIRECT construction rather than from the parser.
//
// A caller can build RekorLog{TrustedLogKeys: ...} with arbitrary crypto.PublicKey
// values, and two of them panic inside the standard library: ed25519.Verify panics on
// a wrong-length key, and ECDSA verification panics on a nil curve or nil coordinates.
// A panic on a verification path reached from remote transparency-log input is a
// denial of service, so every such key must come back as a typed error instead.
func TestSupportedRekorLogPublicKey_ClosesPanicVectors(t *testing.T) {
	t.Parallel()

	good, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p256 key: %v", err)
	}

	cases := []struct {
		name string
		key  crypto.PublicKey
	}{
		{"short ed25519 key", ed25519.PublicKey([]byte("too-short"))},
		{"empty ed25519 key", ed25519.PublicKey(nil)},
		{"nil ecdsa pointer", (*ecdsa.PublicKey)(nil)},
		{"ecdsa nil curve", &ecdsa.PublicKey{Curve: nil, X: good.X, Y: good.Y}},
		{"ecdsa nil coordinates", &ecdsa.PublicKey{Curve: elliptic.P256()}},
		{"not a key at all", "definitely-not-a-key"},
		{"nil key", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("policy panicked on %s, which is a DoS on a remotely reachable "+
						"verification path: %v", tc.name, r)
				}
			}()
			if _, err := supportedRekorLogPublicKey(tc.key); !errors.Is(err, ErrUnsupportedRekorLogKey) {
				t.Fatalf("want ErrUnsupportedRekorLogKey for %s, got: %v", tc.name, err)
			}
			// verifySignature must survive the same input, since it is the function the
			// checkpoint and SET paths actually call.
			if verifySignature(tc.key, []byte("message"), []byte("signature")) {
				t.Fatalf("verifySignature accepted %s", tc.name)
			}
		})
	}
}

// TestRekorLogVerify_UnsupportedTrustedKeyIsDistinguishable proves that a
// directly-constructed RekorLog fails closed with an error naming the KEY problem,
// rather than collapsing into the same generic "verification failed" that an actual
// signature mismatch produces. It uses a real submitted proof so the trust-set check
// is genuinely reached: a minimal hand-built Proof is rejected by submission-record
// validation first, which would make this test pass without exercising the policy.
func TestRekorLogVerify_UnsupportedTrustedKeyIsDistinguishable(t *testing.T) {
	t.Parallel()

	receipts, keyHex := testReceiptChain(t, 1)
	checkpoint, err := BuildCheckpoint("proxy", receipts, []string{keyHex})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	_, submitPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate submission key: %v", err)
	}
	proof, err := (RekorLog{URL: fakeRekorServer(t).URL, Signer: submitPriv}).Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	err = (RekorLog{TrustedLogKeys: []crypto.PublicKey{&rsaKey.PublicKey}}).Verify(proof, checkpoint)
	if err == nil {
		t.Fatal("Verify accepted a proof with an unsupported trusted log key")
	}
	if !errors.Is(err, ErrUnsupportedRekorLogKey) {
		t.Fatalf("Verify must name the unsupported key so an operator can tell it from a "+
			"tampered log, got: %v", err)
	}
	if !strings.Contains(err.Error(), "trusted rekor log key 0") {
		t.Errorf("error should identify WHICH pinned key is unsupported, got: %v", err)
	}
}
