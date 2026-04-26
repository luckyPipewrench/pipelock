// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type testKeyPair struct {
	PrivateKeyHex string `json:"private_key_hex"`
	PublicKeyHex  string `json:"public_key_hex"`
	Message       string `json:"message"`
	SignatureHex  string `json:"signature_hex"`
}

func loadTestKeys(t *testing.T) testKeyPair {
	t.Helper()
	path := filepath.Join("testdata", "golden", "ed25519_test_keys.json")
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read test keys: %v", err)
	}
	var k testKeyPair
	if err := json.Unmarshal(b, &k); err != nil {
		t.Fatalf("unmarshal test keys: %v", err)
	}
	return k
}

func TestVerify_PureEdDSA_RFC8032Vector(t *testing.T) {
	t.Parallel()
	keys := loadTestKeys(t)
	pub, err := hex.DecodeString(keys.PublicKeyHex)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	sig, err := hex.DecodeString(keys.SignatureHex)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !VerifyEd25519PureEdDSA(pub, []byte(keys.Message), sig) {
		t.Error("RFC 8032 §7.1 test 1 vector failed to verify")
	}
}

func TestVerify_RejectsWrongLengthInputs(t *testing.T) {
	t.Parallel()
	if VerifyEd25519PureEdDSA([]byte{1, 2, 3}, []byte("msg"), make([]byte, 64)) {
		t.Error("short pubkey should fail verify")
	}
	if VerifyEd25519PureEdDSA(make([]byte, 32), []byte("msg"), []byte{1, 2, 3}) {
		t.Error("short signature should fail verify")
	}
}

func TestVerify_KeyPurpose_AuthorityMatrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		payloadKind string
		signed      string
		ok          bool
	}{
		{"proxy_decision", "receipt-signing", true},
		{"proxy_decision", "contract-activation-signing", false},
		{"contract_promote_intent", "contract-activation-signing", true},
		{"contract_promote_intent", "receipt-signing", false},
		{"contract_promote_committed", "receipt-signing", true},
		{"contract_rollback_authorized", "contract-activation-signing", true},
		{"contract_rollback_committed", "receipt-signing", true},
		{"contract_demoted", "receipt-signing", true},
		{"contract_drift", "receipt-signing", true},
		{"shadow_delta", "receipt-signing", true},
		{"opportunity_missing", "receipt-signing", true},
		{"contract_ratified", "receipt-signing", true},
		{"contract_expired", "receipt-signing", true},
		{"key_rotation", "contract-activation-signing", true},
		{"contract_redaction_request", "contract-activation-signing", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.payloadKind+"_signed_with_"+tc.signed, func(t *testing.T) {
			t.Parallel()
			err := AuthorizeKeyPurpose(tc.payloadKind, tc.signed)
			switch {
			case tc.ok && err != nil:
				t.Errorf("got %v, want nil", err)
			case !tc.ok && err == nil:
				t.Errorf("got nil, want rejection")
			case !tc.ok && !errors.Is(err, ErrWrongKeyPurpose):
				t.Errorf("got %v, want ErrWrongKeyPurpose", err)
			}
		})
	}
}

func TestAuthorize_RejectsUnknownPayloadKind(t *testing.T) {
	t.Parallel()
	err := AuthorizeKeyPurpose("nonsense_payload", "receipt-signing")
	if err == nil {
		t.Error("expected error for unknown payload_kind")
	}
}
