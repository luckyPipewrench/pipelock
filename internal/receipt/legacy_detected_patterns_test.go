// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestUnmarshalLegacyDetectedPatternsCompatibility(t *testing.T) {
	t.Parallel()
	raw, keyHex := legacyDetectedPatternsFixture(t)

	parsed, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal legacy detected_patterns fixture: %v", err)
	}
	if parsed.ActionRecord.ChainSeq != 2 {
		t.Fatalf("legacy fixture chain_seq = %d, want 2", parsed.ActionRecord.ChainSeq)
	}
	if err := VerifyWithKey(parsed, keyHex); err != nil {
		t.Fatalf("VerifyWithKey legacy detected_patterns fixture: %v", err)
	}
}

func TestUnmarshalLegacyDetectedPatternsStillRejectsOtherUnknown(t *testing.T) {
	t.Parallel()
	raw, _ := legacyDetectedPatternsFixture(t)
	tampered := mutateLegacyActionRecord(t, raw, func(ar map[string]json.RawMessage) {
		ar["unrelated_unknown"] = json.RawMessage(`true`)
	})

	if _, err := Unmarshal(tampered); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("Unmarshal accepted unrelated unknown field: %v", err)
	}
}

func TestUnmarshalLegacyDetectedPatternsTamperFailsSignature(t *testing.T) {
	t.Parallel()
	raw, keyHex := legacyDetectedPatternsFixture(t)
	tampered := mutateLegacyActionRecord(t, raw, func(ar map[string]json.RawMessage) {
		ar["target"] = json.RawMessage(`"https://api.vendor.example/tampered"`)
	})

	parsed, err := Unmarshal(tampered)
	if err != nil {
		t.Fatalf("Unmarshal tampered legacy fixture: %v", err)
	}
	err = VerifyWithKey(parsed, keyHex)
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("VerifyWithKey tampered legacy fixture err = %v, want signature failure", err)
	}
}

func legacyDetectedPatternsFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	ar := ActionRecord{
		Version:       ActionRecordVersion,
		ActionID:      "legacy-detected-patterns-seq-2",
		ActionType:    ActionRead,
		Timestamp:     time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Target:        "https://api.vendor.example/resource",
		Verdict:       "block",
		Transport:     "fetch",
		Layer:         "dlp",
		Pattern:       "aws_access_key_id",
		ChainPrevHash: "0123456789abcdef",
		ChainSeq:      2,
	}
	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign legacy fixture: %v", err)
	}
	raw, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal legacy fixture: %v", err)
	}
	withLegacy := mutateLegacyActionRecord(t, raw, func(action map[string]json.RawMessage) {
		action["detected_patterns"] = json.RawMessage(`["aws_access_key_id"]`)
	})
	return withLegacy, hex.EncodeToString(pub)
}

func mutateLegacyActionRecord(
	t *testing.T,
	raw []byte,
	mutate func(map[string]json.RawMessage),
) []byte {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshal top: %v", err)
	}
	var action map[string]json.RawMessage
	if err := json.Unmarshal(top["action_record"], &action); err != nil {
		t.Fatalf("unmarshal action_record: %v", err)
	}
	mutate(action)
	actionRaw, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("marshal action_record: %v", err)
	}
	top["action_record"] = actionRaw
	out, err := json.Marshal(top)
	if err != nil {
		t.Fatalf("marshal top: %v", err)
	}
	return out
}
