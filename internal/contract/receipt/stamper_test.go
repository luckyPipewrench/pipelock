// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

var testProducerStamper = NewStamper("contract.receipt.test")

// v2Receipt is a receipt value as a producer builds it: every generated
// field holds the bundle-shaped head the detector matches.
func v2Receipt() EvidenceReceipt {
	return EvidenceReceipt{
		RecordType:       RecordTypeEvidenceV2,
		ReceiptVersion:   2,
		PayloadKind:      PayloadProxyDecision,
		Canonicalization: DefaultCanonicalizationProfile(),
		Crit:             CritForPayloadKind(PayloadProxyDecision),
		EventID:          receiptcontent.NewGeneratedID().String(),
		Timestamp:        time.Now().UTC(),
		Principal:        "operator",
		Actor:            "agent",
		Signature:        SignatureProof{SignerKeyID: v2WedgedHead, KeyPurpose: "receipt-signing", Algorithm: "ed25519", Signature: v2WedgedHead},
		ChainSeq:         7,
		ChainPrevHash:    v2WedgedHead,
		PolicyHash:       "sha256:" + strings.Repeat("0", 64),
		Payload:          json.RawMessage(`{"transport":"forward","action_type":"read","verdict":"allow","winning_source":"policy","target":"https://api.vendor.example/x"}`),
	}
}

// TestSerializedReceiptGainsNoProducerOrigin is the regression for serialized
// v2 bytes acquiring generated-field exclusion: any caller holding receipt
// bytes could record them under the producer schema, so a caller-chosen
// chain_prev_hash carrying a detected canary was accepted. Recording now
// takes a receipt value and the producer's own Stamper, so bytes that were
// serialized and read back cannot be recorded by anyone else.
func TestSerializedReceiptGainsNoProducerOrigin(t *testing.T) {
	rec := v2Recorder(t)
	raw, err := json.Marshal(v2Receipt())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["chain_prev_hash"] = v2Canary
	mutated, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	var rcpt EvidenceReceipt
	if err := json.Unmarshal(mutated, &rcpt); err != nil || rcpt.ChainPrevHash != v2Canary {
		t.Fatalf("mutation failed: %v", err)
	}
	if rec.ReceiptDetector()(t.Context(), v2Canary).Clean {
		t.Fatal("positive control: the detector must match the canary")
	}
	for name, s := range map[string]*Stamper{"nil": nil, "zero": {}} {
		if err := s.Record(context.Background(), rec, recorder.DefaultSessionBase, rcpt, true); !errors.Is(err, ErrNoStamper) {
			t.Fatalf("%s stamper recorded deserialized bytes: %v", name, err)
		}
	}
	// The producer's own receipt keeps its generated-field exclusion.
	for i := 0; i < 3; i++ {
		if err := testProducerStamper.Record(context.Background(), rec, recorder.DefaultSessionBase, v2Receipt(), i%2 == 0); err != nil {
			t.Fatalf("producer receipt with a generated wedged head refused: %v", err)
		}
	}
}

func TestStamperRefusesDuplicatesAndUnmarshalable(t *testing.T) {
	for name, producer := range map[string]string{"duplicate": "contract.receipt.test", "empty": ""} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s stamper did not panic", name)
				}
			}()
			NewStamper(producer)
		}()
	}
	bad := v2Receipt()
	bad.Payload = json.RawMessage(`{`)
	if err := testProducerStamper.Record(context.Background(), &plainRecorder{}, "s", bad, false); err == nil || !strings.Contains(err.Error(), "marshal evidence receipt") {
		t.Fatalf("unmarshalable receipt error = %v", err)
	}
}
