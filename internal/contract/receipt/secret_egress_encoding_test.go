// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestSecretEgressRawReadersPreserveJCSFormatting(t *testing.T) {
	t.Parallel()
	raw, original := secretEgressWireFixture(t)
	pub := secretEgressWirePublicKey(t, original.Signature.SignerKeyID)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	reordered := editSecretEgressWire(t, raw, func(map[string]json.RawMessage) {})
	cases := []struct {
		name string
		raw  []byte
	}{
		{"producer", raw},
		{"whitespace", pretty.Bytes()},
		{"property order", reordered},
		{"escaped envelope property", bytes.Replace(raw, []byte(`"payload_kind"`), []byte(`"\u0070ayload_kind"`), 1)},
		{"escaped decision property", bytes.Replace(raw, []byte(`"destination_kind"`), []byte(`"destination_\u006bind"`), 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name != "producer" && bytes.Equal(tc.raw, raw) {
				t.Fatal("test requires a distinct encoding of the same facts")
			}
			parsed, err := receipt.ParseEvidenceReceipt(tc.raw)
			if err != nil {
				t.Fatalf("ordinary raw profile: %v", err)
			}
			if err := receipt.VerifyWithKey(parsed, pub, original.Signature.SignerKeyID); err != nil {
				t.Fatalf("JCS signature: %v", err)
			}
			stream, err := receipt.NewPinnedStreamingVerifier(pub)
			if err != nil {
				t.Fatal(err)
			}
			if err := stream.AddRaw(tc.raw); err != nil {
				t.Fatalf("stream raw profile: %v", err)
			}
			exactErr := receipt.VerifyV2BytesWithKey(tc.raw, pub, original.Signature.SignerKeyID)
			if (exactErr == nil) != (tc.name == "producer") {
				t.Fatalf("exact-emitted-byte acceptance changed: %v", exactErr)
			}

			// Exercise the real recorder's serialization, not only a hand-built
			// JSONL wrapper. Its RawDetail must remain valid for ordinary readers.
			dir := t.TempDir()
			rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = rec.Close() })
			session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
			if err != nil {
				t.Fatal(err)
			}
			if err := rec.RecordDurable(recorder.Entry{
				SessionID: session, Type: receipt.EvidenceEntryType, Transport: "forward",
				Summary: "encoding boundary fixture", Detail: json.RawMessage(tc.raw),
			}); err != nil {
				t.Fatal(err)
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			extracted, err := receipt.ExtractEvidenceReceiptsFromSessionDir(dir, session)
			if err != nil || len(extracted) != 1 {
				t.Fatalf("real recorder extraction: count=%d err=%v", len(extracted), err)
			}
			result := receipt.VerifyChain(extracted, receipt.ChainVerifyOptions{PinnedKey: pub})
			if !result.Valid || !result.SignaturesVerified {
				t.Fatalf("recorded JCS chain: %+v", result)
			}
		})
	}
}
