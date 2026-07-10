// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// signTestReceipt builds a minimal valid signed receipt for strict-verify tests.
func signTestReceipt(t *testing.T) (Receipt, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ar := ActionRecord{
		Version:         ActionRecordVersion,
		ActionID:        "action-strict-0",
		ActionType:      ActionRead,
		Timestamp:       time.Unix(1700000000, 0).UTC(),
		Target:          "https://api.example.com/v1/data",
		SideEffectClass: SideEffectExternalRead,
		Reversibility:   ReversibilityFull,
		Verdict:         "allow",
		Transport:       "https",
		ChainPrevHash:   GenesisHash,
	}
	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return r, priv
}

// TestUnmarshal_RejectsUnknownTopLevelField proves EV2-FU-1: an unrecognized
// top-level field on a signed v1 receipt is rejected, not accept-and-ignored.
func TestUnmarshal_RejectsUnknownTopLevelField(t *testing.T) {
	t.Parallel()
	r, _ := signTestReceipt(t)
	data, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Splice an unknown top-level field into the object.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	m["sidecar"] = json.RawMessage(`{"vendor":"acme"}`)
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if _, err := Unmarshal(tampered); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("Unmarshal did not reject an unknown top-level field with ErrUnknownField: %v", err)
	}
}

// TestUnmarshal_ToleratesExtBagAndIgnoresIt proves EV2-FU-1's escape hatch: the
// single top-level ext bag is accepted, verifies under the same key, and does
// NOT affect the verdict (identical content to the rejected top-level field).
func TestUnmarshal_ToleratesExtBagAndIgnoresIt(t *testing.T) {
	t.Parallel()
	r, _ := signTestReceipt(t)
	data, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	m["ext"] = json.RawMessage(`{"vendor":"acme","note":"forward-compat"}`)
	withExt, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	parsed, err := Unmarshal(withExt)
	if err != nil {
		t.Fatalf("Unmarshal rejected a tolerated ext bag: %v", err)
	}
	if err := VerifyWithKey(parsed, r.SignerKey); err != nil {
		t.Fatalf("VerifyWithKey failed with ext present: %v", err)
	}
	// The verdict comes from the signed action record, never from ext.
	if parsed.ActionRecord.Verdict != r.ActionRecord.Verdict {
		t.Fatalf("ext altered the verdict: got %q want %q", parsed.ActionRecord.Verdict, r.ActionRecord.Verdict)
	}
}

// TestUnmarshal_RejectsUnknownFieldInActionRecord proves the strict contract
// recurses into nested signed objects: ext is top-level only.
func TestUnmarshal_RejectsUnknownFieldInActionRecord(t *testing.T) {
	t.Parallel()
	r, _ := signTestReceipt(t)
	data, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("unmarshal top: %v", err)
	}
	var ar map[string]json.RawMessage
	if err := json.Unmarshal(top["action_record"], &ar); err != nil {
		t.Fatalf("unmarshal action_record: %v", err)
	}
	ar["smuggled"] = json.RawMessage(`"x"`)
	arBytes, _ := json.Marshal(ar)
	top["action_record"] = arBytes
	tampered, _ := json.Marshal(top)
	if _, err := Unmarshal(tampered); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("Unmarshal did not reject an unknown field inside action_record: %v", err)
	}
}

// TestUnmarshal_RejectsTrailingTokens proves that valid receipt JSON followed
// by anything else fails closed with ErrTrailingTokens, covering both the
// trailing-valid-JSON branch and the trailing-garbage branch. Accepting
// trailing tokens would let a producer smuggle a second document past a
// verifier that only reads the first.
func TestUnmarshal_RejectsTrailingTokens(t *testing.T) {
	t.Parallel()
	r, _ := signTestReceipt(t)
	data, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Sanity: the untampered receipt unmarshals cleanly.
	if _, err := Unmarshal(data); err != nil {
		t.Fatalf("Unmarshal rejected a clean receipt: %v", err)
	}

	withTrailer := func(trailer string) []byte {
		out := make([]byte, 0, len(data)+len(trailer))
		out = append(out, data...)
		out = append(out, trailer...)
		return out
	}
	cases := map[string]string{
		"trailing_json_object": `{"vendor":"acme"}`,
		"trailing_json_number": " 42",
		"trailing_garbage":     "garbage",
	}
	for name, trailer := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Unmarshal(withTrailer(trailer)); !errors.Is(err, ErrTrailingTokens) {
				t.Fatalf("Unmarshal did not reject trailing tokens with ErrTrailingTokens: %v", err)
			}
		})
	}
}

// TestExtractReceiptsBytes_RejectsUnexpectedRecorderType proves AF-37: a
// recorder file mixing a valid receipt with an entry whose type is outside the
// taxonomy fails closed rather than certifying a "valid receipt subsequence".
func TestExtractReceiptsBytes_RejectsUnexpectedRecorderType(t *testing.T) {
	t.Parallel()
	r, _ := signTestReceipt(t)
	detail, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal receipt: %v", err)
	}
	receiptEntry := recorder.Entry{
		Version: recorder.EntryVersion, Sequence: 0, Timestamp: time.Now().UTC(),
		SessionID: "s", Type: recorderEntryType, Transport: "https", Summary: "r",
		Detail: json.RawMessage(detail), PrevHash: recorder.GenesisHash,
	}
	receiptEntry.Hash = recorder.ComputeHash(receiptEntry)
	badEntry := recorder.Entry{
		Version: recorder.EntryVersion, Sequence: 1, Timestamp: time.Now().UTC(),
		SessionID: "s", Type: "surprise", Transport: "https", Summary: "x",
		PrevHash: receiptEntry.Hash,
	}
	badEntry.Hash = recorder.ComputeHash(badEntry)

	line0, _ := json.Marshal(receiptEntry)
	line1, _ := json.Marshal(badEntry)
	data := append(append(line0, '\n'), append(line1, '\n')...)

	if _, err := ExtractReceiptsBytes(data); !errors.Is(err, ErrUnexpectedRecorderEntryType) {
		t.Fatalf("ExtractReceiptsBytes did not reject unexpected type: err=%v", err)
	}

	// A known operational entry (decision) is skipped, not rejected.
	okEntry := recorder.Entry{
		Version: recorder.EntryVersion, Sequence: 1, Timestamp: time.Now().UTC(),
		SessionID: "s", Type: "decision", Transport: "https", Summary: "d",
		PrevHash: receiptEntry.Hash,
	}
	okEntry.Hash = recorder.ComputeHash(okEntry)
	line1ok, _ := json.Marshal(okEntry)
	okData := append(append(line0, '\n'), append(line1ok, '\n')...)
	got, err := ExtractReceiptsBytes(okData)
	if err != nil {
		t.Fatalf("ExtractReceiptsBytes rejected a known operational entry: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("receipt count = %d, want 1", len(got))
	}
}

// TestExtractReceiptsFromSessionDir_RejectsUnexpectedRecorderType covers the
// directory verifier path: it must inspect the full session stream before
// filtering receipts, or an unknown recorder entry can ride beside a valid
// receipt subsequence.
func TestExtractReceiptsFromSessionDir_RejectsUnexpectedRecorderType(t *testing.T) {
	t.Parallel()
	r, _ := signTestReceipt(t)
	detail, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal receipt: %v", err)
	}
	receiptEntry := recorder.Entry{
		Version: recorder.EntryVersion, Sequence: 0, Timestamp: time.Now().UTC(),
		SessionID: "s", Type: recorderEntryType, Transport: "https", Summary: "r",
		Detail: json.RawMessage(detail), PrevHash: recorder.GenesisHash,
	}
	receiptEntry.Hash = recorder.ComputeHash(receiptEntry)
	badEntry := recorder.Entry{
		Version: recorder.EntryVersion, Sequence: 1, Timestamp: time.Now().UTC(),
		SessionID: "s", Type: "surprise", Transport: "https", Summary: "x",
		PrevHash: receiptEntry.Hash,
	}
	badEntry.Hash = recorder.ComputeHash(badEntry)

	dir := t.TempDir()
	path := dir + "/evidence-s-0.jsonl"
	line0, _ := json.Marshal(receiptEntry)
	line1, _ := json.Marshal(badEntry)
	data := append(append(line0, '\n'), append(line1, '\n')...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := ExtractReceiptsFromSessionDir(dir, "s"); !errors.Is(err, ErrUnexpectedRecorderEntryType) {
		t.Fatalf("ExtractReceiptsFromSessionDir did not reject unexpected type: err=%v", err)
	}
}

// TestExtractAndVerifyWholeRecorderBytes proves AF-37 whole-recorder mode:
// verifies the recorder hash chain over every entry, extracts the receipt
// subsequence, and rejects an entry whose type is outside the taxonomy.
func TestExtractAndVerifyWholeRecorderBytes(t *testing.T) {
	t.Parallel()
	r, _ := signTestReceipt(t)
	detail, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal receipt: %v", err)
	}
	receiptEntry := recorder.Entry{
		Version: recorder.EntryVersion, Sequence: 0, Timestamp: time.Now().UTC(),
		SessionID: "s", Type: recorderEntryType, Transport: "https", Summary: "r",
		Detail: json.RawMessage(detail), PrevHash: recorder.GenesisHash,
	}
	receiptEntry.Hash = recorder.ComputeHash(receiptEntry)
	line0, _ := json.Marshal(receiptEntry)

	got, err := ExtractAndVerifyWholeRecorderBytes(append(line0, '\n'))
	if err != nil {
		t.Fatalf("whole-recorder verify failed on a clean file: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("receipt count = %d, want 1", len(got))
	}

	// A broken recorder hash chain must fail whole-recorder mode.
	broken := receiptEntry
	broken.Hash = "deadbeef"
	brokenLine, _ := json.Marshal(broken)
	if _, err := ExtractAndVerifyWholeRecorderBytes(append(brokenLine, '\n')); err == nil {
		t.Fatalf("whole-recorder verify accepted a tampered hash chain")
	}

	// An unknown record type must fail whole-recorder mode too.
	bad := recorder.Entry{
		Version: recorder.EntryVersion, Sequence: 1, Timestamp: time.Now().UTC(),
		SessionID: "s", Type: "surprise", Transport: "https", Summary: "x",
		PrevHash: receiptEntry.Hash,
	}
	bad.Hash = recorder.ComputeHash(bad)
	badLine, _ := json.Marshal(bad)
	data := append(append(line0, '\n'), append(badLine, '\n')...)
	if _, err := ExtractAndVerifyWholeRecorderBytes(data); !errors.Is(err, ErrUnexpectedRecorderEntryType) {
		t.Fatalf("whole-recorder verify did not reject unexpected type: err=%v", err)
	}
}
