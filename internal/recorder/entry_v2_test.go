// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// Test-local constants — repeated string literals belong in a const block
// per the recorder package goconst convention.
const (
	v2EventKindWrite          = "write"
	v2EventKindCheckpoint     = "checkpoint"
	v2EventKindProxyDecision  = "proxy_decision"
	v2EventKindFieldJSON      = `"event_kind":"write"`
	v2SessionV1               = "v1-sess"
	v2SessionV2               = "v2-sess"
	v2SessionMixed            = "mixed-sess"
	v2SessionRoundtrip        = "rt-sess"
	v2TestType                = "request"
	v2TestTransport           = "fetch"
	v2UnsupportedVersionFence = "unsupported entry version"
)

// fixedV2Timestamp is a deterministic timestamp for hash-stability tests.
var fixedV2Timestamp = time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

// TestComputeHash_V1FrozenProjection asserts that v1 hashes are byte-for-byte
// stable across the schema bump. Computing the hash for a v1-shaped entry
// must match the historical projection (no EventKind in the digest input).
// This is the regression guard that protects pre-upgrade audit chains.
func TestComputeHash_V1FrozenProjection(t *testing.T) {
	v1 := recorder.Entry{
		Version:   1,
		Sequence:  7,
		Timestamp: fixedV2Timestamp,
		SessionID: v2SessionV1,
		TraceID:   "trace-7",
		Type:      v2TestType,
		// EventKind populated but MUST NOT affect v1 hash.
		EventKind: v2EventKindWrite,
		Transport: v2TestTransport,
		Summary:   "regression-guard",
		Detail:    map[string]string{"k": "v"},
		PrevHash:  recorder.GenesisHash,
	}

	gotV1 := recorder.ComputeHash(v1)

	// A logically identical v1 entry without EventKind must produce the
	// same hash — proves EventKind is not in the v1 projection.
	v1NoKind := v1
	v1NoKind.EventKind = ""
	if gotV1 != recorder.ComputeHash(v1NoKind) {
		t.Fatalf("v1 hash changed with EventKind: with=%s without=%s", gotV1, recorder.ComputeHash(v1NoKind))
	}

	// And the v1 hash must NOT equal the v2 hash for the same logical
	// content. This isolates the chains: a v1 entry can never be replayed
	// or accepted as v2 because the version field differs in the digest.
	v2 := v1
	v2.Version = 2
	if gotV1 == recorder.ComputeHash(v2) {
		t.Fatal("v1 and v2 produced identical hash for same logical entry — version isolation broken")
	}
}

// TestComputeHash_V2IncludesEventKind asserts EventKind binds to the v2
// hash. Two v2 entries identical except for EventKind must produce
// different hashes; an empty EventKind must still produce a hash that
// differs from the equivalent v1 entry (because the version field differs).
func TestComputeHash_V2IncludesEventKind(t *testing.T) {
	base := recorder.Entry{
		Version:   2,
		Sequence:  3,
		Timestamp: fixedV2Timestamp,
		SessionID: v2SessionV2,
		Type:      v2TestType,
		Transport: v2TestTransport,
		Summary:   "v2-base",
		PrevHash:  recorder.GenesisHash,
	}
	emptyHash := recorder.ComputeHash(base)

	withKind := base
	withKind.EventKind = v2EventKindWrite
	withKindHash := recorder.ComputeHash(withKind)

	if emptyHash == withKindHash {
		t.Fatalf("v2 hash unchanged when EventKind set: empty=%s with=%s", emptyHash, withKindHash)
	}

	// Cross-version isolation: same logical entry as v1 (EventKind ignored
	// in projection) must still produce a different hash than v2 with
	// empty EventKind, purely because the version field "1" vs "2" enters
	// the digest.
	v1Equivalent := base
	v1Equivalent.Version = 1
	if recorder.ComputeHash(v1Equivalent) == emptyHash {
		t.Fatal("v1 with empty EventKind produced same hash as v2 with empty EventKind")
	}
}

// TestComputeHash_UnknownVersionReturnsEmpty asserts the version dispatch
// returns "" for unknown versions. VerifyChain then surfaces a clear error
// at the version fence rather than treating "" as a valid hash.
func TestComputeHash_UnknownVersionReturnsEmpty(t *testing.T) {
	e := recorder.Entry{
		Version:   99,
		Sequence:  0,
		Timestamp: fixedV2Timestamp,
		SessionID: v2SessionV2,
		Type:      v2TestType,
		Transport: v2TestTransport,
		PrevHash:  recorder.GenesisHash,
	}
	if got := recorder.ComputeHash(e); got != "" {
		t.Errorf("ComputeHash(version=99) = %q, want empty", got)
	}
	// Also v0 (the zero value) — common error mode for callers who forgot
	// to set Version. Must NOT silently produce a v1 hash.
	e.Version = 0
	if got := recorder.ComputeHash(e); got != "" {
		t.Errorf("ComputeHash(version=0) = %q, want empty", got)
	}
}

// buildMixedV1V2Chain builds [v1, v2] linked by PrevHash. Each entry uses
// the projection matching its Version. Returns the chain ready for
// VerifyChain.
func buildMixedV1V2Chain(t *testing.T) []recorder.Entry {
	t.Helper()
	ts := fixedV2Timestamp
	v1 := recorder.Entry{
		Version:   1,
		Sequence:  0,
		Timestamp: ts,
		SessionID: v2SessionMixed,
		Type:      v2TestType,
		Transport: v2TestTransport,
		Summary:   "v1-entry",
		PrevHash:  recorder.GenesisHash,
	}
	v1.Hash = recorder.ComputeHash(v1)

	v2 := recorder.Entry{
		Version:   2,
		Sequence:  1,
		Timestamp: ts.Add(time.Second),
		SessionID: v2SessionMixed,
		Type:      v2TestType,
		EventKind: v2EventKindWrite,
		Transport: v2TestTransport,
		Summary:   "v2-entry",
		PrevHash:  v1.Hash,
	}
	v2.Hash = recorder.ComputeHash(v2)

	return []recorder.Entry{v1, v2}
}

// TestVerifyChain_MixedV1V2 asserts a chain with a v1 entry followed by a
// v2 entry verifies cleanly. This is the upgrade scenario: existing chain
// pre-upgrade, new entries appended after the schema bump.
func TestVerifyChain_MixedV1V2(t *testing.T) {
	entries := buildMixedV1V2Chain(t)
	if err := recorder.VerifyChain(entries); err != nil {
		t.Fatalf("mixed v1/v2 chain failed verification: %v", err)
	}
}

// TestVerifyChain_RejectsV0AndV3 asserts the version fence rejects
// versions outside the accepted range {1, 2}. v0 is the zero-value
// programming error; v3 is a future schema not yet supported.
func TestVerifyChain_RejectsV0AndV3(t *testing.T) {
	cases := []struct {
		name    string
		version int
	}{
		{"version_zero", 0},
		{"version_three", 3},
		{"version_high", 99},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := recorder.Entry{
				Version:   tc.version,
				Sequence:  0,
				Timestamp: fixedV2Timestamp,
				SessionID: v2SessionV2,
				Type:      v2TestType,
				Transport: v2TestTransport,
				PrevHash:  recorder.GenesisHash,
			}
			// Don't set Hash — VerifyChain rejects on version before hash
			// check, but if a future change reorders the checks, the
			// missing hash should still surface a failure.
			err := recorder.VerifyChain([]recorder.Entry{e})
			if err == nil {
				t.Fatalf("expected error for version=%d, got nil", tc.version)
			}
		})
	}
}

// TestReadEntries_AcceptsV1AndV2 asserts a JSONL file containing both v1
// and v2 entries parses without error. Each entry is written with its
// version-appropriate hash projection.
func TestReadEntries_AcceptsV1AndV2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.jsonl")

	entries := buildMixedV1V2Chain(t)

	f, err := os.Create(filepath.Clean(path))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	enc := json.NewEncoder(f)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	_ = f.Close()

	got, err := recorder.ReadEntries(path)
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].Version != 1 {
		t.Errorf("entry[0].Version = %d, want 1", got[0].Version)
	}
	if got[1].Version != 2 {
		t.Errorf("entry[1].Version = %d, want 2", got[1].Version)
	}
	if got[1].EventKind != v2EventKindWrite {
		t.Errorf("entry[1].EventKind = %q, want %q", got[1].EventKind, v2EventKindWrite)
	}
	// And the chain still verifies after round-trip through JSON.
	if err := recorder.VerifyChain(got); err != nil {
		t.Fatalf("round-tripped chain verification: %v", err)
	}
}

// TestReadEntries_RejectsUnknownVersionInRange asserts the error message
// names the accepted range (1, 2) so operators see an actionable hint.
func TestReadEntries_RejectsUnknownVersionInRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "future.jsonl")

	e := recorder.Entry{
		Version: 7, Sequence: 0, SessionID: v2SessionV2,
		Timestamp: fixedV2Timestamp, Type: v2TestType, Transport: v2TestTransport,
		Summary: "future schema", PrevHash: recorder.GenesisHash,
	}
	data, _ := json.Marshal(e)
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := recorder.ReadEntries(path)
	if err == nil {
		t.Fatal("expected error for version 7")
	}
	if !strings.Contains(err.Error(), v2UnsupportedVersionFence) {
		t.Errorf("error = %q, want substring %q", err.Error(), v2UnsupportedVersionFence)
	}
	if !strings.Contains(err.Error(), "accepted: 1, 2") {
		t.Errorf("error = %q, want accepted-range hint", err.Error())
	}
}

// TestEntryJSON_OmitemptyEventKind asserts the JSON tag omits EventKind
// when empty (so v1 readers who never knew about the field don't see a
// `"event_kind":""` token they'd have to handle) and includes it when
// populated.
func TestEntryJSON_OmitemptyEventKind(t *testing.T) {
	t.Run("empty omits field", func(t *testing.T) {
		e := recorder.Entry{
			Version:   2,
			SessionID: v2SessionRoundtrip,
			Type:      v2TestType,
			Transport: v2TestTransport,
			PrevHash:  recorder.GenesisHash,
		}
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if strings.Contains(string(data), "event_kind") {
			t.Errorf("empty EventKind should be omitted, got: %s", string(data))
		}
	})

	t.Run("populated emits field", func(t *testing.T) {
		e := recorder.Entry{
			Version:   2,
			SessionID: v2SessionRoundtrip,
			Type:      v2TestType,
			EventKind: v2EventKindWrite,
			Transport: v2TestTransport,
			PrevHash:  recorder.GenesisHash,
		}
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !strings.Contains(string(data), v2EventKindFieldJSON) {
			t.Errorf("populated EventKind should marshal, got: %s", string(data))
		}
	})

	t.Run("round trip preserves field", func(t *testing.T) {
		original := recorder.Entry{
			Version:   2,
			Sequence:  5,
			Timestamp: fixedV2Timestamp,
			SessionID: v2SessionRoundtrip,
			Type:      v2TestType,
			EventKind: v2EventKindWrite,
			Transport: v2TestTransport,
			Summary:   "rt",
			PrevHash:  recorder.GenesisHash,
		}
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var decoded recorder.Entry
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if decoded.EventKind != v2EventKindWrite {
			t.Errorf("round-trip EventKind = %q, want %q", decoded.EventKind, v2EventKindWrite)
		}
	})
}

// TestRecorder_CheckpointStampsEventKind asserts checkpoint entries written
// by the recorder carry EventKind="checkpoint" and Version=2. The checkpoint
// is read back from disk and verified through VerifyChain.
func TestRecorder_CheckpointStampsEventKind(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_ = pub

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1, // checkpoint after every entry
		SignCheckpoints:    true,
	}, nil, priv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := rec.Record(recorder.Entry{
		SessionID: "cp-event-kind",
		Type:      v2TestType,
		Transport: v2TestTransport,
		Summary:   "trigger checkpoint",
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-cp-event-kind-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}

	var foundCheckpoint bool
	for _, e := range entries {
		if e.Type != v2EventKindCheckpoint {
			continue
		}
		foundCheckpoint = true
		if e.Version != recorder.EntryVersion {
			t.Errorf("checkpoint Version = %d, want %d", e.Version, recorder.EntryVersion)
		}
		if e.EventKind != v2EventKindCheckpoint {
			t.Errorf("checkpoint EventKind = %q, want %q", e.EventKind, v2EventKindCheckpoint)
		}
	}
	if !foundCheckpoint {
		t.Fatal("no checkpoint entry found")
	}
	if err := recorder.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

// TestRecorder_RecordDecisionStampsEventKind asserts decision entries
// written via RecordDecision carry EventKind="proxy_decision". This is the
// fixed classifier for signed verdict proofs.
func TestRecorder_RecordDecisionStampsEventKind(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 100,
	}, nil, priv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	dr := recorder.DecisionRecord{
		SessionID: "decision-ek",
		Verdict:   "block",
		ScannerResult: recorder.ScannerEvidence{
			Layer:   "dlp",
			Pattern: "test_pattern",
		},
		RequestContext: recorder.RequestEvidence{
			Transport: v2TestTransport,
			Direction: "outbound",
		},
	}

	if err := rec.RecordDecision(dr); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-decision-ek-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}

	var foundDecision bool
	for _, e := range entries {
		if e.Type != "decision" {
			continue
		}
		foundDecision = true
		if e.Version != recorder.EntryVersion {
			t.Errorf("decision Version = %d, want %d", e.Version, recorder.EntryVersion)
		}
		if e.EventKind != v2EventKindProxyDecision {
			t.Errorf("decision EventKind = %q, want %q", e.EventKind, v2EventKindProxyDecision)
		}
	}
	if !foundDecision {
		t.Fatal("no decision entry found")
	}
	if err := recorder.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

// TestRecorder_AcceptsEmptyEventKindFromCaller asserts the recorder accepts
// entries from external callers (e.g. capture, proxy) that haven't yet been
// updated to populate EventKind. Empty EventKind must round-trip without
// error and the entry must verify.
func TestRecorder_AcceptsEmptyEventKindFromCaller(t *testing.T) {
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 100,
	}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := rec.Record(recorder.Entry{
		SessionID: "empty-ek",
		Type:      v2TestType,
		Transport: v2TestTransport,
		Summary:   "no event_kind set",
		// EventKind intentionally empty
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-empty-ek-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}

	var foundData bool
	for _, e := range entries {
		if e.Type != v2TestType {
			continue
		}
		foundData = true
		if e.Version != recorder.EntryVersion {
			t.Errorf("Version = %d, want %d", e.Version, recorder.EntryVersion)
		}
		if e.EventKind != "" {
			t.Errorf("EventKind = %q, want empty", e.EventKind)
		}
	}
	if !foundData {
		t.Fatal("data entry not found")
	}
	if err := recorder.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

// TestVerifyChain_HashMismatchAcrossVersions asserts a chain forged by
// taking a v1 entry's hash and stamping it onto a v2 entry fails. This
// proves the version-bound projection prevents replay/forgery across
// versions.
func TestVerifyChain_HashMismatchAcrossVersions(t *testing.T) {
	v1 := recorder.Entry{
		Version:   1,
		Sequence:  0,
		Timestamp: fixedV2Timestamp,
		SessionID: v2SessionV1,
		Type:      v2TestType,
		Transport: v2TestTransport,
		Summary:   "v1",
		PrevHash:  recorder.GenesisHash,
	}
	v1.Hash = recorder.ComputeHash(v1)

	// Take the v1 entry, change Version to 2 but keep the v1 hash.
	// VerifyChain must fail because v2 projection produces a different
	// hash than the stored v1 hash.
	forged := v1
	forged.Version = 2
	// forged.Hash still set to v1's hash.

	err := recorder.VerifyChain([]recorder.Entry{forged})
	if err == nil {
		t.Fatal("expected hash mismatch on cross-version forgery")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("error = %q, want hash-mismatch", err.Error())
	}
}

// TestComputeHash_MarshalErrorFallback exercises both v1 and v2
// projections with a Detail value that json.Marshal can't encode (a
// channel). Both projections must fall back to "null" rather than panic
// or produce an empty hash. This covers the marshal-error branch in
// both computeHashV1 and computeHashV2.
func TestComputeHash_MarshalErrorFallback(t *testing.T) {
	for _, ver := range []int{1, 2} {
		ver := ver
		t.Run("version_"+string(rune('0'+ver)), func(t *testing.T) {
			e := recorder.Entry{
				Version:   ver,
				Sequence:  1,
				Timestamp: fixedV2Timestamp,
				SessionID: v2SessionV2,
				Type:      v2TestType,
				Transport: v2TestTransport,
				PrevHash:  recorder.GenesisHash,
				Detail:    make(chan int), // json.Marshal returns error
			}
			got := recorder.ComputeHash(e)
			if got == "" {
				t.Fatalf("v%d ComputeHash returned empty for unmarshalable Detail", ver)
			}
			// The fallback is deterministic — two calls must produce the
			// same hash.
			if recorder.ComputeHash(e) != got {
				t.Errorf("v%d marshal-error fallback not deterministic", ver)
			}
		})
	}
}

// TestVerifyChain_SignedV2Checkpoint asserts the v2 checkpoint signature
// flow — the recorder writes v2 checkpoints with EventKind="checkpoint",
// and a chain that includes them verifies under both VerifyChain and
// VerifyCheckpoints.
func TestVerifyChain_SignedV2Checkpoint(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 2,
		SignCheckpoints:    true,
	}, nil, priv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := rec.Record(recorder.Entry{
			SessionID: "v2-cp",
			Type:      v2TestType,
			Transport: v2TestTransport,
			Summary:   "data",
		}); err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-v2-cp-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}

	if err := recorder.VerifyChain(entries, pub); err != nil {
		t.Fatalf("VerifyChain with signed v2 checkpoints: %v", err)
	}
	if err := recorder.VerifyCheckpoints(entries, pub); err != nil {
		t.Fatalf("VerifyCheckpoints: %v", err)
	}

	// Spot-check: at least one checkpoint exists and has a non-empty
	// hex signature.
	var sawCheckpoint bool
	for _, e := range entries {
		if e.Type != v2EventKindCheckpoint {
			continue
		}
		sawCheckpoint = true
		detailJSON, _ := json.Marshal(e.Detail)
		var cp recorder.CheckpointDetail
		_ = json.Unmarshal(detailJSON, &cp)
		if cp.Signature == "" {
			t.Error("expected non-empty checkpoint signature")
		}
		if _, err := hex.DecodeString(cp.Signature); err != nil {
			t.Errorf("checkpoint signature is not valid hex: %v", err)
		}
	}
	if !sawCheckpoint {
		t.Fatal("expected at least one checkpoint in chain")
	}
}
