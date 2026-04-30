// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type testSigner struct {
	priv ed25519.PrivateKey
}

func newTestSigner() testSigner {
	seed := sha256.Sum256([]byte("shadow delta receipt signer"))
	return testSigner{priv: ed25519.NewKeyFromSeed(seed[:])}
}

func (s testSigner) KeyID() string { return "shadow-test-key" }

func (s testSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

func TestAggregate_GroupsWindowsAndSamples(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	deltas := []Delta{
		delta(base.Add(3*time.Second), "rule-b", "block", "allow", "b1"),
		delta(base.Add(2*time.Second), "rule-a", "allow", "block", "a2"),
		delta(base.Add(time.Second), "rule-a", "allow", "block", "a1"),
		delta(base.Add(70*time.Second), "rule-a", "allow", "block", "a4"),
		delta(base.Add(4*time.Second), "rule-a", "allow", "block", "a3"),
	}

	got, err := Aggregate(deltas, AggregateConfig{WindowDuration: time.Minute, SampleCount: 2})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("batches = %d, want 3: %#v", len(got), got)
	}
	first := got[0]
	if first.RuleID != "rule-a" || first.LosslessCount != 3 {
		t.Fatalf("first batch = %+v, want rule-a count 3", first)
	}
	if want := []string{"a1", "a2"}; !reflect.DeepEqual(first.ExemplarIDs, want) {
		t.Fatalf("first samples = %v, want %v", first.ExemplarIDs, want)
	}
	if !first.WindowStart.Equal(base) || !first.WindowEnd.Equal(base.Add(time.Minute)) {
		t.Fatalf("first window = %s..%s", first.WindowStart, first.WindowEnd)
	}
}

func TestAggregate_SortsTieBreakersAndSamples(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	deltas := []Delta{
		{ContractHash: "sha256:b", RuleID: "rule-b", OriginalVerdict: "warn", CandidateVerdict: "block", ExemplarID: "b", ObservedAt: base},
		{ContractHash: "sha256:a", RuleID: "rule-b", OriginalVerdict: "warn", CandidateVerdict: "block", ExemplarID: "b", ObservedAt: base},
		{ContractHash: "sha256:a", RuleID: "rule-a", OriginalVerdict: "warn", CandidateVerdict: "block", ExemplarID: "a", ObservedAt: base},
		{ContractHash: "sha256:a", RuleID: "rule-a", OriginalVerdict: "allow", CandidateVerdict: "warn", ExemplarID: "c", ObservedAt: base},
		{ContractHash: "sha256:a", RuleID: "rule-a", OriginalVerdict: "allow", CandidateVerdict: "block", ExemplarID: "d", ObservedAt: base},
	}
	got, err := Aggregate(deltas, AggregateConfig{WindowDuration: time.Minute, SampleCount: 1})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	wantOrder := []string{
		"sha256:a/rule-a/allow/block",
		"sha256:a/rule-a/allow/warn",
		"sha256:a/rule-a/warn/block",
		"sha256:a/rule-b/warn/block",
		"sha256:b/rule-b/warn/block",
	}
	for i, want := range wantOrder {
		gotKey := got[i].ContractHash + "/" + got[i].RuleID + "/" + got[i].OriginalVerdict + "/" + got[i].CandidateVerdict
		if gotKey != want {
			t.Fatalf("batch[%d] = %q, want %q", i, gotKey, want)
		}
	}
	for _, batch := range got {
		if len(batch.ExemplarIDs) != 1 {
			t.Fatalf("batch samples = %d, want the one available exemplar", len(batch.ExemplarIDs))
		}
	}
}

func TestAggregate_RejectsInvalidConfigAndDelta(t *testing.T) {
	t.Parallel()
	for _, cfg := range []AggregateConfig{
		{WindowDuration: -time.Second, SampleCount: 1},
		{WindowDuration: 0, SampleCount: 1},
		{WindowDuration: time.Minute, SampleCount: -1},
		{WindowDuration: time.Minute, SampleCount: 0},
	} {
		if _, err := Aggregate(nil, cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("Aggregate invalid config %#v error = %v, want ErrInvalidConfig", cfg, err)
		}
	}

	defaults := DefaultAggregateConfig()
	if defaults.WindowDuration != defaultWindowDuration || defaults.SampleCount != defaultSampleCount {
		t.Fatalf("DefaultAggregateConfig = %+v, want %s/%d", defaults, defaultWindowDuration, defaultSampleCount)
	}

	for _, tc := range []Delta{
		{RuleID: "r", OriginalVerdict: "allow", CandidateVerdict: "block", ObservedAt: time.Now()},
		{ContractHash: "sha256:c", OriginalVerdict: "allow", CandidateVerdict: "block", ObservedAt: time.Now()},
		{ContractHash: "sha256:c", RuleID: "r", CandidateVerdict: "block", ObservedAt: time.Now()},
		{ContractHash: "sha256:c", RuleID: "r", OriginalVerdict: "allow", ObservedAt: time.Now()},
		{ContractHash: "sha256:c", RuleID: "r", OriginalVerdict: "allow", CandidateVerdict: "block"},
	} {
		_, err := Aggregate([]Delta{tc}, defaults)
		if !errors.Is(err, ErrInvalidDelta) {
			t.Fatalf("Aggregate invalid delta %#v error = %v, want ErrInvalidDelta", tc, err)
		}
	}
}

func TestAggregate_OneHundredKEventsCollapsesToOneBatch(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	deltas := make([]Delta, 100_000)
	for i := range deltas {
		deltas[i] = delta(base.Add(time.Duration(i%60)*time.Second), "rule-a", "allow", "block", "sample")
	}

	got, err := Aggregate(deltas, DefaultAggregateConfig())
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("batches = %d, want 1", len(got))
	}
	if got[0].LosslessCount != 100_000 {
		t.Fatalf("LosslessCount = %d, want 100000", got[0].LosslessCount)
	}
	if len(got[0].ExemplarIDs) != defaultSampleCount {
		t.Fatalf("sample count = %d, want %d", len(got[0].ExemplarIDs), defaultSampleCount)
	}
}

func TestEmitter_RecordsSignedShadowDeltaReceiptsInRecorderChain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, nil)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	signer := newTestSigner()
	base := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	clockTicks := 0
	emitter := NewEmitter(EmitterConfig{
		Recorder:           rec,
		Signer:             signer,
		Principal:          "runtime",
		Actor:              "shadow",
		ActiveManifestHash: "sha256:manifest",
		SelectorID:         "selector-a",
		ContractGeneration: 7,
		Clock: func() time.Time {
			clockTicks++
			return base.Add(time.Duration(clockTicks) * time.Second)
		},
		EventID: func() (string, error) {
			return "01900000-0000-7000-8000-000000000001", nil
		},
	})

	first := Batch{
		ContractHash:     "sha256:contract",
		RuleID:           "rule-a",
		OriginalVerdict:  "allow",
		CandidateVerdict: "block",
		WindowStart:      base,
		WindowEnd:        base.Add(time.Minute),
		LosslessCount:    1<<53 + 1,
		ExemplarIDs:      []string{"ex-1", "ex-2"},
	}
	second := first
	second.RuleID = "rule-b"
	second.ExemplarIDs = []string{"ex-3"}

	if err := emitter.EmitBatch(first); err != nil {
		t.Fatalf("EmitBatch first: %v", err)
	}
	if err := emitter.EmitBatch(second); err != nil {
		t.Fatalf("EmitBatch second: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rawEntries := readRawEntries(t, dir)
	if err := recorder.VerifyChain(rawEntries); err != nil {
		t.Fatalf("recorder.VerifyChain: %v", err)
	}

	receiptEntries := make([]recorder.Entry, 0, 2)
	for _, entry := range rawEntries {
		if entry.Type == evidenceReceiptEntryType {
			receiptEntries = append(receiptEntries, entry)
		}
	}
	if len(receiptEntries) != 2 {
		t.Fatalf("receipt entries = %d, want 2", len(receiptEntries))
	}

	receipts := make([]contractreceipt.EvidenceReceipt, 0, len(receiptEntries))
	for _, entry := range receiptEntries {
		if entry.EventKind != string(contractreceipt.PayloadShadowDelta) {
			t.Fatalf("EventKind = %q, want shadow_delta", entry.EventKind)
		}
		detail, ok := entry.Detail.(json.RawMessage)
		if !ok {
			t.Fatalf("entry detail type = %T, want json.RawMessage", entry.Detail)
		}
		var rcpt contractreceipt.EvidenceReceipt
		if err := json.Unmarshal(detail, &rcpt); err != nil {
			t.Fatalf("unmarshal receipt: %v", err)
		}
		if err := contractreceipt.VerifyWithKey(rcpt, signer.priv.Public().(ed25519.PublicKey), signer.KeyID()); err != nil {
			t.Fatalf("VerifyWithKey: %v", err)
		}
		receipts = append(receipts, rcpt)
	}
	if receipts[0].ChainSeq != 0 || receipts[0].ChainPrevHash != recorder.GenesisHash {
		t.Fatalf("first chain fields = seq %d prev %q", receipts[0].ChainSeq, receipts[0].ChainPrevHash)
	}
	firstHash, err := contractreceipt.ReceiptHash(receipts[0])
	if err != nil {
		t.Fatalf("ReceiptHash first: %v", err)
	}
	if receipts[1].ChainSeq != 1 || receipts[1].ChainPrevHash != firstHash {
		t.Fatalf("second chain fields = seq %d prev %q, want prev %q", receipts[1].ChainSeq, receipts[1].ChainPrevHash, firstHash)
	}

	var payload contractreceipt.PayloadShadowDeltaStruct
	if err := json.Unmarshal(receipts[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.Aggregation.LosslessCount != 1<<53+1 || payload.Aggregation.DeltaSampleCount != 2 {
		t.Fatalf("aggregation = %+v, want exact large lossless count and sample 2", payload.Aggregation)
	}
}

func TestEmitter_NoOpAndDefaults(t *testing.T) {
	t.Parallel()
	if NewEmitter(EmitterConfig{Signer: newTestSigner()}) != nil {
		t.Fatal("NewEmitter without recorder should return nil")
	}
	if NewEmitter(EmitterConfig{Recorder: &memoryRecorder{}}) != nil {
		t.Fatal("NewEmitter without signer should return nil")
	}
	var nilEmitter *Emitter
	if err := nilEmitter.EmitBatch(Batch{}); err != nil {
		t.Fatalf("nil EmitBatch error = %v, want nil", err)
	}

	rec := &memoryRecorder{}
	emitter := NewEmitter(EmitterConfig{
		Recorder: rec,
		Signer:   newTestSigner(),
		Clock: func() time.Time {
			return time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
		},
	})
	if emitter.sessionID != recorderSessionID {
		t.Fatalf("default sessionID = %q, want %q", emitter.sessionID, recorderSessionID)
	}
	if id, err := newEventID(); err != nil || id == "" {
		t.Fatalf("newEventID = %q, want generated UUID", id)
	}
}

func TestEmitter_RejectsInvalidBatches(t *testing.T) {
	t.Parallel()
	emitter := NewEmitter(EmitterConfig{Recorder: &memoryRecorder{}, Signer: newTestSigner()})
	base := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	valid := Batch{
		ContractHash:     "sha256:contract",
		RuleID:           "rule-a",
		OriginalVerdict:  "allow",
		CandidateVerdict: "block",
		WindowStart:      base,
		WindowEnd:        base.Add(time.Minute),
		LosslessCount:    1,
		ExemplarIDs:      []string{"ex-1"},
	}
	cases := []Batch{
		{RuleID: "rule-a", OriginalVerdict: "allow", CandidateVerdict: "block", WindowStart: base, WindowEnd: base.Add(time.Minute), LosslessCount: 1},
		withBatch(valid, func(b *Batch) { b.WindowEnd = base }),
		withBatch(valid, func(b *Batch) { b.LosslessCount = 0 }),
		withBatch(valid, func(b *Batch) { b.LosslessCount = 1; b.ExemplarIDs = []string{"ex-1", "ex-2"} }),
		withBatch(valid, func(b *Batch) { b.ExemplarIDs = []string{""} }),
	}
	for _, batch := range cases {
		if err := emitter.EmitBatch(batch); !errors.Is(err, ErrInvalidDelta) {
			t.Fatalf("EmitBatch(%+v) error = %v, want ErrInvalidDelta", batch, err)
		}
	}
}

func TestEmitter_SurfacesSignerValidateAndRecordErrors(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	batch := Batch{
		ContractHash:     "sha256:contract",
		RuleID:           "rule-a",
		OriginalVerdict:  "allow",
		CandidateVerdict: "block",
		WindowStart:      base,
		WindowEnd:        base.Add(time.Minute),
		LosslessCount:    1,
		ExemplarIDs:      []string{"ex-1"},
	}

	errSigner := errSigner{err: errors.New("sign failed")}
	emitter := NewEmitter(EmitterConfig{Recorder: &memoryRecorder{}, Signer: errSigner})
	if err := emitter.EmitBatch(batch); err == nil || !strings.Contains(err.Error(), "sign failed") {
		t.Fatalf("EmitBatch signer error = %v, want sign failed", err)
	}

	shortSigner := shortSigner{}
	emitter = NewEmitter(EmitterConfig{Recorder: &memoryRecorder{}, Signer: shortSigner})
	if err := emitter.EmitBatch(batch); err == nil || !strings.Contains(err.Error(), "signature size") {
		t.Fatalf("EmitBatch short signature error = %v, want signature size", err)
	}

	emitter = NewEmitter(EmitterConfig{
		Recorder: &memoryRecorder{},
		Signer:   newTestSigner(),
		EventID: func() (string, error) {
			return "", nil
		},
	})
	if err := emitter.EmitBatch(batch); err == nil || !strings.Contains(err.Error(), "event_id") {
		t.Fatalf("EmitBatch validate error = %v, want event_id", err)
	}

	eventIDErr := errors.New("event id failed")
	emitter = NewEmitter(EmitterConfig{
		Recorder: &memoryRecorder{},
		Signer:   newTestSigner(),
		EventID: func() (string, error) {
			return "", eventIDErr
		},
	})
	if err := emitter.EmitBatch(batch); !errors.Is(err, eventIDErr) {
		t.Fatalf("EmitBatch event id error = %v, want eventIDErr", err)
	}

	recordErr := errors.New("record failed")
	emitter = NewEmitter(EmitterConfig{Recorder: &memoryRecorder{err: recordErr}, Signer: newTestSigner()})
	if err := emitter.EmitBatch(batch); !errors.Is(err, recordErr) {
		t.Fatalf("EmitBatch record error = %v, want recordErr", err)
	}
	if emitter.chainSeq != 0 || emitter.chainPrevHash != recorder.GenesisHash {
		t.Fatalf("chain state advanced after record failure: seq=%d prev=%q", emitter.chainSeq, emitter.chainPrevHash)
	}
}

func TestEmitter_ErrorSeams(t *testing.T) {
	base := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	batch := Batch{
		ContractHash:     "sha256:contract",
		RuleID:           "rule-a",
		OriginalVerdict:  "allow",
		CandidateVerdict: "block",
		WindowStart:      base,
		WindowEnd:        base.Add(time.Minute),
		LosslessCount:    1,
		ExemplarIDs:      []string{"ex-1"},
	}
	resetSeams := func() {
		jsonMarshal = json.Marshal
		receiptHash = contractreceipt.ReceiptHash
		newUUIDV7 = uuid.NewV7
	}
	t.Cleanup(resetSeams)

	boom := errors.New("boom")
	jsonMarshal = func(any) ([]byte, error) { return nil, boom }
	emitter := NewEmitter(EmitterConfig{Recorder: &memoryRecorder{}, Signer: newTestSigner()})
	if err := emitter.EmitBatch(batch); !errors.Is(err, boom) {
		t.Fatalf("payload marshal seam error = %v, want boom", err)
	}
	resetSeams()

	receiptHash = func(contractreceipt.EvidenceReceipt) (string, error) { return "", boom }
	emitter = NewEmitter(EmitterConfig{Recorder: &memoryRecorder{}, Signer: newTestSigner()})
	if err := emitter.EmitBatch(batch); !errors.Is(err, boom) {
		t.Fatalf("receipt hash seam error = %v, want boom", err)
	}
	resetSeams()

	marshalCalls := 0
	jsonMarshal = func(v any) ([]byte, error) {
		marshalCalls++
		if marshalCalls == 2 {
			return nil, boom
		}
		return json.Marshal(v)
	}
	emitter = NewEmitter(EmitterConfig{Recorder: &memoryRecorder{}, Signer: newTestSigner()})
	if err := emitter.EmitBatch(batch); !errors.Is(err, boom) {
		t.Fatalf("receipt marshal seam error = %v, want boom", err)
	}
	resetSeams()

	newUUIDV7 = func() (uuid.UUID, error) { return uuid.Nil, boom }
	if id, err := newEventID(); !errors.Is(err, boom) || id != "" {
		t.Fatalf("newEventID error = id %q err %v, want boom", id, err)
	}
}

type memoryRecorder struct {
	entries []recorder.Entry
	err     error
}

func (r *memoryRecorder) Record(entry recorder.Entry) error {
	if r.err != nil {
		return r.err
	}
	r.entries = append(r.entries, entry)
	return nil
}

type errSigner struct {
	err error
}

func (s errSigner) KeyID() string { return "err-signer" }

func (s errSigner) Sign([]byte) ([]byte, error) { return nil, s.err }

type shortSigner struct{}

func (s shortSigner) KeyID() string { return "short-signer" }

func (s shortSigner) Sign([]byte) ([]byte, error) { return []byte("short"), nil }

func withBatch(batch Batch, mutate func(*Batch)) Batch {
	mutate(&batch)
	return batch
}

func delta(at time.Time, ruleID, original, candidate, exemplar string) Delta {
	return Delta{
		ContractHash:     "sha256:contract",
		RuleID:           ruleID,
		OriginalVerdict:  original,
		CandidateVerdict: candidate,
		ExemplarID:       exemplar,
		ObservedAt:       at,
	}
}

type rawRecorderEntry struct {
	Version   int             `json:"v"`
	Sequence  uint64          `json:"seq"`
	Timestamp time.Time       `json:"ts"`
	SessionID string          `json:"session_id"`
	TraceID   string          `json:"trace_id,omitempty"`
	Type      string          `json:"type"`
	EventKind string          `json:"event_kind,omitempty"`
	Transport string          `json:"transport"`
	Summary   string          `json:"summary"`
	Detail    json.RawMessage `json:"detail"`
	RawRef    string          `json:"raw_ref,omitempty"`
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
}

func readRawEntries(t *testing.T, dir string) []recorder.Entry {
	t.Helper()
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var files []string
	for _, entry := range dirEntries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "evidence-"+recorderSessionID+"-") && strings.HasSuffix(name, ".jsonl") {
			files = append(files, filepath.Join(dir, name))
		}
	}
	sort.Strings(files)

	var out []recorder.Entry
	for _, file := range files {
		body, err := os.ReadFile(file) //nolint:gosec // test reads recorder output from t.TempDir.
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
			if line == "" {
				continue
			}
			var raw rawRecorderEntry
			if err := json.Unmarshal([]byte(line), &raw); err != nil {
				t.Fatalf("unmarshal raw entry: %v", err)
			}
			out = append(out, recorder.Entry{
				Version:   raw.Version,
				Sequence:  raw.Sequence,
				Timestamp: raw.Timestamp,
				SessionID: raw.SessionID,
				TraceID:   raw.TraceID,
				Type:      raw.Type,
				EventKind: raw.EventKind,
				Transport: raw.Transport,
				Summary:   raw.Summary,
				Detail:    raw.Detail,
				RawRef:    raw.RawRef,
				PrevHash:  raw.PrevHash,
				Hash:      raw.Hash,
			})
		}
	}
	return out
}
