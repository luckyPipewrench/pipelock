// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	v2EntryVersion = 2
	v3EntryVersion = 3
)

func TestStreamTypesCaptureSummary(t *testing.T) {
	rec := testEntry(t, recorder.EntryVersion, 1, recorder.GenesisHash, capture.EntryTypeCapture, capture.CaptureSummary{
		CaptureSchemaVersion: capture.CaptureSchemaV1,
		Surface:              capture.SurfaceURL,
		Agent:                "agent-one",
		ActionClass:          "read",
		Request: capture.CaptureRequest{
			Method: "GET",
			URL:    "https://example.test/widgets/123",
		},
		Outcome:         capture.OutcomeBlocked,
		EffectiveAction: "block",
		PayloadBytes:    42,
		ScannerBytes:    17,
	})

	entries, errs := collectStream(t, mustJSONLines(t, rec), StreamOptions{})

	if len(errs) != 0 {
		t.Fatalf("errs = %v, want none", errs)
	}
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(entries))
	}
	if entries[0].Recorder.Hash != rec.Hash {
		t.Fatalf("recorder hash = %q, want %q", entries[0].Recorder.Hash, rec.Hash)
	}
	if entries[0].Capture == nil {
		t.Fatal("Capture is nil, want typed summary")
	}
	if entries[0].Capture.Surface != capture.SurfaceURL {
		t.Errorf("Capture.Surface = %q, want %q", entries[0].Capture.Surface, capture.SurfaceURL)
	}
	if entries[0].Capture.Request.Method != http.MethodGet {
		t.Errorf("Capture.Request.Method = %q, want GET", entries[0].Capture.Request.Method)
	}
	if entries[0].Capture.PayloadBytes != 42 {
		t.Errorf("Capture.PayloadBytes = %d, want 42", entries[0].Capture.PayloadBytes)
	}
}

func TestParseRecorderEntryRejectsExplicitNullV3ProjectedField(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want string
	}{
		{"null", `{"v":3,"seq":0,"ts":null,"session_id":"s","chain_kind":"recorder","writer_instance_id":"writer-a","type":"checkpoint","transport":"x","summary":"","detail":{},"prev_hash":"genesis","hash":"h"}`, "ts must be a string"},
		{"missing", `{"v":3,"seq":0,"session_id":"s","chain_kind":"recorder","writer_instance_id":"writer-a","type":"checkpoint","transport":"x","summary":"","detail":{},"prev_hash":"genesis","hash":"h"}`, "ts required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseRecorderEntry([]byte(tc.line)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseRecorderEntry() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestStreamExplicitNullDetailHashesAsNull(t *testing.T) {
	rec := recorder.Entry{
		Version:   recorder.EntryVersion,
		Sequence:  1,
		Timestamp: time.Date(2026, 4, 29, 12, 0, 1, 0, time.UTC),
		SessionID: "session-1",
		Type:      "checkpoint",
		EventKind: "test",
		Transport: "test",
		Summary:   "null detail",
		Detail:    json.RawMessage("null"),
		PrevHash:  recorder.GenesisHash,
	}
	rec.Hash = recorder.ComputeHash(rec)

	entries, errs := collectStream(t, mustJSONLines(t, rec), StreamOptions{})

	if len(errs) != 0 {
		t.Fatalf("errs = %v, want none", errs)
	}
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(entries))
	}
	if got := recorder.ComputeHash(entries[0].Recorder); got != rec.Hash {
		t.Fatalf("computed hash = %q, want %q", got, rec.Hash)
	}
}

func TestTypedEntryFallbackDetailShapes(t *testing.T) {
	rec := testEntry(t, recorder.EntryVersion, 1, recorder.GenesisHash, capture.EntryTypeCapture, capture.CaptureSummary{
		CaptureSchemaVersion: capture.CaptureSchemaV1,
		Surface:              capture.SurfaceURL,
	})
	rec.Detail = capture.CaptureSummary{
		CaptureSchemaVersion: capture.CaptureSchemaV1,
		Surface:              capture.SurfaceURL,
	}
	entry, err := typedEntry(rec)
	if err != nil {
		t.Fatalf("typedEntry struct detail: %v", err)
	}
	if entry.Capture == nil || entry.Capture.Surface != capture.SurfaceURL {
		t.Fatalf("typedEntry struct detail capture = %+v", entry.Capture)
	}

	rec.Detail = make(chan int)
	if _, err := typedEntry(rec); err == nil {
		t.Fatal("typedEntry channel detail expected error")
	}
}

func TestStreamMalformedLineContinuesAndCountsDrops(t *testing.T) {
	first := testEntry(t, recorder.EntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"ok": true})
	second := testEntry(t, recorder.EntryVersion, 2, first.Hash, "checkpoint", map[string]any{"ok": "after malformed"})
	input := mustJSONLines(t, first) + "{not-json}\n" + mustJSONLines(t, second)

	entries, errs := collectStream(t, input, StreamOptions{})

	if len(entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(entries))
	}
	if entries[0].Recorder.Hash != first.Hash || entries[1].Recorder.Hash != second.Hash {
		t.Fatalf("stream did not preserve valid entries around malformed line")
	}
	if len(errs) != 1 {
		t.Fatalf("errs len = %d, want 1: %v", len(errs), errs)
	}
	if !errors.Is(errs[0], ErrMalformedEntry) {
		t.Fatalf("error %v does not wrap ErrMalformedEntry", errs[0])
	}
	if got := errs[0].Error(); !strings.Contains(got, "line=2") || !strings.Contains(got, "dropped=1") {
		t.Fatalf("malformed error = %q, want line and drop count", got)
	}
}

func TestStreamUnsupportedCaptureSchemaIsNonFatalAndAdvancesChain(t *testing.T) {
	badCapture := testEntry(t, recorder.EntryVersion, 1, recorder.GenesisHash, capture.EntryTypeCapture, capture.CaptureSummary{
		CaptureSchemaVersion: capture.CaptureSchemaV1 + 1,
		Surface:              capture.SurfaceURL,
	})
	next := testEntry(t, recorder.EntryVersion, 2, badCapture.Hash, "checkpoint", map[string]any{"after": "bad capture"})

	entries, errs := collectStream(t, mustJSONLines(t, badCapture, next), StreamOptions{})

	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(entries))
	}
	if entries[0].Recorder.Hash != next.Hash {
		t.Fatalf("entry hash = %q, want next hash %q", entries[0].Recorder.Hash, next.Hash)
	}
	if len(errs) != 1 {
		t.Fatalf("errs len = %d, want 1: %v", len(errs), errs)
	}
	if !errors.Is(errs[0], ErrMalformedEntry) {
		t.Fatalf("error %v does not wrap ErrMalformedEntry", errs[0])
	}
	if errors.Is(errs[0], ErrHashChainBroken) {
		t.Fatalf("unsupported capture schema error wraps ErrHashChainBroken: %v", errs[0])
	}
}

func TestStreamDetectsHashChainBreaks(t *testing.T) {
	t.Run("first entry must point at genesis", func(t *testing.T) {
		rec := testEntry(t, recorder.EntryVersion, 1, "not-genesis", "checkpoint", map[string]any{"ok": true})

		entries, errs := collectStream(t, mustJSONLines(t, rec), StreamOptions{})

		if len(entries) != 0 {
			t.Fatalf("entries len = %d, want 0", len(entries))
		}
		requireOneErrorIs(t, errs, ErrHashChainBroken)
	})

	t.Run("later entry must point at previous valid hash", func(t *testing.T) {
		first := testEntry(t, recorder.EntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"ok": true})
		second := testEntry(t, recorder.EntryVersion, 2, "wrong-prev", "checkpoint", map[string]any{"ok": false})

		entries, errs := collectStream(t, mustJSONLines(t, first, second), StreamOptions{})

		if len(entries) != 1 {
			t.Fatalf("entries len = %d, want 1", len(entries))
		}
		requireOneErrorIs(t, errs, ErrHashChainBroken)
	})

	t.Run("stored hash must match canonical hash", func(t *testing.T) {
		rec := testEntry(t, recorder.EntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"ok": true})
		rec.Hash = "tampered"

		entries, errs := collectStream(t, mustJSONLines(t, rec), StreamOptions{})

		if len(entries) != 0 {
			t.Fatalf("entries len = %d, want 0", len(entries))
		}
		requireOneErrorIs(t, errs, ErrHashChainBroken)
	})
}

func TestStreamSchemaVersionGating(t *testing.T) {
	t.Run("zero options allow mixed legacy recorder versions", func(t *testing.T) {
		v1 := testEntry(t, 1, 1, recorder.GenesisHash, "checkpoint", map[string]any{"version": 1})
		v2 := testEntry(t, 2, 2, v1.Hash, "checkpoint", map[string]any{"version": 2})

		entries, errs := collectStream(t, mustJSONLines(t, v1, v2), StreamOptions{})

		if len(errs) != 0 {
			t.Fatalf("errs = %v, want none", errs)
		}
		if len(entries) != 2 {
			t.Fatalf("entries len = %d, want 2", len(entries))
		}
	})

	t.Run("zero options allow a namespaced v3 stream", func(t *testing.T) {
		v3 := testEntry(t, recorder.LatestEntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"version": 3})
		entries, errs := collectStream(t, mustJSONLines(t, v3), StreamOptions{})
		if len(errs) != 0 || len(entries) != 1 {
			t.Fatalf("entries = %d, errs = %v, want one v3 entry", len(entries), errs)
		}
	})

	t.Run("v3 requires complete chain namespace", func(t *testing.T) {
		rec := testEntry(t, recorder.LatestEntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"version": 3})
		rec.WriterInstanceID = ""
		rec.Hash = recorder.ComputeHash(rec)

		entries, errs := collectStream(t, mustJSONLines(t, rec), StreamOptions{})

		if len(entries) != 0 {
			t.Fatalf("entries len = %d, want 0", len(entries))
		}
		requireOneErrorIs(t, errs, ErrUnsupportedSchemaVersion)
	})

	t.Run("v3 requires chain kind", func(t *testing.T) {
		rec := testEntry(t, v3EntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"version": 3})
		rec.ChainKind = ""
		rec.Hash = recorder.ComputeHash(rec)

		entries, errs := collectStream(t, mustJSONLines(t, rec), StreamOptions{})

		if len(entries) != 0 {
			t.Fatalf("entries len = %d, want 0", len(entries))
		}
		requireOneErrorIs(t, errs, ErrUnsupportedSchemaVersion)
	})

	t.Run("legacy entries reject unhashed chain namespace", func(t *testing.T) {
		rec := testEntry(t, recorder.CurrentWriteEntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"version": 2})
		rec.ChainKind = recorder.ChainKindRecorder
		rec.Hash = recorder.ComputeHash(rec)
		entries, errs := collectStream(t, mustJSONLines(t, rec), StreamOptions{})
		if len(entries) != 0 {
			t.Fatalf("entries len = %d, want 0", len(entries))
		}
		requireOneErrorIs(t, errs, ErrUnsupportedSchemaVersion)
	})

	t.Run("legacy entries reject unhashed writer namespace", func(t *testing.T) {
		rec := testEntry(t, v2EntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"version": 2})
		rec.WriterInstanceID = "writer-a"
		rec.Hash = recorder.ComputeHash(rec)
		entries, errs := collectStream(t, mustJSONLines(t, rec), StreamOptions{})
		if len(entries) != 0 {
			t.Fatalf("entries len = %d, want 0", len(entries))
		}
		requireOneErrorIs(t, errs, ErrUnsupportedSchemaVersion)
	})

	t.Run("v3 namespace cannot change within a stream", func(t *testing.T) {
		first := testEntry(t, recorder.LatestEntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"version": 3})
		second := testEntry(t, recorder.LatestEntryVersion, 2, first.Hash, "checkpoint", map[string]any{"version": 3})
		second.WriterInstanceID = "writer-other"
		second.Hash = recorder.ComputeHash(second)

		entries, errs := collectStream(t, mustJSONLines(t, first, second), StreamOptions{})
		if len(entries) != 1 {
			t.Fatalf("entries len = %d, want 1", len(entries))
		}
		requireOneErrorIs(t, errs, ErrHashChainBroken)
	})

	t.Run("v3 chain kind cannot change within a stream", func(t *testing.T) {
		first := testEntry(t, recorder.LatestEntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"version": 3})
		second := testEntry(t, recorder.LatestEntryVersion, 2, first.Hash, "checkpoint", map[string]any{"version": 3})
		second.ChainKind = "receipt"
		second.Hash = recorder.ComputeHash(second)
		entries, errs := collectStream(t, mustJSONLines(t, first, second), StreamOptions{})
		if len(entries) != 1 {
			t.Fatalf("entries len = %d, want 1", len(entries))
		}
		requireOneErrorIs(t, errs, ErrHashChainBroken)
	})

	t.Run("v3 session cannot change within a stream", func(t *testing.T) {
		first := testEntry(t, v3EntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"version": 3})
		second := testEntry(t, v3EntryVersion, 2, first.Hash, "checkpoint", map[string]any{"version": 3})
		second.SessionID = "session-other"
		second.Hash = recorder.ComputeHash(second)
		entries, errs := collectStream(t, mustJSONLines(t, first, second), StreamOptions{})
		if len(entries) != 1 {
			t.Fatalf("entries len = %d, want 1", len(entries))
		}
		requireOneErrorIs(t, errs, ErrHashChainBroken)
	})

	t.Run("legacy stream cannot transition to v3", func(t *testing.T) {
		legacy := testEntry(t, recorder.CurrentWriteEntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"version": 2})
		v3 := testEntry(t, recorder.LatestEntryVersion, 2, legacy.Hash, "checkpoint", map[string]any{"version": 3})
		entries, errs := collectStream(t, mustJSONLines(t, legacy, v3), StreamOptions{})
		if len(entries) != 1 {
			t.Fatalf("entries len = %d, want 1", len(entries))
		}
		requireOneErrorIs(t, errs, ErrHashChainBroken)
	})

	t.Run("explicit allow list rejects omitted recorder versions", func(t *testing.T) {
		v1 := testEntry(t, 1, 1, recorder.GenesisHash, "checkpoint", map[string]any{"version": 1})

		entries, errs := collectStream(t, mustJSONLines(t, v1), StreamOptions{
			AllowSchemaVersion: []int{recorder.EntryVersion},
		})

		if len(entries) != 0 {
			t.Fatalf("entries len = %d, want 0", len(entries))
		}
		requireOneErrorIs(t, errs, ErrUnsupportedSchemaVersion)
	})

	t.Run("unknown versions stay unsupported even when allowed", func(t *testing.T) {
		rec := testEntry(t, recorder.EntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"ok": true})
		rec.Version = recorder.EntryVersion + 100
		rec.Hash = ""

		entries, errs := collectStream(t, mustJSONLines(t, rec), StreamOptions{
			AllowSchemaVersion: []int{rec.Version},
		})

		if len(entries) != 0 {
			t.Fatalf("entries len = %d, want 0", len(entries))
		}
		requireOneErrorIs(t, errs, ErrUnsupportedSchemaVersion)
	})
}

func TestStreamEscrowPrivateKeyIsNoOp(t *testing.T) {
	rec := testEntry(t, recorder.EntryVersion, 1, recorder.GenesisHash, "checkpoint", map[string]any{"ok": true})

	entries, errs := collectStream(t, mustJSONLines(t, rec), StreamOptions{
		EscrowPrivateKey: []byte("test-only-key-material"),
	})

	if len(errs) != 0 {
		t.Fatalf("errs = %v, want none", errs)
	}
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(entries))
	}
	if entries[0].Recorder.Hash != rec.Hash {
		t.Fatalf("entry hash = %q, want %q", entries[0].Recorder.Hash, rec.Hash)
	}
}

func TestStreamScannerReadErrorIsMalformed(t *testing.T) {
	reader := errReader{}

	entries, errs := collectStreamFromReader(reader, StreamOptions{})

	if len(entries) != 0 {
		t.Fatalf("entries len = %d, want 0", len(entries))
	}
	requireOneErrorIs(t, errs, ErrMalformedEntry)
	if got := errs[0].Error(); !strings.Contains(got, "read recorder line") {
		t.Fatalf("error = %q, want read context", got)
	}
}

func testEntry(t *testing.T, version int, seq int, prevHash, entryType string, detail any) recorder.Entry {
	t.Helper()

	rec := recorder.Entry{
		Version:   version,
		Sequence:  testUint64(seq),
		Timestamp: time.Date(2026, 4, 29, 12, 0, seq, 0, time.UTC),
		SessionID: "session-1",
		Type:      entryType,
		EventKind: "test",
		Transport: "test",
		Summary:   "test entry",
		Detail:    detail,
		PrevHash:  prevHash,
	}
	if recorder.EntryVersionHasNamespace(version) {
		rec.ChainKind = recorder.ChainKindRecorder
		rec.WriterInstanceID = "writer-test"
	}
	rec.Hash = recorder.ComputeHash(rec)
	return rec
}

func testUint64(v int) uint64 {
	if v <= 0 {
		return 0
	}
	return uint64(v)
}

func mustJSONLines(t *testing.T, entries ...recorder.Entry) string {
	t.Helper()

	var buf bytes.Buffer
	for _, entry := range entries {
		if err := json.NewEncoder(&buf).Encode(entry); err != nil {
			t.Fatalf("encode entry: %v", err)
		}
	}
	return buf.String()
}

func collectStream(t *testing.T, input string, opts StreamOptions) ([]Entry, []error) {
	t.Helper()
	return collectStreamFromReader(strings.NewReader(input), opts)
}

func collectStreamFromReader(input io.Reader, opts StreamOptions) ([]Entry, []error) {
	entryCh, errCh := Stream(input, opts)
	var entries []Entry
	var errs []error
	for entryCh != nil || errCh != nil {
		select {
		case entry, ok := <-entryCh:
			if !ok {
				entryCh = nil
				continue
			}
			entries = append(entries, entry)
		case err, ok := <-errCh:
			if !ok {
				errCh = nil
				continue
			}
			errs = append(errs, err)
		}
	}
	return entries, errs
}

func requireOneErrorIs(t *testing.T, errs []error, target error) {
	t.Helper()

	if len(errs) != 1 {
		t.Fatalf("errs len = %d, want 1: %v", len(errs), errs)
	}
	if !errors.Is(errs[0], target) {
		t.Fatalf("error %v does not wrap %v", errs[0], target)
	}
}

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, errBoom
}

var errBoom = errors.New("boom")
