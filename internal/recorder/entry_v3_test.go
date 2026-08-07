// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func v3Entry() recorder.Entry {
	return recorder.Entry{
		Version:          recorder.LatestEntryVersion,
		Sequence:         7,
		Timestamp:        time.Date(2026, 8, 7, 12, 34, 56, 789, time.UTC),
		SessionID:        "proxy",
		ChainKind:        recorder.ChainKindRecorder,
		WriterInstanceID: "writer-0123456789abcdef",
		TraceID:          "trace-7",
		Type:             "request",
		EventKind:        "write",
		Transport:        "fetch",
		Summary:          "v3 reader fixture",
		Detail:           map[string]any{"a": "b"},
		RawRef:           "evidence.raw.enc",
		PrevHash:         recorder.GenesisHash,
	}
}

func TestComputeHashV3FrozenProjection(t *testing.T) {
	e := v3Entry()
	const want = "86cf558b8504031e857711860383f0b2badd0cff5c06761a3f29ae507c1d4292"
	if got := recorder.ComputeHash(e); got != want {
		t.Fatalf("ComputeHash(v3) = %q, want frozen %q", got, want)
	}
}

func TestComputeHashV3BindsNamespace(t *testing.T) {
	base := v3Entry()
	baseHash := recorder.ComputeHash(base)

	for _, tc := range []struct {
		name   string
		mutate func(*recorder.Entry)
	}{
		{"chain_kind", func(e *recorder.Entry) { e.ChainKind = "receipt" }},
		{"writer_instance_id", func(e *recorder.Entry) { e.WriterInstanceID = "writer-fedcba9876543210" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			tc.mutate(&changed)
			if got := recorder.ComputeHash(changed); got == baseHash {
				t.Fatalf("changing %s did not change v3 hash", tc.name)
			}
		})
	}

	v2 := base
	v2.Version = recorder.CurrentWriteEntryVersion
	v2.ChainKind = ""
	v2.WriterInstanceID = ""
	if recorder.ComputeHash(v2) == baseHash {
		t.Fatal("v2 and v3 hashes collide for equivalent record")
	}
}

func TestV3RejectsNullDelimiterCollision(t *testing.T) {
	left := v3Entry()
	left.ChainKind = "recorder"
	left.WriterInstanceID = "a\x00b"
	right := left
	right.ChainKind = "recorder\x00a"
	right.WriterInstanceID = "b"
	if recorder.ComputeHash(left) != recorder.ComputeHash(right) {
		t.Fatal("fixture does not reproduce the frozen v3 delimiter collision")
	}
	for _, entry := range []recorder.Entry{left, right} {
		if err := recorder.ValidateEntrySchema(entry); err == nil || !strings.Contains(err.Error(), "cannot contain NUL") {
			t.Fatalf("ValidateEntrySchema() error = %v, want NUL rejection", err)
		}
	}
}

func TestEntryVersionsCanShareChain(t *testing.T) {
	for _, tc := range []struct {
		name        string
		tail, write int
		want        bool
	}{
		{"v1_to_v2", 1, 2, true},
		{"v2_to_v3", 2, 3, false},
		{"v3_to_v2", 3, 2, false},
		{"v3_to_v3", 3, 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := recorder.EntryVersionsCanShareChain(tc.tail, tc.write); got != tc.want {
				t.Fatalf("EntryVersionsCanShareChain(%d, %d) = %v, want %v", tc.tail, tc.write, got, tc.want)
			}
		})
	}
}

func TestVerifyChainV3RequiresNamespace(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*recorder.Entry)
		want   string
	}{
		{"missing_chain_kind", func(e *recorder.Entry) { e.ChainKind = "" }, "chain_kind required"},
		{"missing_writer_instance_id", func(e *recorder.Entry) { e.WriterInstanceID = "" }, "writer_instance_id required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := v3Entry()
			tc.mutate(&e)
			e.Hash = recorder.ComputeHash(e)
			err := recorder.VerifyChain([]recorder.Entry{e})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VerifyChain() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyChainAcceptsMixedV1V2(t *testing.T) {
	entries := make([]recorder.Entry, 2)
	prevHash := recorder.GenesisHash
	for i, version := range []int{1, 2} {
		entries[i] = v3Entry()
		entries[i].Version = version
		entries[i].Sequence = uint64(i)
		entries[i].ChainKind = ""
		entries[i].WriterInstanceID = ""
		entries[i].PrevHash = prevHash
		entries[i].Hash = recorder.ComputeHash(entries[i])
		prevHash = entries[i].Hash
	}
	if err := recorder.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain(v1/v2) = %v", err)
	}
}

func TestVerifyChainRejectsNamespaceTransitions(t *testing.T) {
	first := v3Entry()
	first.Sequence = 0
	first.PrevHash = recorder.GenesisHash
	first.Hash = recorder.ComputeHash(first)

	for _, tc := range []struct {
		name   string
		mutate func(*recorder.Entry)
		want   string
	}{
		{"writer_change", func(e *recorder.Entry) { e.WriterInstanceID = "writer-b" }, "namespace changed"},
		{"kind_change", func(e *recorder.Entry) { e.ChainKind = "receipt" }, "namespace changed"},
		{"legacy_after_v3", func(e *recorder.Entry) {
			e.Version = recorder.CurrentWriteEntryVersion
			e.ChainKind = ""
			e.WriterInstanceID = ""
		}, "legacy entry cannot continue"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			second := first
			second.Sequence = 1
			second.PrevHash = first.Hash
			tc.mutate(&second)
			second.Hash = recorder.ComputeHash(second)
			err := recorder.VerifyChain([]recorder.Entry{first, second})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VerifyChain() error = %v, want %q", err, tc.want)
			}
		})
	}

	legacy := first
	legacy.Version = recorder.CurrentWriteEntryVersion
	legacy.ChainKind = ""
	legacy.WriterInstanceID = ""
	legacy.Hash = recorder.ComputeHash(legacy)
	newChain := first
	newChain.Sequence = 1
	newChain.PrevHash = legacy.Hash
	newChain.Hash = recorder.ComputeHash(newChain)
	if err := recorder.VerifyChain([]recorder.Entry{legacy, newChain}); err == nil || !strings.Contains(err.Error(), "cannot continue a legacy") {
		t.Fatalf("VerifyChain(v2/v3) error = %v, want namespace transition rejection", err)
	}
}

func TestReadEntriesPreservesV3Namespace(t *testing.T) {
	e := v3Entry()
	e.Hash = recorder.ComputeHash(e)
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "evidence-proxy-7.jsonl")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := recorder.ReadEntries(path)
	if err != nil {
		t.Fatalf("ReadEntries() = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("ReadEntries() count = %d, want 1", len(entries))
	}
	if entries[0].ChainKind != e.ChainKind || entries[0].WriterInstanceID != e.WriterInstanceID {
		t.Fatalf("namespace = (%q, %q), want (%q, %q)", entries[0].ChainKind, entries[0].WriterInstanceID, e.ChainKind, e.WriterInstanceID)
	}
	if err := recorder.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain(ReadEntries()) = %v", err)
	}
}

func TestReadEntriesRejectsIncompleteV3Namespace(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*recorder.Entry)
		want   string
	}{
		{"missing_chain_kind", func(e *recorder.Entry) { e.ChainKind = "" }, "chain_kind required"},
		{"missing_writer_instance_id", func(e *recorder.Entry) { e.WriterInstanceID = "" }, "writer_instance_id required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := v3Entry()
			tc.mutate(&e)
			e.Hash = recorder.ComputeHash(e)
			data, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "v3.jsonl")
			if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := recorder.ReadEntries(path); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ReadEntries() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLegacyEntriesRejectV3NamespaceFields(t *testing.T) {
	for _, version := range []int{1, recorder.CurrentWriteEntryVersion} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			e := v3Entry()
			e.Version = version
			e.Hash = recorder.ComputeHash(e)

			if err := recorder.VerifyChain([]recorder.Entry{e}); err == nil || !strings.Contains(err.Error(), "legacy entry cannot carry") {
				t.Fatalf("VerifyChain() error = %v, want legacy namespace rejection", err)
			}

			data, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "legacy.jsonl")
			if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := recorder.ReadEntries(path); err == nil || !strings.Contains(err.Error(), "legacy entry cannot carry") {
				t.Fatalf("ReadEntries() error = %v, want legacy namespace rejection", err)
			}
		})
	}
}

// Remove this rollout tripwire when the recorder advances its writer to v3.
func TestRecorderStillWritesV2DuringReaderFirstRollout(t *testing.T) {
	if recorder.CurrentWriteEntryVersion != 2 {
		t.Fatalf("CurrentWriteEntryVersion = %d, want 2 during reader-first rollout", recorder.CurrentWriteEntryVersion)
	}
	if recorder.LatestEntryVersion != 3 {
		t.Fatalf("LatestEntryVersion = %d, want 3", recorder.LatestEntryVersion)
	}
}

func TestRecorderStripsNamespaceFieldsWhileWritingV2(t *testing.T) {
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: false}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Record(recorder.Entry{
		SessionID:        "proxy",
		ChainKind:        recorder.ChainKindRecorder,
		WriterInstanceID: "caller-controlled",
		Type:             "capture",
		Transport:        "fetch",
		Summary:          "reader-first",
	}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("evidence files = %v, err = %v", files, err)
	}
	entries, err := recorder.ReadEntries(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no recorder entries")
	}
	if entries[0].Version != recorder.CurrentWriteEntryVersion || entries[0].ChainKind != "" || entries[0].WriterInstanceID != "" {
		t.Fatalf("written namespace = v%d (%q, %q), want v2 with empty namespace", entries[0].Version, entries[0].ChainKind, entries[0].WriterInstanceID)
	}
}
