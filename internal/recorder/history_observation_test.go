// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func TestObservedHistoryDurableBoundary(t *testing.T) {
	const session = "observed-history"
	for _, tail := range []string{"intact", "fragment", "valid_unterminated", "sparse_padding", "empty", "crlf"} {
		t.Run(tail, func(t *testing.T) {
			dir := t.TempDir()
			entries := historyEntries(t, session, 0, 2, "s")
			wire := historyLines(t, entries)
			offset := int64(len(wire))
			wantDurable, wantFragment := 2, 0
			wantObservation := tail != "intact" && tail != "empty" && tail != "crlf"
			switch tail {
			case "fragment":
				wire = append(wire, []byte(`{"version":`)...)
			case "valid_unterminated":
				wire = wire[:len(wire)-1]
				offset = int64(len(historyLines(t, entries[:1])))
				wantDurable, wantFragment = 1, 1
			case "sparse_padding":
				wire = append(wire, make([]byte, MaxEntryLineBytes+1)...)
			case "empty":
				wire = nil
				offset = 0
				wantDurable = 0
			case "crlf":
				wire = bytes.ReplaceAll(wire, []byte{'\n'}, []byte{'\r', '\n'})
				offset = int64(len(wire))
			}
			name := "evidence-" + session + "-0.jsonl"
			if err := os.WriteFile(filepath.Join(dir, name), wire, 0o600); err != nil {
				t.Fatal(err)
			}
			durable, fragment := 0, 0
			var readBytes int64
			observation, err := WalkSessionHistoryObserved(dir, session, verification.Options{Progress: func(p verification.Progress) error { readBytes += p.Bytes; return nil }}, func(e Entry, complete bool) error {
				if e.Sequence != entries[durable+fragment].Sequence || e.Hash != entries[durable+fragment].Hash || e.Summary != entries[durable+fragment].Summary {
					t.Fatalf("entry=%+v want=%+v", e, entries[durable+fragment])
				}
				if complete {
					durable++
				} else {
					fragment++
				}
				return nil
			})
			if err != nil || durable != wantDurable || fragment != wantFragment || readBytes != int64(len(wire)) {
				t.Fatalf("durable=%d fragment=%d bytes=%d err=%v", durable, fragment, readBytes, err)
			}
			if (observation != nil) != wantObservation {
				t.Fatalf("observation=%+v", observation)
			}
			if observation != nil {
				sum := sha256.Sum256(wire)
				want := TornSnapshot{Size: int64(len(wire)), Offset: offset, SHA256: hex.EncodeToString(sum[:])}
				if observation.Shard != name || observation.Snapshot != want {
					t.Fatalf("observation=%+v want=%+v", observation, want)
				}
			}
		})
	}
}

func TestObservedHistoryRefusals(t *testing.T) {
	const session = "observed-refusal"
	failure := errors.New("visitor refused record")
	for _, tc := range []struct{ name, want string }{
		{"malformed", "invalid character"},
		{"version", "unsupported entry version"},
		{"schema", "NUL"},
		{"session", "session"},
		{"embedded_nul", "embedded NUL"},
		{"oversized_wire", "entry limit"},
		{"oversized_payload", "entry limit"},
		{"visitor", failure.Error()},
		{"non_final_torn", "torn non-final segment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			entries := historyEntries(t, session, 0, 1, "s")
			switch tc.name {
			case "version":
				entries[0].Version = 99
			case "schema":
				entries[0].Summary = "bad\x00summary"
			case "session":
				entries[0].SessionID = "other-session"
			}
			wire := historyLines(t, entries)
			switch tc.name {
			case "malformed":
				wire = []byte("{broken}\n")
			case "embedded_nul":
				wire = append(wire, []byte("\x00unexpected")...)
			case "oversized_wire":
				wire = []byte(strings.Repeat("x", maxEntryWireLineBytes+1))
			case "oversized_payload":
				wire = []byte(strings.Repeat("x", MaxEntryLineBytes+1) + "\n")
			case "non_final_torn":
				wire = append(wire, []byte(`{"torn":`)...)
				writeHistoryShard(t, dir, session, 1, 1)
			}
			if err := os.WriteFile(filepath.Join(dir, "evidence-"+session+"-0.jsonl"), wire, 0o600); err != nil {
				t.Fatal(err)
			}
			observation, err := WalkSessionHistoryObserved(dir, session, verification.Options{}, func(Entry, bool) error {
				if tc.name == "visitor" {
					return failure
				}
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) || observation != nil {
				t.Fatalf("observation=%+v err=%v want %q", observation, err, tc.want)
			}
		})
	}
}

func TestObservedHistoryCancellationAndReadErrors(t *testing.T) {
	const session = "observed-cancel"
	for _, phase := range []string{"before", "read", "visitor", "progress_error", "location"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			writeHistoryShard(t, dir, session, 0, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("read notification failed")
			options := verification.Options{Context: ctx}
			if phase == "before" {
				cancel()
			}
			if phase == "read" || phase == "progress_error" {
				options.Progress = func(verification.Progress) error {
					if phase == "read" {
						cancel()
						return nil
					}
					return failure
				}
			}
			if phase == "location" {
				dir = "\x00"
			}
			delivered := 0
			obs, err := WalkSessionHistoryObserved(dir, session, options, func(Entry, bool) error {
				delivered++
				if phase == "visitor" {
					cancel()
				}
				return nil
			})
			if err == nil || obs != nil {
				t.Fatalf("observation=%+v error=%v", obs, err)
			}
			if phase != "location" && phase != "progress_error" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation became %v", err)
			}
			if phase == "progress_error" && !errors.Is(err, failure) {
				t.Fatalf("read failure became %v", err)
			}
			if phase == "before" && delivered != 0 {
				t.Fatalf("delivered %d entries after refusal", delivered)
			}
		})
	}
}

func TestTrailingNULReaderBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name          string
		parts         [][]byte
		want, wantErr string
	}{
		{"no_padding", [][]byte{[]byte("record")}, "record", ""},
		{"padding_only", [][]byte{{0, 0}, {0, 0}}, "", ""},
		{"split_padding", [][]byte{[]byte("record\x00"), {0, 0}}, "record", ""},
		{"embedded_same_read", [][]byte{[]byte("record\x00x")}, "", "embedded NUL"},
		{"embedded_next_read", [][]byte{[]byte("record\x00"), []byte("x")}, "record", "embedded NUL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			readers := make([]io.Reader, 0, len(tc.parts))
			for _, part := range tc.parts {
				readers = append(readers, bytes.NewReader(part))
			}
			r := &trailingNULReader{source: io.MultiReader(readers...)}
			got, err := io.ReadAll(r)
			if string(got) != tc.want || tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("got=%q err=%v", got, err)
			}
		})
	}
}

func TestObservedEntriesReadAndVisitorFailures(t *testing.T) {
	const session = "observed-reader"
	failure := errors.New("source read failed")
	for _, tc := range []struct {
		name   string
		reader io.Reader
		want   string
	}{
		{"read_failure", observedErrorReader{failure}, failure.Error()},
		{"embedded_nul", strings.NewReader("{\x00}\n"), "embedded NUL"},
		{"large_valid", bytes.NewReader(historyLines(t, historyEntries(t, session, 0, 1, strings.Repeat("s", 8192)))), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			visits := 0
			size, offset, torn, err := walkObservedEntries(tc.reader, session, func(Entry, bool) error { visits++; return nil })
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) || visits != 0 {
					t.Fatalf("visits=%d err=%v", visits, err)
				}
				return
			}
			if err != nil || visits != 1 || size != offset || torn {
				t.Fatalf("size=%d offset=%d torn=%v visits=%d err=%v", size, offset, torn, visits, err)
			}
		})
	}
}

type observedErrorReader struct{ err error }

func (r observedErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestHistoryOptionsEarlyRefusals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, phase := range []string{"location", "canceled", "non_final_torn", "reader"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			const session = "options-refusal"
			name := writeHistoryShard(t, dir, session, 0, 1)
			options := verification.Options{}
			switch phase {
			case "location":
				dir = "\x00"
			case "canceled", "reader":
				options.Context = ctx
			case "non_final_torn":
				if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"torn":`), 0o600); err != nil {
					t.Fatal(err)
				}
				writeHistoryShard(t, dir, session, 1, 1)
			}
			visits := 0
			var err error
			if phase == "reader" {
				r := &historyProgressReader{Reader: strings.NewReader("record"), options: options}
				var b [8]byte
				_, err = r.Read(b[:])
			} else {
				err = WalkSessionHistoryWithOptions(dir, session, options, func(Entry) error { visits++; return nil })
			}
			if err == nil || visits != 0 {
				t.Fatalf("visits=%d err=%v", visits, err)
			}
			if (phase == "canceled" || phase == "reader") && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel became %v", err)
			}
			if phase == "non_final_torn" && !strings.Contains(err.Error(), "torn segment") {
				t.Fatalf("non-final damage became %v", err)
			}
		})
	}
}

func TestTrailingNULReaderFinalReadError(t *testing.T) {
	r := &trailingNULReader{source: iotest.DataErrReader(bytes.NewReader([]byte{0}))}
	got, err := io.ReadAll(r)
	if err != nil || len(got) != 0 || !r.padding {
		t.Fatalf("padding=%t bytes=%q error=%v", r.padding, got, err)
	}
}
