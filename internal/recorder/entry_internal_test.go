// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecodeEntryDetailRejectsMalformedRawJSON(t *testing.T) {
	t.Parallel()

	if _, err := decodeEntryDetail(json.RawMessage(`{"unterminated":`)); err == nil {
		t.Fatal("decodeEntryDetail accepted malformed raw detail")
	}
}

func TestReadEntriesFromReaderRejectsUnrepresentableRawDetail(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	line := fmt.Sprintf(
		`{"v":2,"seq":0,"ts":%q,"session_id":"s1","type":"request","transport":"fetch","summary":"bad detail","detail":1e10000,"prev_hash":"genesis","hash":"abc"}`+"\n",
		ts,
	)

	_, err := ReadEntriesFromReader(bytes.NewBufferString(line))
	if err == nil {
		t.Fatal("ReadEntriesFromReader accepted detail that cannot decode into the public Detail view")
	}
}

func TestReadEntriesFromReaderBounded(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		limits     entryReadLimits
		wantCount  int
		wantBytes  int64
		wantErrSub string
	}{
		{
			name:      "byte limit counts skipped lines",
			input:     strings.Repeat("\n", 1<<20),
			limits:    entryReadLimits{MaxEntries: 1, MaxBytes: 128},
			wantCount: 0,
			wantBytes: 128,
		},
		{
			name:      "entry limit reports extra record",
			input:     testEntryLine(t, 0) + testEntryLine(t, 1),
			limits:    entryReadLimits{MaxEntries: 1, MaxBytes: 4096},
			wantCount: 1,
			wantBytes: int64(len(testEntryLine(t, 0))),
		},
		{
			name:      "small input complete",
			input:     testEntryLine(t, 0),
			limits:    entryReadLimits{MaxEntries: 1, MaxBytes: 4096},
			wantCount: 1,
		},
		{
			name:       "line size fence remains active",
			input:      strings.Repeat("x", MaxEntryLineBytes+1),
			limits:     entryReadLimits{MaxBytes: int64(MaxEntryLineBytes + 2)},
			wantErrSub: "line 1",
		},
		{
			name:       "duplicate key fence remains active",
			input:      `{"v":2,"seq":0,"ts":"2026-07-12T12:00:00Z","session_id":"s1","type":"request","type":"response","transport":"fetch","summary":"x","prev_hash":"genesis","hash":"abc"}` + "\n",
			limits:     entryReadLimits{MaxBytes: 4096},
			wantErrSub: "duplicate object key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			counting := &countingReader{r: strings.NewReader(test.input)}
			entries, truncated, bytesRead, err := readEntriesFromReader(counting, test.limits)
			if test.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("readEntriesFromReader error = %v, want substring %q", err, test.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("readEntriesFromReader: %v", err)
			}
			wantTruncated := test.name != "small input complete"
			if truncated != wantTruncated {
				t.Fatalf("truncated = %t, want %t", truncated, wantTruncated)
			}
			if len(entries) != test.wantCount {
				t.Fatalf("len(entries) = %d, want %d", len(entries), test.wantCount)
			}
			if test.wantBytes > 0 && bytesRead <= test.wantBytes {
				t.Fatalf("bytesRead = %d, want evidence that read limit was reached past %d", bytesRead, test.wantBytes)
			}
			if test.name == "byte limit counts skipped lines" && counting.read >= int64(len(test.input)) {
				t.Fatalf("reader was drained to EOF: read %d bytes", counting.read)
			}
		})
	}
}

func TestReadEntriesStrictBoundaries(t *testing.T) {
	t.Run("public reader errors on byte truncation", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "evidence-s1-0.jsonl")
		if err := os.WriteFile(path, []byte(strings.Repeat("\n", int(MaxEvidenceReadFileBytes)+1)), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadEntries(path)
		if !errors.Is(err, ErrEvidenceReadLimitExceeded) {
			t.Fatalf("ReadEntries error = %v, want ErrEvidenceReadLimitExceeded", err)
		}
	})

	t.Run("file as parent", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(parent, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadEntries(filepath.Join(parent, "evidence.jsonl")); err == nil {
			t.Fatal("ReadEntries accepted file-as-parent path")
		}
	})

	t.Run("unreadable file", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can read chmod 000 files")
		}
		path := filepath.Join(t.TempDir(), "evidence.jsonl")
		if err := os.WriteFile(path, []byte(testEntryLine(t, 0)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		if _, err := ReadEntries(path); err == nil {
			t.Fatal("ReadEntries accepted unreadable file")
		}
	})

	t.Run("public reader from io errors on entry truncation", func(t *testing.T) {
		var input strings.Builder
		for seq := range MaxEvidenceReadEntries + 1 {
			input.WriteString(testEntryLine(t, uint64(seq)))
		}
		_, err := ReadEntriesFromReader(strings.NewReader(input.String()))
		if !errors.Is(err, ErrEvidenceReadLimitExceeded) {
			t.Fatalf("ReadEntriesFromReader error = %v, want ErrEvidenceReadLimitExceeded", err)
		}
	})
}

func TestReadEntriesFromReaderPropagatesReaderError(t *testing.T) {
	_, _, _, err := readEntriesFromReader(errorReader{}, entryReadLimits{MaxBytes: 4096})
	if err == nil || !strings.Contains(err.Error(), "scanning evidence entries") {
		t.Fatalf("readEntriesFromReader error = %v, want scanning evidence entries", err)
	}
}

func TestReadLimitExceededErrorMessages(t *testing.T) {
	tests := []struct {
		name   string
		limits entryReadLimits
		want   string
	}{
		{name: "entries and bytes", limits: entryReadLimits{MaxEntries: 1, MaxBytes: 2}, want: "1 entries or 2 bytes"},
		{name: "entries", limits: entryReadLimits{MaxEntries: 1}, want: "1 entries"},
		{name: "bytes", limits: entryReadLimits{MaxBytes: 2}, want: "2 bytes"},
		{name: "fallback", limits: entryReadLimits{}, want: "bounded read limits"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := readLimitExceededError("evidence.jsonl", test.limits)
			if !errors.Is(err, ErrEvidenceReadLimitExceeded) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("readLimitExceededError = %v, want ErrEvidenceReadLimitExceeded containing %q", err, test.want)
			}
		})
	}
}

func testEntryLine(t *testing.T, seq uint64) string {
	t.Helper()
	entry := Entry{
		Version:   EntryVersion,
		Sequence:  seq,
		Timestamp: time.Date(2026, 7, 12, 12, 0, int(seq), 0, time.UTC),
		SessionID: "s1",
		Type:      "request",
		Transport: "fetch",
		Summary:   fmt.Sprintf("entry %d", seq),
		PrevHash:  GenesisHash,
	}
	entry.Hash = ComputeHash(entry)
	wire, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(wire) + "\n"
}

type countingReader struct {
	r    io.Reader
	read int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.read += int64(n)
	return n, err
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("forced reader error")
}
