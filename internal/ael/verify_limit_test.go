// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadBoundedAELLineCountsGrowthAcrossRecords(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int64
		fail  bool
	}{
		{"within limit", 11, false},
		{"appended line exceeds limit", 10, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stream.jsonl")
			if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			initial, err := file.Stat()
			if err != nil || initial.Size() > tc.limit {
				t.Fatalf("initial stream size = %v, %v", initial, err)
			}
			writer, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.WriteString("more\n"); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			r := bufio.NewReader(file)
			var total int64
			if line, err := readBoundedAELLine(r, &total, tc.limit); err != nil || string(line) != "first\n" || total != 6 {
				t.Fatalf("first line = %q, %v, total=%d", line, err, total)
			}
			line, err := readBoundedAELLine(r, &total, tc.limit)
			if tc.fail {
				if !errors.Is(err, errAELStreamTooLarge) || total != 6 {
					t.Fatalf("growth beyond limit = %q, %v, total=%d", line, err, total)
				}
			} else if err != nil || string(line) != "more\n" || total != 11 {
				t.Fatalf("bounded stream = %q, %v, total=%d", line, err, total)
			}
		})
	}
}
