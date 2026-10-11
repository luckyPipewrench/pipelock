// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadEvidenceLocationAppendTail(t *testing.T) {
	const name = "evidence-proxy-0.jsonl"
	original := []byte("{\"a\":1}\n{\"b\":2}\n")
	for _, tc := range []struct {
		name    string
		during  func(t *testing.T, path string)
		wantErr bool
	}{
		{name: "stable"},
		{name: "appended during read", during: func(t *testing.T, path string) {
			f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if _, err := f.WriteString("{\"c\":3}\n"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "truncated during read", wantErr: true, during: func(t *testing.T, path string) {
			if err := os.Truncate(path, 4); err != nil {
				t.Fatal(err)
			}
		}},
		// The read stays on the opened file; the replacement is the next
		// read's concern.
		{name: "replaced during read", during: func(t *testing.T, path string) {
			tmp := path + ".new"
			if err := os.WriteFile(tmp, append(append([]byte(nil), original...), "{\"d\":4}\n"...), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			location, err := ResolveEvidenceLocation(dir, "")
			if err != nil {
				t.Fatal(err)
			}
			if tc.during != nil {
				restore := afterAppendTailRead
				afterAppendTailRead = func(string) { tc.during(t, path) }
				defer func() { afterAppendTailRead = restore }()
			}
			data, truncated, err := ReadEvidenceLocationAppendTail(location, name, 1024)
			if tc.wantErr {
				if !errors.Is(err, ErrEvidenceFileChanged) {
					t.Fatalf("err = %v, want ErrEvidenceFileChanged", err)
				}
				return
			}
			if err != nil || truncated || !bytes.Equal(data, original) {
				t.Fatalf("read = %q truncated=%v err=%v, want the bytes present when the read began", data, truncated, err)
			}
		})
	}
}
