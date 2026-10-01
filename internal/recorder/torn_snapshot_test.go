// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureTornEvidence(t *testing.T) {
	source := "../../sdk/conformance/testdata/recovery-seals/valid/evidence/evidence-proxy.run." + "11111111111111111111111111111111-0.jsonl"
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"nul", "cut_line", "missing_newline", "healthy", "symlink", "bound", "bad_complete", "validator", "complete_callback"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "shard.jsonl")
			data := bytes.Clone(raw)
			capBytes := MaxEvidenceReadFileBytes
			switch mode {
			case "cut_line":
				data = append(bytes.TrimRight(data, "\x00"), []byte(`{"v":`)...)
			case "missing_newline":
				data = bytes.TrimSuffix(bytes.TrimRight(data, "\x00"), []byte("\n"))
			case "healthy":
				data = bytes.TrimRight(data, "\x00")
			case "bound":
				capBytes = 1
			case "bad_complete":
				data = append([]byte("bad\n"), data...)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if mode == "symlink" {
				link := path + ".link"
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			}
			var complete, observed int
			failure := errors.New("callback failure")
			s, err := CaptureTornEvidence(path, capBytes, func(Entry) error {
				observed++
				if mode == "validator" {
					return failure
				}
				return nil
			}, func(Entry) error {
				complete++
				if mode == "complete_callback" {
					return failure
				}
				return nil
			})
			if mode == "nul" || mode == "cut_line" || mode == "missing_newline" {
				if err != nil {
					t.Fatal(err)
				}
				h := sha256.Sum256(data)
				if s.Size != int64(len(data)) || s.SHA256 != hex.EncodeToString(h[:]) || s.Offset != int64(bytes.LastIndexByte(data, '\n')+1) {
					t.Fatalf("incorrect byte observation: %+v", s)
				}
				want := bytes.Count(bytes.TrimRight(raw, "\x00"), []byte("\n"))
				if observed != want || complete < 1 || (mode == "missing_newline" && complete != want-1) {
					t.Fatalf("callbacks observed=%d complete=%d", observed, complete)
				}
			} else if err == nil {
				t.Fatal("invalid input or callback accepted")
			}
			if mode == "validator" || mode == "complete_callback" {
				if !errors.Is(err, failure) {
					t.Fatalf("wrong callback error: %v", err)
				}
			}
		})
	}
}
