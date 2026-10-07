// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The same signed producer evidence and mutations are consumed by every
// verifier. A close file is a verdict input, never an AEL verification gate.
func TestReceiptGroupAELMatrix(t *testing.T) {
	first, err := os.ReadFile("../../sdk/verifiers/python/tests/fixtures/receipt-groups-matrix.zip.gz")
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := gzip.NewReader(bytes.NewReader(first))
	if err != nil {
		t.Fatal(err)
	}
	zipBytes, err := io.ReadAll(compressed)
	_ = compressed.Close()
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	var cases []struct {
		Name        string              `json:"name"`
		GroupID     string              `json:"group_id"`
		TrustedKeys []string            `json:"trusted_keys"`
		Expected    ReceiptGroupVerdict `json:"expected"`
	}
	var controls []struct {
		Name        string              `json:"name"`
		GroupID     string              `json:"group_id"`
		TrustedKeys []string            `json:"trusted_keys"`
		Expected    ReceiptGroupVerdict `json:"expected"`
	}
	for _, file := range archive.File {
		if file.Name != "matrix.json" && file.Name != "controls.json" && !strings.HasPrefix(file.Name, "cases/") && !strings.HasPrefix(file.Name, "controls/") {
			t.Fatalf("unexpected matrix path %q", file.Name)
		}
		if strings.Contains(file.Name, "..") || strings.HasPrefix(file.Name, "/") {
			t.Fatalf("unsafe matrix path %q", file.Name)
		}
		if file.FileInfo().IsDir() {
			// #nosec G305 -- rejected absolute paths and traversal components above.
			if err := os.MkdirAll(filepath.Join(root, file.Name), 0o750); err != nil {
				t.Fatal(err)
			}
			continue
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		if file.Name == "matrix.json" {
			if err := json.Unmarshal(data, &cases); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if file.Name == "controls.json" {
			if err := json.Unmarshal(data, &controls); err != nil {
				t.Fatal(err)
			}
			continue
		}
		// #nosec G305 -- rejected absolute paths and traversal components above.
		path := filepath.Join(root, file.Name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if len(cases) != 116 {
		t.Fatalf("matrix has %d cells, want 116", len(cases))
	}
	for _, item := range cases {
		t.Run(item.Name, func(t *testing.T) {
			result := VerifyReceiptGroup(filepath.Join(root, "cases", item.Name), item.GroupID, item.TrustedKeys)
			if result.Verdict != item.Expected {
				t.Fatalf("got %s, want %s: %s", result.Verdict, item.Expected, result.Error)
			}
			if strings.Contains(item.Name, "__torn-early") || strings.Contains(item.Name, "__bad-middle-json") {
				summary, err := VerifyReceiptGroups(filepath.Join(root, "cases", item.Name), item.TrustedKeys, nil)
				if err == nil && summary.Invalid == 0 {
					t.Fatalf("directory mode accepted damaged session: %+v", summary)
				}
			}
			if item.Name == "rotation__legacy__suffix-intact" || item.Name == "rotation__legacy__duplicate-seq" {
				if !strings.Contains(result.Error, "ambiguous evidence shard sequence start") {
					t.Fatalf("ambiguous filename reported as %q", result.Error)
				}
			}
			if item.Name == "predecessor__intact__present" && !strings.Contains(result.Error, "GROUP_INCOMPLETE") {
				t.Fatalf("successor omitted incomplete predecessor: %+v", result)
			}
			if item.Name == "predecessor__byte-flipped__present" {
				dir := filepath.Join(root, "cases", item.Name)
				openName, _ := ReceiptGroupFileName(item.GroupID, "open")
				openBytes, err := readBoundedGroupFile(dir, openName)
				if err != nil {
					t.Fatal(err)
				}
				open, err := UnmarshalReceiptGroupOpen(openBytes, item.TrustedKeys)
				if err != nil {
					t.Fatal(err)
				}
				previousName, _ := ReceiptGroupFileName(open.PreviousGroupID, "open")
				previousBytes, err := readBoundedGroupFile(dir, previousName)
				if err != nil {
					t.Fatal(err)
				}
				previous, err := UnmarshalReceiptGroupOpen(previousBytes, item.TrustedKeys)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := verifyGroupShardPrefix(dir, previous, open.PreviousOpenManifestSHA256, 0); err == nil {
					t.Fatal("predecessor prefix accepted forged completed native AEL")
				}
			}
		})
	}
	if len(controls) != 1 {
		t.Fatalf("matrix controls = %d, want 1", len(controls))
	}
	for _, item := range controls {
		t.Run(item.Name, func(t *testing.T) {
			result := VerifyReceiptGroup(filepath.Join(root, "controls", item.Name), item.GroupID, item.TrustedKeys)
			if result.Verdict != item.Expected {
				t.Fatalf("got %s, want %s: %s", result.Verdict, item.Expected, result.Error)
			}
		})
	}
}

// Pinning these signed bytes prevents fixture regeneration from silently
// changing the Go verifier's oracle.
func TestReceiptGroupCrossLanguageGoldenBytes(t *testing.T) {
	first, err := os.ReadFile("../../sdk/verifiers/python/tests/fixtures/receipt-groups.zip")
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(first), int64(len(first)))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"group-valid/receipt-group-a6c9a32034a3e0467360c6800a82b0e6-open.json":           "8755c2f9ca1eadbebf1f5066723f9cd6b7870067d04d1169410ca420f94de57f",
		"group-valid/receipt-group-a6c9a32034a3e0467360c6800a82b0e6-close.json":          "9772ccfd6768dadb3aeffe235d62ac8649487e96bcdf8d85dea4a11e2da9a114",
		"group-successor/receipt-group-4a4ada2ab57c81440377b5c6cce80d58-transition.json": "bc5764ff811748fc11cb463249b2629834eed82e8c0273ab8ffd2aabce81dd79",
	}
	const session = "group-valid/evidence-proxy.run.1806d08396effa4a8f31e45aa8165c84-0.jsonl"
	const sessionOpenHash = "93a8203267235132f5b2c8b2bc981637531a44b4ba87fe98fb173f409c006803"
	for _, file := range archive.File {
		if _, ok := want[file.Name]; !ok && file.Name != session {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(reader, 1<<20))
		_ = reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		if file.Name == session {
			found := false
			for _, line := range bytes.Split(raw, []byte{'\n'}) {
				if bytes.Contains(line, []byte(`"session_open"`)) && bytes.Contains(line, []byte(`"group_binding"`)) {
					if got := fmt.Sprintf("%x", sha256.Sum256(line)); got != sessionOpenHash {
						t.Fatalf("N>1 session_open bytes changed: %s", got)
					}
					found = true
				}
			}
			if !found {
				t.Fatal("N>1 session_open missing from group fixture")
			}
			continue
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want[file.Name] {
			t.Fatalf("%s bytes changed: %s", file.Name, got)
		}
		delete(want, file.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing signed group vectors: %v", want)
	}
}
