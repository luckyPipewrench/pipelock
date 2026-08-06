// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCommittedProvenanceCorpusMatchesFrozenExpectations runs every committed
// provenance fixture through the Go verifier and compares the staged report to
// its frozen .expect.json known answer.
//
// Why this exists in Go, when corpus-gate.sh already compares the same files:
// the gate needs four built verifier binaries (GO_VERIFY, TS_VERIFY, RUST_VERIFY,
// PY_VERIFY), so in practice it only ever runs in CI. Without this test, editing
// a frozen expectation locally leaves `go test ./cmd/pipelock-verifier/` green,
// and the corpus is unguarded in the loop developers actually work in.
//
// This does NOT replace the gate. The gate additionally proves the four
// implementations agree byte-for-byte with each other, which a single-language
// test cannot. This only makes the known answers load-bearing locally.
func TestCommittedProvenanceCorpusMatchesFrozenExpectations(t *testing.T) {
	dir := filepath.Clean(filepath.Join("..", "..", "sdk", "conformance", "testdata", "provenance"))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read provenance corpus: %v", err)
	}

	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".expect.json") {
			continue
		}
		base := strings.TrimSuffix(name, ".json")

		t.Run(base, func(t *testing.T) {
			fixturePath := filepath.Clean(filepath.Join(dir, name))

			// A fixture with no committed expectation is a hole in the corpus,
			// not a case to skip.
			expectPath := filepath.Clean(filepath.Join(dir, base+".expect.json"))
			expectData, err := os.ReadFile(expectPath)
			if err != nil {
				t.Fatalf("missing frozen expectation for %s: %v", base, err)
			}
			var want provenanceStageReport
			if err := decodeStrictJSON(expectData, &want); err != nil {
				t.Fatalf("decode expectation: %v", err)
			}

			var output bytes.Buffer
			runErr := runProvenance(&output, fixturePath, true)
			var got provenanceStageReport
			if err := decodeStrictJSON(output.Bytes(), &got); err != nil {
				t.Fatalf("decode verifier output: %v (%q)", err, output.String())
			}
			if rejected := want.Overall == "invalid"; rejected != (runErr != nil) {
				t.Fatalf("overall %q with error %v; want error presence %t", want.Overall, runErr, rejected)
			}
			if got != want {
				gotJSON, _ := json.Marshal(got)
				wantJSON, _ := json.Marshal(want)
				t.Fatalf("staged report drifted from the frozen known answer\n got: %s\nwant: %s", gotJSON, wantJSON)
			}
		})
		checked++
	}

	// A corpus path that silently matches nothing would make every assertion
	// above vacuous, so refuse to pass on zero fixtures.
	if checked == 0 {
		t.Fatalf("no provenance fixtures found under %s", dir)
	}
	t.Logf("checked %d committed provenance fixtures against frozen expectations", checked)
}
