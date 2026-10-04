// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestEvidenceDoctorTornTail(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]byte) []byte
		torn   bool
	}{
		{"healthy", func(b []byte) []byte { return b }, false},
		{"empty", func(_ []byte) []byte { return nil }, false},
		{"bad prefix hash with NUL", func(b []byte) []byte {
			return append(bytes.Replace(b, []byte(`"summary":"test"`), []byte(`"summary":"edited"`), 1), 0)
		}, false},
		{"nul", func(b []byte) []byte { return append(b, 0, 0) }, true},
		{"truncated", func(b []byte) []byte { return append(b, []byte(`{"version":`)...) }, true},
		{"missing newline", func(b []byte) []byte { return b[:len(b)-1] }, true},
		{"midfile garbage", func(b []byte) []byte { return append(append([]byte("garbage\n"), b...), 0) }, false},
		{"bad hash unterminated", func(b []byte) []byte {
			return bytes.Replace(b[:len(b)-1], []byte(`"summary":"test"`), []byte(`"summary":"edited"`), 1)
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			name := "evidence-proxy-0.jsonl"
			path := filepath.Join(dir, name)
			writeDoctorEntries(t, dir, name, doctorEntryPlan{{session: "proxy", seq: 0}})
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			data = tc.mutate(data)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			report, err := runEvidenceDoctor(dir)
			if err != nil {
				t.Fatal(err)
			}
			if report.FilesRead != 1 {
				t.Fatalf("files read=%d want 1", report.FilesRead)
			}
			torn := false
			for _, f := range report.Findings {
				if f.Kind == "torn_tail" {
					torn = true
					if !strings.Contains(f.Message, path) || !strings.Contains(f.Message, "byte ") || !strings.Contains(f.Message, "observed at ") {
						t.Fatalf("incomplete torn finding: %+v", f)
					}
				}
			}
			if torn != tc.torn {
				t.Fatalf("torn=%v want %v findings=%+v", torn, tc.torn, report.Findings)
			}
			if tc.name != "healthy" && !report.Damaged() {
				t.Fatal("damaged file reported healthy")
			}
			after, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, after) {
				t.Fatal("doctor rewrote shard")
			}
		})
	}
}

func TestEvidenceDoctorSignatureBeforeTornTail(t *testing.T) {
	dir := t.TempDir()
	writeActualDoctorReceipt(t, dir)
	path := filepath.Join(dir, "evidence-proxy-0.jsonl")
	entries, err := recorder.ReadEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := receipt.Unmarshal(entries[0].RawDetail)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = "ed25519:" + strings.Repeat("0", 128)
	entries[0].Detail, entries[0].RawDetail = r, nil
	entries[0].Hash = recorder.ComputeHash(entries[0])
	line, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append(line, '\n'), 0), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := runEvidenceDoctor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Damaged() {
		t.Fatal("invalid signature reported healthy")
	}
	for _, finding := range report.Findings {
		if finding.Kind == "torn_tail" {
			t.Fatal("invalid signature hidden by torn suffix")
		}
	}
}

func TestEvidenceDoctorTornPrefixAccounting(t *testing.T) {
	dir := t.TempDir()
	writeActualDoctorReceipt(t, dir)
	path := filepath.Join(dir, "evidence-proxy-0.jsonl")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-1.jsonl"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	healthy, err := runEvidenceDoctor(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"duplicate_recorder_seq", "duplicate_receipt_chain_seq"} {
		found := false
		for _, f := range healthy.Findings {
			if f.Kind == kind {
				found = true
			}
		}
		if !found {
			t.Fatalf("positive control missing %s: %+v", kind, healthy.Findings)
		}
	}
	if err := os.WriteFile(path, append(data, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := runEvidenceDoctor(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"torn_tail", "duplicate_recorder_seq", "duplicate_receipt_chain_seq"} {
		found := false
		for _, f := range report.Findings {
			if f.Kind == kind {
				found = true
			}
		}
		if !found {
			t.Errorf("torn prefix lost %s: %+v", kind, report.Findings)
		}
	}
	if report.FilesRead != 2 {
		t.Errorf("files read=%d want 2", report.FilesRead)
	}
}
