// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceDoctorTornTail(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]byte) []byte
		torn   bool
	}{
		{"healthy", func(b []byte) []byte { return b }, false},
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
			data, err := os.ReadFile(path)
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
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, after) {
				t.Fatal("doctor rewrote shard")
			}
		})
	}
}
