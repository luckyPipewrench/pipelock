// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

func TestDataClassForRuleFallbackOrder(t *testing.T) {
	withDefault := func(c contract.Contract) contract.Contract {
		c.Defaults.Privacy.DefaultDataClass = "public"
		return c
	}
	tests := []struct {
		name string
		c    contract.Contract
		want string
	}{
		{name: "pointer key wins", c: withDefault(contract.Contract{DataClassRoot: "internal", FieldDataClasses: map[string]string{"/rules/1": "secret", "rules.1": "x", "rules": "y"}}), want: "secret"},
		{name: "dotted key when no pointer", c: withDefault(contract.Contract{FieldDataClasses: map[string]string{"rules.1": "confidential", "rules": "y"}}), want: "confidential"},
		{name: "rules-wide key", c: withDefault(contract.Contract{FieldDataClasses: map[string]string{"rules": "regulated"}}), want: "regulated"},
		{name: "other index ignored, root used", c: withDefault(contract.Contract{DataClassRoot: "internal", FieldDataClasses: map[string]string{"/rules/0": "secret"}}), want: "internal"},
		{name: "default when nothing set", c: withDefault(contract.Contract{}), want: "public"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dataClassForRule(tt.c, 1); got != tt.want {
				t.Fatalf("dataClassForRule = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSummarizeSelectorShapes(t *testing.T) {
	long := strings.Repeat("a", 200)
	tests := []struct {
		name string
		in   map[string]any
		want string
	}{
		{name: "empty", in: nil, want: "(none)"},
		{name: "host and path", in: map[string]any{"host": "api.vendor.example", "path": "/v1"}, want: "api.vendor.example/v1"},
		{name: "host only", in: map[string]any{"host": "api.vendor.example"}, want: "api.vendor.example"},
		{name: "no host falls back to json", in: map[string]any{"method": "GET"}, want: `{"method":"GET"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := summarizeSelector(tt.in); got != tt.want {
				t.Fatalf("summarizeSelector = %q, want %q", got, tt.want)
			}
		})
	}
	// The display limit itself is a presentation choice; pin only that an
	// over-long summary is cut, marked, and still a prefix of the full value.
	full, err := json.Marshal(map[string]any{"method": long})
	if err != nil {
		t.Fatal(err)
	}
	got := summarizeSelector(map[string]any{"method": long})
	if !strings.HasSuffix(got, "...") || len(got) >= len(full) || !strings.HasPrefix(string(full), strings.TrimSuffix(got, "...")) {
		t.Fatalf("long selector summary = %q (len %d), want a shorter prefix of %d-byte JSON ending in ...", got, len(got), len(full))
	}
}

func TestStageContractEnvelopeYAMLErrors(t *testing.T) {
	tests := []struct {
		name string
		dest func(t *testing.T) string
		want string // empty means success expected
	}{
		{name: "writable directory stages", dest: func(t *testing.T) string { return filepath.Join(t.TempDir(), "candidate.yaml") }},
		{name: "missing parent directory", dest: func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent", "candidate.yaml") }, want: "create candidate staging file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := tt.dest(t)
			env := contract.ContractEnvelope{Signature: "sig-placeholder", Body: contract.Contract{DataClassRoot: "internal"}}
			staged, err := stageContractEnvelopeYAML(dest, env)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("stage: %v", err)
				}
				if filepath.Dir(staged) != filepath.Dir(dest) || staged == dest {
					t.Fatalf("staged path %q not a sibling temp of %q", staged, dest)
				}
				got, readErr := os.ReadFile(filepath.Clean(staged))
				if readErr != nil {
					t.Fatalf("read staged file: %v", readErr)
				}
				want, mErr := marshalYAMLWithJSONTags(env)
				if mErr != nil {
					t.Fatal(mErr)
				}
				if string(got) != string(want) {
					t.Fatalf("staged content = %q, want %q", got, want)
				}
				if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
					t.Fatalf("destination touched before commit: %v", statErr)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("stage error = %v, want %q", err, tt.want)
			}
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("stage error %v does not carry the missing-directory cause", err)
			}
			if staged != "" {
				t.Fatalf("staged path %q returned alongside error", staged)
			}
			entries, dirErr := os.ReadDir(filepath.Dir(filepath.Dir(dest)))
			if dirErr != nil {
				t.Fatal(dirErr)
			}
			if len(entries) != 0 {
				t.Fatalf("failed stage left entries behind: %v", entries)
			}
		})
	}
}
