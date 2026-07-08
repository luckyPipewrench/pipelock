// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestLimitsDocParity(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "evidence", "hard-limits.md"))
	if err != nil {
		t.Fatalf("read hard limits doc: %v", err)
	}
	re := regexp.MustCompile(`L-[A-Z0-9-]+`)
	docIDs := map[LimitID]struct{}{}
	for _, match := range re.FindAllString(string(data), -1) {
		docIDs[LimitID(match)] = struct{}{}
	}
	codeIDs := map[LimitID]struct{}{}
	for _, limit := range Limits {
		codeIDs[limit.ID] = struct{}{}
		if _, ok := docIDs[limit.ID]; !ok {
			t.Fatalf("doc missing limit id %s", limit.ID)
		}
	}
	for id := range docIDs {
		if _, ok := codeIDs[id]; !ok {
			t.Fatalf("doc has unknown limit id %s", id)
		}
	}
}

func TestLimitsGenerateIdempotent(t *testing.T) {
	docPath := filepath.Join("..", "..", "docs", "evidence", "hard-limits.md")
	before, err := os.ReadFile(filepath.Clean(docPath))
	if err != nil {
		t.Fatalf("read hard limits doc: %v", err)
	}
	cmd := exec.CommandContext(context.Background(), "go", "generate", "./internal/evidence")
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go generate failed: %v\n%s", err, out)
	}
	after, err := os.ReadFile(filepath.Clean(docPath))
	if err != nil {
		t.Fatalf("read regenerated doc: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("go generate changed hard-limits.md:\n%s", strings.TrimSpace(string(out)))
	}
}

func TestByID(t *testing.T) {
	tests := []struct {
		name   string
		id     LimitID
		wantOK bool
		wantID LimitID
	}{
		{name: "known", id: LimitContainmentUnproven, wantOK: true, wantID: LimitContainmentUnproven},
		{name: "unknown", id: LimitID("L-NOT-REAL"), wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ByID(tt.id)
			if ok != tt.wantOK {
				t.Fatalf("ByID(%s) ok = %v, want %v", tt.id, ok, tt.wantOK)
			}
			if tt.wantOK && got.ID != tt.wantID {
				t.Fatalf("ByID(%s) ID = %s, want %s", tt.id, got.ID, tt.wantID)
			}
		})
	}
}

func TestMustSummary(t *testing.T) {
	tests := []struct {
		name string
		id   LimitID
		want string
	}{
		{
			name: "known",
			id:   LimitContainmentUnproven,
			want: "L-CONTAINMENT-UNPROVEN: \"The boundary is the witness\" holds only under attested containment; the binary alone cannot prove non-bypass.",
		},
		{name: "unknown fallback", id: LimitID("L-NOT-REAL"), want: "L-NOT-REAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MustSummary(tt.id); got != tt.want {
				t.Fatalf("MustSummary(%s) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}
