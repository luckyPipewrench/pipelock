// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestToCycloneDX(t *testing.T) {
	b := NewBuilder("s1", "mcp_stdio")
	b.SetStartedAt(time.Now())
	b.SetMode("strict")
	b.SetConfigHash("sha256:abc123")
	b.AddDeclaredTool("exec", "Execute commands")
	b.AddDeclaredTool("read_file", "Read file contents")
	m := b.Build()

	bom := ToCycloneDX(m)

	if bom.SpecVersion != cdx.SpecVersion1_6 {
		t.Errorf("spec version: got %v, want %v", bom.SpecVersion, cdx.SpecVersion1_6)
	}
	if bom.Metadata == nil {
		t.Fatal("expected metadata")
	}
	if bom.Metadata.Timestamp == "" {
		t.Fatal("metadata timestamp should be set")
	}
	if bom.Components == nil {
		t.Fatal("expected components")
	}
	if got := len(*bom.Components); got != 2 {
		t.Fatalf("expected 2 components for tools, got %d", got)
	}
}

func TestToCycloneDX_UsesDeclaredTools(t *testing.T) {
	b := NewBuilder("s1", "fetch")
	b.AddDeclaredTool("exec", "")
	b.AddObservedTool("exec")
	b.AddObservedTool("unlisted")
	m := b.Build()

	bom := ToCycloneDX(m)
	if bom.Components == nil {
		t.Fatal("components should not be nil")
	}
	if len(*bom.Components) != 1 {
		t.Fatalf("expected only declared tools in components, got %d", len(*bom.Components))
	}
	if (*bom.Components)[0].Name != "exec" {
		t.Fatalf("unexpected tool component %q", (*bom.Components)[0].Name)
	}
}

func TestToCycloneDX_ZeroStartedAt(t *testing.T) {
	m := NewBuilder("s1", "mcp_http").Build()
	bom := ToCycloneDX(m)
	if bom.Metadata == nil || bom.Metadata.Timestamp == "" {
		t.Fatal("metadata timestamp should be set when started_at is zero")
	}
}
