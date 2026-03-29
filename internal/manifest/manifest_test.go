// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	testToolExec   = "exec"
	testValueDirty = "tampered"
)

func TestBuilder_Minimal(t *testing.T) {
	b := NewBuilder("session-123", "mcp_stdio")
	b.SetStartedAt(time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC))
	b.SetConfigHash("sha256:abc123")
	b.SetMode("enforce")

	m := b.Build()

	if m.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version: got %d, want %d", m.SchemaVersion, SchemaVersion)
	}
	if m.SessionID != "session-123" {
		t.Errorf("session_id: got %q", m.SessionID)
	}
	if m.Transport != "mcp_stdio" {
		t.Errorf("transport: got %q", m.Transport)
	}
	if m.Policy.ConfigHash != "sha256:abc123" {
		t.Errorf("config_hash: got %q", m.Policy.ConfigHash)
	}
	if err := m.Validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestBuilder_WithTools(t *testing.T) {
	b := NewBuilder("s1", "mcp_http")
	b.SetStartedAt(time.Now())
	b.AddDeclaredTool(testToolExec, "Execute commands")
	b.AddDeclaredTool("read_file", "Read file contents")
	b.AddObservedTool(testToolExec)
	b.AddObservedTool(testToolExec) // dedupe

	m := b.Build()

	if len(m.Tools.Declared) != 2 {
		t.Errorf("declared tools: got %d, want 2", len(m.Tools.Declared))
	}
	if len(m.Tools.Observed) != 1 {
		t.Errorf("observed tools: got %d, want 1", len(m.Tools.Observed))
	}
}

func TestBuilder_VerdictSummary(t *testing.T) {
	b := NewBuilder("s1", "fetch")
	b.SetStartedAt(time.Now())
	b.RecordVerdict("block")
	b.RecordVerdict("allow")
	b.RecordVerdict("allow")
	b.RecordVerdict("ask")
	b.RecordVerdict("redirect")
	b.RecordVerdict("strip")
	b.RecordVerdict("warn")

	m := b.Build()

	if m.VerdictSummary.Total != 7 {
		t.Errorf("total: got %d, want 7", m.VerdictSummary.Total)
	}
	if m.VerdictSummary.Blocked != 1 {
		t.Errorf("blocked: got %d, want 1", m.VerdictSummary.Blocked)
	}
	if m.VerdictSummary.Allowed != 2 {
		t.Errorf("allowed: got %d, want 2", m.VerdictSummary.Allowed)
	}
	if m.VerdictSummary.Asked != 1 {
		t.Errorf("asked: got %d, want 1", m.VerdictSummary.Asked)
	}
	if m.VerdictSummary.Redirected != 1 {
		t.Errorf("redirected: got %d, want 1", m.VerdictSummary.Redirected)
	}
	if m.VerdictSummary.Stripped != 1 {
		t.Errorf("stripped: got %d, want 1", m.VerdictSummary.Stripped)
	}
	if m.VerdictSummary.Warned != 1 {
		t.Errorf("warned: got %d, want 1", m.VerdictSummary.Warned)
	}
}

func TestManifest_JSON(t *testing.T) {
	b := NewBuilder("s1", "mcp_stdio")
	b.SetStartedAt(time.Now())
	b.SetConfigHash("sha256:def456")
	b.SetMode("balanced")
	b.AddActiveFeature("dlp")
	b.AddActiveFeature("tool_policy")
	m := b.Build()

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	decoded, err := Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if decoded.SchemaVersion != SchemaVersion {
		t.Errorf("round-trip schema_version: got %d", decoded.SchemaVersion)
	}
	if decoded.Policy.Mode != "balanced" {
		t.Errorf("round-trip mode: got %q", decoded.Policy.Mode)
	}
	if len(decoded.Policy.ActiveFeatures) != 2 {
		t.Errorf("round-trip features: got %d", len(decoded.Policy.ActiveFeatures))
	}
}

func TestBuilder_BuildDeepCopy(t *testing.T) {
	b := NewBuilder("s1", "mcp_stdio")
	b.AddActiveFeature("dlp")
	b.AddDeclaredTool(testToolExec, "")
	b.AddObservedTool(testToolExec)

	first := b.Build()
	first.Policy.ActiveFeatures[0] = testValueDirty
	first.Tools.Declared[0].Name = testValueDirty
	first.Tools.Observed[0] = testValueDirty

	second := b.Build()
	if second.Policy.ActiveFeatures[0] != "dlp" {
		t.Fatalf("active features mutated through snapshot")
	}
	if second.Tools.Declared[0].Name != testToolExec {
		t.Fatalf("declared tools mutated through snapshot")
	}
	if second.Tools.Observed[0] != testToolExec {
		t.Fatalf("observed tools mutated through snapshot")
	}
}

func TestBuilder_FingerprintStableAcrossInsertionOrder(t *testing.T) {
	b1 := NewBuilder("s1", "mcp_stdio")
	b1.AddObservedTool(testToolExec)
	b1.AddObservedTool("read_file")
	b1.AddActiveFeature("dlp")
	b1.AddActiveFeature("tool_policy")
	b1.RecordVerdict("allow")
	b1.RecordVerdict("block")

	b2 := NewBuilder("s1", "mcp_stdio")
	b2.AddObservedTool("read_file")
	b2.AddObservedTool(testToolExec)
	b2.AddActiveFeature("tool_policy")
	b2.AddActiveFeature("dlp")
	b2.RecordVerdict("allow")
	b2.RecordVerdict("block")

	m1 := b1.Build()
	m2 := b2.Build()
	if m1.Fingerprint == "" {
		t.Fatal("fingerprint should not be empty")
	}
	if m1.Fingerprint != m2.Fingerprint {
		t.Fatalf("fingerprints differ: %q vs %q", m1.Fingerprint, m2.Fingerprint)
	}
}

func TestBuilder_SetAgentIdentity(t *testing.T) {
	b := NewBuilder("s1", "mcp_stdio")
	b.SetAgentIdentity("agent-alpha")
	m := b.Build()
	if m.AgentIdentity != "agent-alpha" {
		t.Errorf("agent_identity: got %q, want %q", m.AgentIdentity, "agent-alpha")
	}

	// Overwrite with a different identity
	b.SetAgentIdentity("agent-beta")
	m2 := b.Build()
	if m2.AgentIdentity != "agent-beta" {
		t.Errorf("agent_identity after overwrite: got %q, want %q", m2.AgentIdentity, "agent-beta")
	}
}

func TestBuilder_AddActiveFeature_EmptyString(t *testing.T) {
	b := NewBuilder("s1", "mcp_stdio")
	b.AddActiveFeature("") // Should be silently ignored
	b.AddActiveFeature("dlp")
	m := b.Build()
	if len(m.Policy.ActiveFeatures) != 1 {
		t.Errorf("active features count: got %d, want 1 (empty string should be skipped)", len(m.Policy.ActiveFeatures))
	}
	if m.Policy.ActiveFeatures[0] != "dlp" {
		t.Errorf("first feature: got %q, want %q", m.Policy.ActiveFeatures[0], "dlp")
	}
}

func TestBuilder_AddActiveFeature_Dedup(t *testing.T) {
	b := NewBuilder("s1", "mcp_stdio")
	b.AddActiveFeature("dlp")
	b.AddActiveFeature("dlp") // duplicate
	b.AddActiveFeature("tool_policy")
	m := b.Build()
	if len(m.Policy.ActiveFeatures) != 2 {
		t.Errorf("expected 2 unique features, got %d", len(m.Policy.ActiveFeatures))
	}
}

func TestBuilder_AddDeclaredTool_EmptyName(t *testing.T) {
	b := NewBuilder("s1", "mcp_stdio")
	b.AddDeclaredTool("", "description") // Should be silently ignored
	b.AddDeclaredTool(testToolExec, "Execute commands")
	m := b.Build()
	if len(m.Tools.Declared) != 1 {
		t.Errorf("declared tools count: got %d, want 1 (empty name should be skipped)", len(m.Tools.Declared))
	}
}

func TestBuilder_AddObservedTool_EmptyName(t *testing.T) {
	b := NewBuilder("s1", "mcp_stdio")
	b.AddObservedTool("") // Should be silently ignored
	b.AddObservedTool(testToolExec)
	m := b.Build()
	if len(m.Tools.Observed) != 1 {
		t.Errorf("observed tools count: got %d, want 1 (empty name should be skipped)", len(m.Tools.Observed))
	}
}

func TestManifest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		m       Manifest
		wantErr string
	}{
		{
			name: "valid manifest",
			m: Manifest{
				SchemaVersion: SchemaVersion,
				SessionID:     "s1",
				Transport:     "mcp_stdio",
			},
			wantErr: "",
		},
		{
			name: "wrong schema version",
			m: Manifest{
				SchemaVersion: 99,
				SessionID:     "s1",
				Transport:     "mcp_stdio",
			},
			wantErr: "unsupported schema_version",
		},
		{
			name: "empty session_id",
			m: Manifest{
				SchemaVersion: SchemaVersion,
				SessionID:     "",
				Transport:     "mcp_stdio",
			},
			wantErr: "session_id is required",
		},
		{
			name: "empty transport",
			m: Manifest{
				SchemaVersion: SchemaVersion,
				SessionID:     "s1",
				Transport:     "",
			},
			wantErr: "transport is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.m.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
			}
		})
	}
}

func TestParse_Errors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "wrong schema version",
			data:    []byte(`{"schema_version":99,"session_id":"s1","transport":"mcp_stdio"}`),
			wantErr: "unsupported schema_version",
		},
		{
			name:    "invalid JSON",
			data:    []byte(`{not valid json`),
			wantErr: "unmarshal manifest",
		},
		{
			name:    "missing session_id",
			data:    []byte(`{"schema_version":1,"session_id":"","transport":"mcp_stdio"}`),
			wantErr: "session_id is required",
		},
		{
			name:    "missing transport",
			data:    []byte(`{"schema_version":1,"session_id":"s1","transport":""}`),
			wantErr: "transport is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.data)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestComputeFingerprint_Empty(t *testing.T) {
	// A manifest with no observed tools, no features, and zero verdicts
	// should still produce a valid fingerprint.
	b := NewBuilder("s1", "mcp_stdio")
	m := b.Build()
	if m.Fingerprint == "" {
		t.Fatal("fingerprint should not be empty even for minimal manifest")
	}
}

func TestBuilder_RecordVerdict_UnknownAction(t *testing.T) {
	// Unknown actions increment Total but no specific counter.
	b := NewBuilder("s1", "mcp_stdio")
	b.RecordVerdict("unknown_action")
	m := b.Build()
	if m.VerdictSummary.Total != 1 {
		t.Errorf("total: got %d, want 1", m.VerdictSummary.Total)
	}
	if m.VerdictSummary.Blocked != 0 || m.VerdictSummary.Allowed != 0 ||
		m.VerdictSummary.Asked != 0 || m.VerdictSummary.Warned != 0 ||
		m.VerdictSummary.Redirected != 0 || m.VerdictSummary.Stripped != 0 {
		t.Error("no specific counter should be incremented for unknown action")
	}
}
