// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package manifest provides the unified session manifest substrate used by
// evidence, replay, and attestation features.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"
)

// SchemaVersion is the current manifest schema version.
const SchemaVersion = 1

// Manifest captures a versioned session snapshot for evidence workflows.
type Manifest struct {
	SchemaVersion  int            `json:"schema_version"`
	SessionID      string         `json:"session_id"`
	StartedAt      time.Time      `json:"started_at"`
	Transport      string         `json:"transport"`
	AgentIdentity  string         `json:"agent_identity,omitempty"`
	Policy         PolicySnapshot `json:"policy"`
	Tools          ToolInventory  `json:"tools"`
	VerdictSummary VerdictSummary `json:"verdicts_summary"`
	Fingerprint    string         `json:"behavioral_fingerprint,omitempty"`
}

// PolicySnapshot captures the active policy state at session start.
type PolicySnapshot struct {
	ConfigHash     string   `json:"config_hash"`
	Mode           string   `json:"mode"`
	ActiveFeatures []string `json:"active_features"`
}

// ToolInventory tracks declared and observed tool usage.
type ToolInventory struct {
	Declared []DeclaredTool `json:"declared"`
	Observed []string       `json:"observed"`
}

// DeclaredTool is a tool from the initial tool list.
type DeclaredTool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// VerdictSummary tracks decision totals by action.
type VerdictSummary struct {
	Total      int `json:"total"`
	Blocked    int `json:"blocked"`
	Allowed    int `json:"allowed"`
	Asked      int `json:"asked"`
	Warned     int `json:"warned"`
	Redirected int `json:"redirected"`
	Stripped   int `json:"stripped"`
}

// Builder incrementally constructs a Manifest. All methods are safe for
// concurrent use.
type Builder struct {
	mu       sync.Mutex
	manifest Manifest
}

// NewBuilder returns a new builder for the session and transport.
func NewBuilder(sessionID, transport string) *Builder {
	return &Builder{
		manifest: Manifest{
			SchemaVersion: SchemaVersion,
			SessionID:     sessionID,
			Transport:     transport,
		},
	}
}

// SetStartedAt records session start time.
func (b *Builder) SetStartedAt(t time.Time) {
	b.mu.Lock()
	b.manifest.StartedAt = t.UTC()
	b.mu.Unlock()
}

// SetConfigHash records the config hash for the session.
func (b *Builder) SetConfigHash(hash string) {
	b.mu.Lock()
	b.manifest.Policy.ConfigHash = hash
	b.mu.Unlock()
}

// SetMode records the active policy mode.
func (b *Builder) SetMode(mode string) {
	b.mu.Lock()
	b.manifest.Policy.Mode = mode
	b.mu.Unlock()
}

// SetAgentIdentity records the resolved agent identity.
func (b *Builder) SetAgentIdentity(name string) {
	b.mu.Lock()
	b.manifest.AgentIdentity = name
	b.mu.Unlock()
}

// AddActiveFeature records an active feature, deduplicated.
func (b *Builder) AddActiveFeature(feature string) {
	if feature == "" {
		return
	}
	b.mu.Lock()
	b.manifest.Policy.ActiveFeatures = appendUniqueString(b.manifest.Policy.ActiveFeatures, feature)
	b.mu.Unlock()
}

// AddDeclaredTool records a declared tool by name.
func (b *Builder) AddDeclaredTool(name, description string) {
	if name == "" {
		return
	}
	b.mu.Lock()
	b.manifest.Tools.Declared = append(b.manifest.Tools.Declared, DeclaredTool{
		Name:        name,
		Description: description,
	})
	b.mu.Unlock()
}

// AddObservedTool records an observed tool invocation, deduplicated by name.
func (b *Builder) AddObservedTool(name string) {
	if name == "" {
		return
	}
	b.mu.Lock()
	b.manifest.Tools.Observed = appendUniqueString(b.manifest.Tools.Observed, name)
	b.mu.Unlock()
}

// RecordVerdict increments action counters.
func (b *Builder) RecordVerdict(action string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.manifest.VerdictSummary.Total++
	switch action {
	case "block":
		b.manifest.VerdictSummary.Blocked++
	case "allow":
		b.manifest.VerdictSummary.Allowed++
	case "ask":
		b.manifest.VerdictSummary.Asked++
	case "warn":
		b.manifest.VerdictSummary.Warned++
	case "redirect":
		b.manifest.VerdictSummary.Redirected++
	case "strip":
		b.manifest.VerdictSummary.Stripped++
	}
}

// Build returns a snapshot Manifest and computes a deterministic fingerprint.
func (b *Builder) Build() Manifest {
	b.mu.Lock()
	defer b.mu.Unlock()

	m := b.manifest
	m.Policy.ActiveFeatures = append([]string(nil), b.manifest.Policy.ActiveFeatures...)
	m.Tools.Declared = append([]DeclaredTool(nil), b.manifest.Tools.Declared...)
	m.Tools.Observed = append([]string(nil), b.manifest.Tools.Observed...)
	m.Fingerprint = computeFingerprint(m)
	return m
}

// Validate checks required fields and schema compatibility.
func (m Manifest) Validate() error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %d (expected %d)", m.SchemaVersion, SchemaVersion)
	}
	if m.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}
	if m.Transport == "" {
		return fmt.Errorf("transport is required")
	}
	return nil
}

// Parse decodes and validates a manifest JSON blob.
func Parse(data []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("unmarshal manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func computeFingerprint(m Manifest) string {
	observed := append([]string(nil), m.Tools.Observed...)
	features := append([]string(nil), m.Policy.ActiveFeatures...)
	slices.Sort(observed)
	slices.Sort(features)

	data, err := json.Marshal(struct {
		Observed []string       `json:"observed_tools"`
		Features []string       `json:"active_features"`
		Verdicts VerdictSummary `json:"verdicts"`
	}{
		Observed: observed,
		Features: features,
		Verdicts: m.VerdictSummary,
	})
	if err != nil {
		return ""
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func appendUniqueString(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
