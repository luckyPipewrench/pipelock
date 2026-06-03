// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package skillscan inventories local agent skill files and flags drift, direct
// source-to-sink transfers, and bounded advisory co-occurrences. It is static
// defense-in-depth; the runtime proxy remains the enforcement layer.
package skillscan

import (
	"errors"
	"fmt"
)

const (
	SchemaVersion = "v1"

	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"

	CapabilityNetworkSink     CapabilityKind = "network_sink"
	CapabilityFilesystemWrite CapabilityKind = "filesystem_write"
	CapabilityExecSubprocess  CapabilityKind = "exec_subprocess"
	CapabilityEnvRead         CapabilityKind = "env_read"
	CapabilitySecretRead      CapabilityKind = "secret_read"
	CapabilityClipboardRead   CapabilityKind = "clipboard_read"
	CapabilityDependencyPull  CapabilityKind = "dependency_install"

	FindingDrift       FindingKind = "changed"
	FindingCombination FindingKind = "combination"
	FindingHidden      FindingKind = "hidden_instruction"
	FindingAllowlist   FindingKind = "stale_allowlist"
	FindingOversize    FindingKind = "oversize"

	// Direct combos are provable on a single command/expression: the source
	// and sink match the same line, so the dangerous data flow or target is
	// visible in one place. These keep an assertive name and severity.
	ComboCredentialExfil ComboKind = "credential" + "-exfil"
	ComboGuardWrite      ComboKind = "guard-file-write"
	ComboShellWrite      ComboKind = "shell-init-write"
	ComboCronWrite       ComboKind = "scheduled-task-write"
	ComboClipboardExfil  ComboKind = "clipboard-network-transfer"

	// Co-occurrence combos are a heuristic: the source and sink appear in the
	// same executable region within a small line window but no direct transfer
	// is proven. They are named honestly and scored one tier lower so they are
	// advisory, never an assertion of exfiltration.
	ComboCredentialCooccur ComboKind = "credential" + "-network-cooccurrence"
	ComboGuardCooccur      ComboKind = "guard-file-write-cooccurrence"
	ComboShellCooccur      ComboKind = "shell-init-write-cooccurrence"
	ComboCronCooccur       ComboKind = "scheduled-task-write-cooccurrence"
	ComboClipboardCooccur  ComboKind = "clipboard-network-cooccurrence"
)

var ErrFindings = errors.New("skill-scan findings detected")

type (
	Severity       string
	CapabilityKind string
	FindingKind    string
	ComboKind      string
)

type Options struct {
	Paths         []string
	LockFile      string
	AllowlistFile string
	Baseline      bool
	Update        bool
	IncludeDeps   bool
	InventoryOnly bool
}

type Evidence struct {
	Path    string `json:"path" yaml:"path"`
	Line    int    `json:"line" yaml:"line"`
	Pattern string `json:"pattern" yaml:"pattern"`
}

func (e Evidence) String() string {
	if e.Line <= 0 {
		return e.Path
	}
	return fmt.Sprintf("%s:%d %s", e.Path, e.Line, e.Pattern)
}

type Capability struct {
	Kind     CapabilityKind `json:"kind" yaml:"kind"`
	Evidence []Evidence     `json:"evidence" yaml:"evidence"`
}

type ReferencedFile struct {
	Path   string `json:"path" yaml:"path"`
	SHA256 string `json:"sha256" yaml:"sha256"`
	Mode   string `json:"mode" yaml:"mode"`
}

// Combo is a detected direct transfer or advisory co-occurrence carried on a
// Skill so it can be fingerprinted into the lock baseline and reported as a
// finding.
type Combo struct {
	Kind        ComboKind  `json:"kind" yaml:"kind"`
	Severity    Severity   `json:"severity" yaml:"severity"`
	Direct      bool       `json:"direct" yaml:"direct"`
	RegionID    string     `json:"region_id" yaml:"region_id"`
	Fingerprint string     `json:"fingerprint" yaml:"fingerprint"`
	Message     string     `json:"message" yaml:"message"`
	Evidence    []Evidence `json:"evidence" yaml:"evidence"`
}

type Skill struct {
	ID              string           `json:"skill_id" yaml:"skill_id"`
	Path            string           `json:"skill_path" yaml:"skill_path"`
	SizeBytes       int64            `json:"size_bytes" yaml:"size_bytes"`
	ContentSHA256   string           `json:"content_sha256" yaml:"content_sha256"`
	ReferencedFiles []ReferencedFile `json:"referenced_files" yaml:"referenced_files"`
	Capabilities    []Capability     `json:"capabilities" yaml:"capabilities"`
	Combos          []Combo          `json:"combos,omitempty" yaml:"combos,omitempty"`
	ScannedFiles    []string         `json:"scanned_files" yaml:"scanned_files"`
}

type Finding struct {
	Kind        FindingKind `json:"kind" yaml:"kind"`
	Severity    Severity    `json:"severity" yaml:"severity"`
	SkillID     string      `json:"skill_id,omitempty" yaml:"skill_id,omitempty"`
	Combo       ComboKind   `json:"combo,omitempty" yaml:"combo,omitempty"`
	Fingerprint string      `json:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`
	Message     string      `json:"message" yaml:"message"`
	Evidence    []Evidence  `json:"evidence" yaml:"evidence"`
}

type Result struct {
	Skills       []Skill   `json:"skills" yaml:"skills"`
	Findings     []Finding `json:"findings" yaml:"findings"`
	FilesScanned int       `json:"files_scanned" yaml:"files_scanned"`
	LockFile     string    `json:"lock_file,omitempty" yaml:"lock_file,omitempty"`
}

func (r Result) GatedFindings(minSeverity Severity) []Finding {
	threshold := severityRank(minSeverity)
	var out []Finding
	for _, finding := range r.Findings {
		if severityRank(finding.Severity) >= threshold {
			out = append(out, finding)
		}
	}
	return out
}

func ValidateSeverity(s Severity) bool {
	return severityRank(s) > 0
}

func severityRank(s Severity) int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	default:
		return 0
	}
}
