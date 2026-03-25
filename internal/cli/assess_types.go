// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/discover"
)

// Schema and scoring version constants.
const (
	assessSchemaVersion   = "1"
	assessScoringVersion  = "1"
	assessRendererVersion = "1.0"
)

// Status constants for AssessManifest.Status.
const (
	assessStatusInitialized = "initialized"
	assessStatusRunning     = "running"
	assessStatusCompleted   = "completed"
	assessStatusFinalized   = "finalized"
	assessStatusFailed      = "failed"
)

// License tier sentinel values for AssessManifest.LicenseTier.
const (
	assessTierFree       = "free"
	assessTierAssess     = "assess"
	assessTierPro        = "pro"
	assessTierEnterprise = "enterprise"
)

// Finding severity constants.
const (
	assessSevCritical = "critical"
	assessSevHigh     = "high"
	assessSevMedium   = "medium"
	assessSevLow      = "low"
	assessSevInfo     = "info"
)

// Grade constants.
const (
	assessGradeA = "A"
	assessGradeB = "B"
	assessGradeC = "C"
	assessGradeD = "D"
	assessGradeF = "F"
)

// Section ID constants.
const (
	sectionDetectionCoverage      = "detection_coverage"
	sectionConfigPosture          = "config_posture"
	sectionDeploymentVerification = "deployment_verification"
	sectionMCPProtection          = "mcp_protection"
)

// Scoring weight constants.
const (
	weightDetectionCoverage      = 25
	weightConfigPosture          = 25
	weightDeploymentVerification = 30
	weightMCPProtection          = 20
)

// AssessManifest carries identity and provenance metadata for an assessment run.
type AssessManifest struct {
	SchemaVersion     string            `json:"schema_version"`
	Version           string            `json:"version"`
	BuildSHA          string            `json:"build_sha"`
	RunID             string            `json:"run_id"`
	ConfigFile        string            `json:"config_file"`
	ConfigHash        string            `json:"config_hash"`
	ConfigDrifted     bool              `json:"config_drifted,omitempty"`
	LicenseTier       string            `json:"license_tier"`
	StartedAt         time.Time         `json:"started_at"`
	CompletedAt       *time.Time        `json:"completed_at,omitempty"`
	FinalizedAt       *time.Time        `json:"finalized_at,omitempty"`
	FailedAt          *time.Time        `json:"failed_at,omitempty"`
	FailureReason     string            `json:"failure_reason,omitempty"`
	GitCommit         string            `json:"git_commit,omitempty"`
	Platform          string            `json:"platform"`
	Status            string            `json:"status"`
	SkippedPrimitives []string          `json:"skipped_primitives,omitempty"`
	AllowPartial      bool              `json:"allow_partial,omitempty"`
	RendererVersion   string            `json:"renderer_version"`
	ScoringVersion    string            `json:"scoring_version"`
	Artifacts         map[string]string `json:"artifacts,omitempty"`
}

// Assessment is the full, attestable assessment output.
type Assessment struct {
	SchemaVersion string              `json:"schema_version"`
	Manifest      AssessManifest      `json:"manifest"`
	OverallGrade  string              `json:"overall_grade"`
	OverallScore  int                 `json:"overall_score"`
	GradeCap      string              `json:"grade_cap,omitempty"`
	CapReasons    []CapReason         `json:"cap_reasons,omitempty"`
	Weights       ScoringWeights      `json:"weights"`
	Sections      []AssessmentSection `json:"sections"`
	Findings      []Finding           `json:"findings"`
	Sources       AssessSources       `json:"sources"`
	Annexes       []Annex             `json:"annexes,omitempty"`
}

// Summary is the compact, human-readable assessment projection.
type Summary struct {
	SchemaVersion string                `json:"schema_version"`
	Manifest      AssessManifest        `json:"manifest"`
	OverallGrade  string                `json:"overall_grade"`
	OverallScore  int                   `json:"overall_score"`
	GradeCap      string                `json:"grade_cap,omitempty"`
	Sections      []AssessmentSection   `json:"sections"`
	TopFindings   []SummaryFinding      `json:"top_findings"`
	ServerCounts  AssessDiscoverSummary `json:"server_counts"`
	DetectionPct  int                   `json:"detection_pct"`
	Signed        bool                  `json:"signed"`
}

// ScoringWeights holds the weight for each assessment section.
type ScoringWeights struct {
	DetectionCoverage      int `json:"detection_coverage"`
	ConfigPosture          int `json:"config_posture"`
	DeploymentVerification int `json:"deployment_verification"`
	MCPProtection          int `json:"mcp_protection"`
}

// CapReason records why the overall grade was capped below its raw score.
type CapReason struct {
	Cap        string `json:"cap"`
	Reason     string `json:"reason"`
	Source     string `json:"source"`
	EvidenceID string `json:"evidence_id"`
}

// AssessmentSection holds scored results for one assessment dimension.
type AssessmentSection struct {
	SchemaVersion string `json:"schema_version"`
	ID            string `json:"id"`
	Name          string `json:"name"`
	Score         int    `json:"score"`
	MaxScore      int    `json:"max_score"`
	Grade         string `json:"grade"`
	Detail        string `json:"detail,omitempty"`
	Applicable    int    `json:"applicable"`
	Total         int    `json:"total"`
}

// Finding is a single security or configuration finding from the assessment.
//
// Evidence must be nil (omitted) or a valid JSON value — never json.RawMessage("null").
type Finding struct {
	SchemaVersion string          `json:"schema_version"`
	ID            string          `json:"id"`
	Severity      string          `json:"severity"`
	Category      string          `json:"category"`
	Source        string          `json:"source"`
	Title         string          `json:"title"`
	Detail        string          `json:"detail,omitempty"`
	Remediation   string          `json:"remediation,omitempty"`
	Evidence      json.RawMessage `json:"evidence,omitempty"`
}

// SummaryFinding is the minimal projection of a Finding for the Summary output.
// Detail, Remediation, and Evidence are deliberately excluded.
type SummaryFinding struct {
	SchemaVersion string `json:"schema_version"`
	ID            string `json:"id"`
	Severity      string `json:"severity"`
	Category      string `json:"category"`
	Source        string `json:"source"`
	Title         string `json:"title"`
}

// Annex references a supplementary artifact attached to the assessment.
type Annex struct {
	SchemaVersion string `json:"schema_version"`
	ID            string `json:"id"`
	Name          string `json:"name"`
}

// AssessSources bundles the raw outputs from each assessment primitive.
type AssessSources struct {
	SchemaVersion string                `json:"schema_version"`
	Simulate      *SimulateResult       `json:"simulate,omitempty"`
	AuditScore    *ScoreResult          `json:"audit_score,omitempty"`
	VerifyInstall *VerifyReport         `json:"verify_install,omitempty"`
	Discover      *AssessDiscoverReport `json:"discover,omitempty"`
}

// AssessDiscoverReport is a versioned wrapper around the discover output.
type AssessDiscoverReport struct {
	SchemaVersion string                 `json:"schema_version"`
	ScannedRoot   string                 `json:"scanned_root"`
	Clients       []AssessDiscoverClient `json:"clients"`
	Servers       []AssessDiscoverServer `json:"servers"`
	Summary       AssessDiscoverSummary  `json:"summary"`
}

// AssessDiscoverClient is a versioned wrapper around a discovered client config.
type AssessDiscoverClient struct {
	discover.ClientConfig
	SchemaVersion string `json:"schema_version"`
}

// AssessDiscoverServer is a versioned wrapper around a discovered MCP server.
type AssessDiscoverServer struct {
	discover.MCPServer
	SchemaVersion string `json:"schema_version"`
}

// AssessDiscoverSummary is a versioned wrapper around discover aggregate counts.
type AssessDiscoverSummary struct {
	discover.Summary
	SchemaVersion string `json:"schema_version"`
}

// defaultScoringWeights returns the canonical scoring weights for an assessment.
func defaultScoringWeights() ScoringWeights {
	return ScoringWeights{
		DetectionCoverage:      weightDetectionCoverage,
		ConfigPosture:          weightConfigPosture,
		DeploymentVerification: weightDeploymentVerification,
		MCPProtection:          weightMCPProtection,
	}
}

// sortAssessmentSections sorts sections by ID alphabetically.
func sortAssessmentSections(sections []AssessmentSection) {
	sort.Slice(sections, func(i, j int) bool {
		return sections[i].ID < sections[j].ID
	})
}

// sortFindings sorts by severity descending (critical first), then ID alphabetical.
func sortFindings(findings []Finding) {
	sevOrder := map[string]int{
		assessSevCritical: 0,
		assessSevHigh:     1,
		assessSevMedium:   2,
		assessSevLow:      3,
		assessSevInfo:     4,
	}
	sort.Slice(findings, func(i, j int) bool {
		si, sj := sevOrder[findings[i].Severity], sevOrder[findings[j].Severity]
		if si != sj {
			return si < sj
		}
		return findings[i].ID < findings[j].ID
	})
}

// gradeFromPercentage returns a letter grade. Shared by simulate, audit, and assess.
func gradeFromPercentage(pct int) string {
	switch {
	case pct >= 90:
		return assessGradeA
	case pct >= 80:
		return assessGradeB
	case pct >= 70:
		return assessGradeC
	case pct >= 60:
		return assessGradeD
	default:
		return assessGradeF
	}
}
