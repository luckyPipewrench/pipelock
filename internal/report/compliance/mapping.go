// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package compliance provides structured coverage mappings between Pipelock
// capabilities and external security frameworks.
//
// These mappings are control mapping + evidence generation, not compliance
// claims. The package records which controls Pipelock addresses and what
// evidence the product can emit.
package compliance

import "fmt"

// Coverage status constants.
const (
	StatusCovered    = "covered"
	StatusPartial    = "partial"
	StatusNotCovered = "not_covered"
)

// Framework is a versioned security framework with control mappings.
type Framework struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	Version        string           `json:"version"`
	MappingVersion int              `json:"mapping_version"`
	URL            string           `json:"url,omitempty"`
	Controls       []ControlMapping `json:"controls"`
}

// ControlMapping maps one framework control to Pipelock features.
type ControlMapping struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Status     string   `json:"status"`
	Features   []string `json:"features,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`
	Limitation string   `json:"limitation,omitempty"`
}

// CoverageSummary is the aggregate coverage for a framework.
type CoverageSummary struct {
	FrameworkID    string `json:"framework_id"`
	FrameworkName  string `json:"framework_name"`
	MappingVersion int    `json:"mapping_version"`
	Total          int    `json:"total"`
	Covered        int    `json:"covered"`
	Partial        int    `json:"partial"`
	NotCovered     int    `json:"not_covered"`
}

// CoverageSummary computes the aggregate coverage for this framework.
func (f Framework) CoverageSummary() CoverageSummary {
	summary := CoverageSummary{
		FrameworkID:    f.ID,
		FrameworkName:  f.Name,
		MappingVersion: f.MappingVersion,
		Total:          len(f.Controls),
	}
	for _, c := range f.Controls {
		switch c.Status {
		case StatusCovered:
			summary.Covered++
		case StatusPartial:
			summary.Partial++
		default:
			summary.NotCovered++
		}
	}
	return summary
}

// CoverageText returns the terse, teaser-safe coverage phrase used in the
// free summary and attestation badge.
func (f Framework) CoverageText() string {
	return f.CoverageSummary().CoverageText()
}

// CoverageText renders a short "N/M covered" phrase.
func (s CoverageSummary) CoverageText() string {
	return fmt.Sprintf("%d/%d covered", s.Covered, s.Total)
}

// CoverageStatus returns the dominant coverage status for badge coloring.
// All covered = "covered", any not-covered = "not_covered", else "partial".
func (f Framework) CoverageStatus() string {
	s := f.CoverageSummary()
	if s.NotCovered > 0 {
		return StatusNotCovered
	}
	if s.Partial > 0 {
		return StatusPartial
	}
	return StatusCovered
}
