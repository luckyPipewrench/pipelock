// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package sarif generates SARIF 2.1.0 output for GitHub Code Scanning.
// SARIF (Static Analysis Results Interchange Format) is the standard
// for uploading findings to GitHub's upload-sarif action.
package sarif

import (
	"encoding/json"
	"io"
)

const sarifVersion = "2.1.0"

// Log is the top-level SARIF container.
type Log struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single tool execution.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results,omitempty"`
}

// Tool identifies the analysis tool.
type Tool struct {
	Driver ToolComponent `json:"driver"`
}

// ToolComponent describes the tool and its rules.
type ToolComponent struct {
	Name           string                `json:"name"`
	Version        string                `json:"version,omitempty"`
	InformationURI string                `json:"informationUri,omitempty"`
	Rules          []ReportingDescriptor `json:"rules,omitempty"`
}

// ReportingDescriptor defines a detection rule.
type ReportingDescriptor struct {
	ID               string  `json:"id"`
	ShortDescription Message `json:"shortDescription"`
	HelpURI          string  `json:"helpUri,omitempty"`
}

// Result is a single finding.
type Result struct {
	RuleID    string     `json:"ruleId"`
	RuleIndex int        `json:"ruleIndex"`
	Message   Message    `json:"message"`
	Level     string     `json:"level"`
	Locations []Location `json:"locations,omitempty"`
}

// Location pinpoints a finding in a file.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation is the file and region.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation is a file path relative to the repo root.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region describes a line span in a file.
type Region struct {
	StartLine int      `json:"startLine"`
	Snippet   *Snippet `json:"snippet,omitempty"`
}

// Snippet holds a code fragment for context.
type Snippet struct {
	Text string `json:"text"`
}

// Message is a human-readable string.
type Message struct {
	Text string `json:"text"`
}

// SeverityToLevel maps pipelock severity strings to SARIF levels.
func SeverityToLevel(severity string) string {
	switch severity {
	case "critical":
		return "error"
	case "warning":
		return "warning"
	default:
		return "note"
	}
}

// New creates a SARIF Log with tool metadata.
func New(toolName, version string) *Log {
	return &Log{
		Version: sarifVersion,
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []Run{{
			Tool: Tool{
				Driver: ToolComponent{
					Name:           toolName,
					Version:        version,
					InformationURI: "https://github.com/luckyPipewrench/pipelock",
				},
			},
		}},
	}
}

// AddRule registers a detection rule and returns its index.
func (l *Log) AddRule(id, description string) int {
	rules := l.Runs[0].Tool.Driver.Rules
	// Deduplicate: return existing index if rule already registered.
	for i, r := range rules {
		if r.ID == id {
			return i
		}
	}
	idx := len(rules)
	l.Runs[0].Tool.Driver.Rules = append(l.Runs[0].Tool.Driver.Rules, ReportingDescriptor{
		ID:               id,
		ShortDescription: Message{Text: description},
		HelpURI:          "https://github.com/luckyPipewrench/pipelock",
	})
	return idx
}

// AddResult appends a finding to the run.
func (l *Log) AddResult(ruleID string, ruleIndex int, level, message, file string, line int, snippet string) {
	r := Result{
		RuleID:    ruleID,
		RuleIndex: ruleIndex,
		Message:   Message{Text: message},
		Level:     level,
	}
	if file != "" {
		loc := Location{
			PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: file},
			},
		}
		if line > 0 {
			loc.PhysicalLocation.Region = &Region{StartLine: line}
			if snippet != "" {
				loc.PhysicalLocation.Region.Snippet = &Snippet{Text: snippet}
			}
		}
		r.Locations = []Location{loc}
	}
	l.Runs[0].Results = append(l.Runs[0].Results, r)
}

// Write serializes the SARIF log as indented JSON.
func (l *Log) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(l)
}
