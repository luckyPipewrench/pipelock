// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Bundle represents a parsed and validated rule bundle.
type Bundle struct {
	FormatVersion int    `yaml:"format_version"`
	Name          string `yaml:"name"`
	Version       string `yaml:"version"`
	Author        string `yaml:"author"`
	Description   string `yaml:"description"`
	Homepage      string `yaml:"homepage"`
	MinPipelock   string `yaml:"min_pipelock"`
	License       string `yaml:"license"`
	Rules         []Rule `yaml:"rules"`
}

// Rule represents a single detection rule within a bundle.
type Rule struct {
	ID          string      `yaml:"id"`
	Type        string      `yaml:"type"`
	Status      string      `yaml:"status"`
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Severity    string      `yaml:"severity"`
	Confidence  string      `yaml:"confidence"`
	References  []string    `yaml:"references"`
	Tags        []string    `yaml:"tags"`
	Pattern     RulePattern `yaml:"pattern"`
}

// RulePattern holds type-specific detection payload.
type RulePattern struct {
	Regex         string   `yaml:"regex"`
	ExemptDomains []string `yaml:"exempt_domains"`
	ScanField     string   `yaml:"scan_field"`
}

// Rule type constants.
const (
	RuleTypeDLP        = "dlp"
	RuleTypeInjection  = "injection"
	RuleTypeToolPoison = "tool-poison"
)

// Rule status constants.
const (
	StatusExperimental = "experimental"
	StatusStable       = "stable"
	StatusDeprecated   = "deprecated"
)

// Severity constants for rule validation. These are independent of the config
// package severity constants because rule bundles use a different set (no
// info/warn, but includes low).
const (
	severityCritical = "critical"
	severityHigh     = "high"
	severityMedium   = "medium"
	severityLow      = "low"
)

// Confidence constants for rule validation.
const (
	confidenceHigh   = "high"
	confidenceMedium = "medium"
	confidenceLow    = "low"
)

// Bundle size and count limits.
const (
	MaxBundleFileSize = 1 << 20 // 1 MB
	MaxRuleCount      = 1000
	MaxRegexLength    = 4096
	MaxBundleNameLen  = 64
	MaxRuleIDLen      = 96
	MinNameLen        = 3
	MinRuleIDLen      = 3
	MaxFormatVersion  = 1
)

// Scan field constants for tool-poison rules.
const (
	scanFieldDescription = "description"
	scanFieldName        = "name"
)

// Compiled validation patterns for bundle names and rule IDs.
// Bundle name: 3-64 chars, lowercase alphanumeric + hyphens, no leading/trailing hyphen.
var bundleNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`)

// Rule ID: 3-96 chars, lowercase alphanumeric + hyphens, no leading/trailing hyphen.
var ruleIDRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,94}[a-z0-9]$`)

// Valid enum sets for quick membership checks.
var validRuleTypes = map[string]bool{
	RuleTypeDLP:        true,
	RuleTypeInjection:  true,
	RuleTypeToolPoison: true,
}

var validStatuses = map[string]bool{
	StatusExperimental: true,
	StatusStable:       true,
	StatusDeprecated:   true,
}

var validSeverities = map[string]bool{
	severityCritical: true,
	severityHigh:     true,
	severityMedium:   true,
	severityLow:      true,
}

var validConfidences = map[string]bool{
	confidenceHigh:   true,
	confidenceMedium: true,
	confidenceLow:    true,
}

var validScanFields = map[string]bool{
	scanFieldDescription: true,
	scanFieldName:        true,
}

// ParseBundle unmarshals YAML data into a Bundle and validates it.
// Unknown fields at any nesting level are rejected.
func ParseBundle(data []byte) (*Bundle, error) {
	var b Bundle

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	if err := decoder.Decode(&b); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}

	if err := b.Validate(); err != nil {
		return nil, err
	}

	return &b, nil
}

// Validate performs comprehensive validation of a Bundle.
func (b *Bundle) Validate() error {
	if b.FormatVersion != MaxFormatVersion {
		return fmt.Errorf("validate bundle: format_version must be %d, got %d", MaxFormatVersion, b.FormatVersion)
	}

	if err := ValidateBundleName(b.Name); err != nil {
		return fmt.Errorf("validate bundle: name: %w", err)
	}

	if _, err := ParseCalVer(b.Version); err != nil {
		return fmt.Errorf("validate bundle: version: %w", err)
	}

	if b.Author == "" {
		return fmt.Errorf("validate bundle: author must not be empty")
	}

	if b.Description == "" {
		return fmt.Errorf("validate bundle: description must not be empty")
	}

	if len(b.Rules) > MaxRuleCount {
		return fmt.Errorf("validate bundle: %d rules exceeds maximum of %d", len(b.Rules), MaxRuleCount)
	}

	seen := make(map[string]bool, len(b.Rules))

	for i := range b.Rules {
		if err := validateRule(&b.Rules[i], seen); err != nil {
			return fmt.Errorf("validate bundle: rule[%d]: %w", i, err)
		}
	}

	return nil
}

// validateRule validates a single rule and checks for duplicate IDs.
func validateRule(r *Rule, seen map[string]bool) error {
	if err := ValidateRuleID(r.ID); err != nil {
		return fmt.Errorf("id: %w", err)
	}

	if seen[r.ID] {
		return fmt.Errorf("duplicate rule id %q", r.ID)
	}
	seen[r.ID] = true

	if !validRuleTypes[r.Type] {
		return fmt.Errorf("invalid type %q for rule %q", r.Type, r.ID)
	}

	if !validStatuses[r.Status] {
		return fmt.Errorf("invalid status %q for rule %q", r.Status, r.ID)
	}

	if r.Name == "" {
		return fmt.Errorf("name must not be empty for rule %q", r.ID)
	}

	if r.Description == "" {
		return fmt.Errorf("description must not be empty for rule %q", r.ID)
	}

	if !validSeverities[r.Severity] {
		return fmt.Errorf("invalid severity %q for rule %q", r.Severity, r.ID)
	}

	if !validConfidences[r.Confidence] {
		return fmt.Errorf("invalid confidence %q for rule %q", r.Confidence, r.ID)
	}

	if err := validatePattern(&r.Pattern, r.Type, r.ID); err != nil {
		return err
	}

	return nil
}

// validatePattern validates a rule's pattern fields based on rule type.
func validatePattern(p *RulePattern, ruleType, ruleID string) error {
	if p.Regex == "" {
		return fmt.Errorf("regex must not be empty for rule %q", ruleID)
	}

	if len(p.Regex) > MaxRegexLength {
		return fmt.Errorf("regex length %d exceeds maximum of %d for rule %q", len(p.Regex), MaxRegexLength, ruleID)
	}

	if _, err := regexp.Compile(p.Regex); err != nil {
		return fmt.Errorf("invalid regex for rule %q: %w", ruleID, err)
	}

	// exempt_domains is only valid for DLP rules.
	if len(p.ExemptDomains) > 0 && ruleType != RuleTypeDLP {
		return fmt.Errorf("exempt_domains is only valid for %s rules, not %s (rule %q)", RuleTypeDLP, ruleType, ruleID)
	}

	// scan_field validation for tool-poison rules.
	if ruleType == RuleTypeToolPoison {
		if p.ScanField == "" {
			// Default to "description" if empty.
			p.ScanField = scanFieldDescription
		} else if !validScanFields[p.ScanField] {
			return fmt.Errorf("invalid scan_field %q for rule %q (must be %q or %q)", p.ScanField, ruleID, scanFieldDescription, scanFieldName)
		}
	}

	return nil
}

// ValidateBundleName validates a bundle name against the naming convention:
// 3-64 chars, lowercase alphanumeric + hyphens, no leading/trailing hyphen.
func ValidateBundleName(name string) error {
	if !bundleNameRegex.MatchString(name) {
		return fmt.Errorf("bundle name %q must match %s (3-%d lowercase alphanumeric chars and hyphens, no leading/trailing hyphen)",
			name, bundleNameRegex.String(), MaxBundleNameLen)
	}
	return nil
}

// ValidateRuleID validates a rule ID against the naming convention:
// 3-96 chars, lowercase alphanumeric + hyphens, no leading/trailing hyphen.
func ValidateRuleID(id string) error {
	if !ruleIDRegex.MatchString(id) {
		return fmt.Errorf("rule id %q must match %s (3-%d lowercase alphanumeric chars and hyphens, no leading/trailing hyphen)",
			id, ruleIDRegex.String(), MaxRuleIDLen)
	}
	return nil
}

// NamespacedID returns a namespaced rule identifier in "bundleName:ruleID" format.
func NamespacedID(bundleName, ruleID string) string {
	return bundleName + ":" + ruleID
}

// CheckMinPipelock verifies that currentVersion meets the minimum required
// pipelock version. If minVersion is empty, the check always passes.
// Both versions are parsed as semver (major.minor.patch), with any
// pre-release suffix (after first "-") stripped before comparison.
func CheckMinPipelock(minVersion, currentVersion string) error {
	if minVersion == "" {
		return nil
	}

	minMajor, minMinor, minPatch, err := parseSemver(minVersion)
	if err != nil {
		return fmt.Errorf("check min pipelock: invalid min_pipelock %q: %w", minVersion, err)
	}

	curMajor, curMinor, curPatch, err := parseSemver(currentVersion)
	if err != nil {
		return fmt.Errorf("check min pipelock: invalid current version %q: %w", currentVersion, err)
	}

	if compareSemver(curMajor, curMinor, curPatch, minMajor, minMinor, minPatch) < 0 {
		return fmt.Errorf("check min pipelock: current version %q is below minimum %q", currentVersion, minVersion)
	}

	return nil
}

// parseSemver parses a semver string into major, minor, patch integers.
// Pre-release suffixes (anything after the first "-") are stripped.
func parseSemver(s string) (major, minor, patch int, err error) {
	// Strip pre-release suffix.
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		s = s[:idx]
	}

	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("expected 3 segments, got %d in %q", len(parts), s)
	}

	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid major %q: %w", parts[0], err)
	}

	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid minor %q: %w", parts[1], err)
	}

	patch, err = strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid patch %q: %w", parts[2], err)
	}

	return major, minor, patch, nil
}

// compareSemver returns -1 if a < b, 0 if equal, 1 if a > b.
func compareSemver(aMajor, aMinor, aPatch, bMajor, bMinor, bPatch int) int {
	if aMajor != bMajor {
		return cmpInt(aMajor, bMajor)
	}

	if aMinor != bMinor {
		return cmpInt(aMinor, bMinor)
	}

	return cmpInt(aPatch, bPatch)
}
