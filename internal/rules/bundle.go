// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Bundle represents a parsed and validated rule bundle.
type Bundle struct {
	FormatVersion    int      `yaml:"format_version"`
	Name             string   `yaml:"name"`
	Version          string   `yaml:"version"`
	Author           string   `yaml:"author"`
	Description      string   `yaml:"description"`
	Homepage         string   `yaml:"homepage"`
	MinPipelock      string   `yaml:"min_pipelock"`
	License          string   `yaml:"license"`
	Tier             string   `yaml:"tier"`              // standard, community, pro (v2+)
	MonotonicVersion uint64   `yaml:"monotonic_version"` // rollback-prevention counter (v2+)
	PublishedAt      string   `yaml:"published_at"`      // RFC 3339 timestamp (v2+)
	ExpiresAt        string   `yaml:"expires_at"`        // RFC 3339 timestamp (v2+)
	RequiredFeatures []string `yaml:"required_features"` // engine features needed (v2+, enforced at load time)
	KeyID            string   `yaml:"key_id"`            // signing key fingerprint (v2+)
	Rules            []Rule   `yaml:"rules"`
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
	Regex     string `yaml:"regex"`
	ScanField string `yaml:"scan_field"`
	// ExemptDomains is accepted for v1 parse compatibility but silently
	// ignored at runtime. External bundle rules are deny-only — exemptions
	// must be configured in the local pipelock config, not in bundles.
	ExemptDomains []string `yaml:"exempt_domains"`
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

// Bundle tier constants.
const (
	TierStandard  = "standard"
	TierCommunity = "community"
	TierPro       = "pro"
)

// validTiers is the set of allowed tier values for v2+ bundles.
var validTiers = map[string]bool{
	TierStandard:  true,
	TierCommunity: true,
	TierPro:       true,
}

// KnownFeatures is the set of engine features that bundles can require.
// Bundles declaring a required_feature not in this set are rejected at
// load time, forcing operators to upgrade pipelock before using the bundle.
var KnownFeatures = map[string]bool{
	"dlp":            true,
	"injection":      true,
	"tool_poison":    true,
	"chain":          true,
	"ssrf":           true,
	"response":       true,
	"encoding_aware": true, // recursive base64/hex/base32 detection
	"checksum":       true, // Luhn, mod97, WIF, ABA validators
}

// featureNameRegex validates required_features entries: 1-64 chars,
// lowercase alphanumeric + underscores.
var featureNameRegex = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// CheckRequiredFeatures verifies that every feature in required is well-formed
// and is a known engine feature. Returns an error naming the first invalid or
// unknown feature.
func CheckRequiredFeatures(required []string) error {
	for _, f := range required {
		if !featureNameRegex.MatchString(f) {
			return fmt.Errorf("invalid feature name %q (must be 1-64 lowercase alphanumeric chars with underscores)", f)
		}
		if !KnownFeatures[f] {
			return fmt.Errorf("bundle requires unknown feature %q (upgrade pipelock to use this bundle)", f)
		}
	}
	return nil
}

// Bundle size and count limits.
const (
	MaxBundleFileSize = 1 << 20 // 1 MB
	MaxRuleCount      = 1000
	MaxRegexLength    = 4096
	MaxBundleNameLen  = 64
	MaxRuleIDLen      = 96
	MinNameLen        = 3
	MinRuleIDLen      = 3
	MaxFormatVersion  = 2
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
	if len(data) > MaxBundleFileSize {
		return nil, fmt.Errorf("parse bundle: size %d exceeds maximum of %d bytes", len(data), MaxBundleFileSize)
	}

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
// Accepts format_version 1 (original) and 2 (with tier, freshness, key binding).
func (b *Bundle) Validate() error {
	if b.FormatVersion < 1 || b.FormatVersion > MaxFormatVersion {
		return fmt.Errorf("validate bundle: format_version must be 1-%d, got %d", MaxFormatVersion, b.FormatVersion)
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

	// V2+ fields are required when format_version >= 2.
	if b.FormatVersion >= 2 {
		if err := b.validateV2Fields(); err != nil {
			return err
		}
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

// validateV2Fields validates fields introduced in format_version 2.
func (b *Bundle) validateV2Fields() error {
	if !validTiers[b.Tier] {
		return fmt.Errorf("validate bundle: invalid tier %q (must be standard, community, or pro)", b.Tier)
	}

	if b.MonotonicVersion == 0 {
		return fmt.Errorf("validate bundle: monotonic_version must be > 0")
	}

	if b.PublishedAt == "" {
		return fmt.Errorf("validate bundle: published_at must not be empty")
	}
	if _, err := parseRFC3339(b.PublishedAt); err != nil {
		return fmt.Errorf("validate bundle: published_at: %w", err)
	}

	if b.ExpiresAt == "" {
		return fmt.Errorf("validate bundle: expires_at must not be empty")
	}
	if _, err := parseRFC3339(b.ExpiresAt); err != nil {
		return fmt.Errorf("validate bundle: expires_at: %w", err)
	}

	if b.KeyID == "" {
		return fmt.Errorf("validate bundle: key_id must not be empty for v2+ bundles")
	}

	for _, f := range b.RequiredFeatures {
		if !featureNameRegex.MatchString(f) {
			return fmt.Errorf("validate bundle: required_features entry %q must be 1-64 lowercase alphanumeric chars with underscores", f)
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

	// scan_field validation for tool-poison rules.
	if ruleType == RuleTypeToolPoison {
		if p.ScanField == "" {
			// Default to "description" if empty.
			p.ScanField = scanFieldDescription
		} else if !validScanFields[p.ScanField] {
			return fmt.Errorf("invalid scan_field %q for rule %q (must be %q or %q)", p.ScanField, ruleID, scanFieldDescription, scanFieldName)
		}
	} else if p.ScanField != "" {
		return fmt.Errorf("scan_field is only valid for %s rules (rule %q)", RuleTypeToolPoison, ruleID)
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
	// Strip "v" prefix (e.g. "v2.1.0" → "2.1.0").
	s = strings.TrimPrefix(s, "v")
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

// parseRFC3339 parses an RFC 3339 timestamp string into a time.Time.
func parseRFC3339(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid RFC 3339 timestamp %q: %w", s, err)
	}
	return t, nil
}
