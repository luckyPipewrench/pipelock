// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"testing"
)

const (
	testValidBundleName = "pipelock-community"
	testValidRuleID     = "dlp-aws-key"
	testValidVersion    = "2026.03.1"
	testValidAuthor     = "Pipelock Contributors"
	testValidDesc       = "Community DLP rules"
)

func validBundleYAML() string {
	return `format_version: 1
name: pipelock-community
version: "2026.03.1"
author: Pipelock Contributors
description: Community DLP rules
homepage: https://example.com
min_pipelock: "1.3.0"
license: Apache-2.0
rules:
  - id: dlp-aws-key
    type: dlp
    status: stable
    name: AWS Access Key
    description: Detects AWS access key IDs
    severity: high
    confidence: high
    references:
      - https://docs.aws.amazon.com
    tags:
      - aws
      - credentials
    pattern:
      regex: "AKIA[0-9A-Z]{16}"
  - id: injection-prompt-leak
    type: injection
    status: experimental
    name: Prompt Leak Attempt
    description: Detects prompt extraction attempts
    severity: medium
    confidence: medium
    tags:
      - injection
    pattern:
      regex: "ignore previous instructions"
  - id: tool-poison-shell
    type: tool-poison
    status: stable
    name: Shell Injection in Tool Description
    description: Detects shell commands in MCP tool descriptions
    severity: critical
    confidence: high
    tags:
      - mcp
      - tool-poison
    pattern:
      regex: "curl\\s+.*\\|\\s*sh"
      scan_field: description
`
}

func TestParseBundle_Valid(t *testing.T) {
	t.Parallel()

	b, err := ParseBundle([]byte(validBundleYAML()))
	if err != nil {
		t.Fatalf("ParseBundle() unexpected error: %v", err)
	}

	if b.FormatVersion != 1 {
		t.Errorf("FormatVersion = %d, want 1", b.FormatVersion)
	}

	if b.Name != testValidBundleName {
		t.Errorf("Name = %q, want %q", b.Name, testValidBundleName)
	}

	if b.Version != testValidVersion {
		t.Errorf("Version = %q, want %q", b.Version, testValidVersion)
	}

	if b.Author != testValidAuthor {
		t.Errorf("Author = %q, want %q", b.Author, testValidAuthor)
	}

	if len(b.Rules) != 3 {
		t.Fatalf("len(Rules) = %d, want 3", len(b.Rules))
	}

	// Verify each rule type parsed correctly.
	if b.Rules[0].Type != RuleTypeDLP {
		t.Errorf("Rules[0].Type = %q, want %q", b.Rules[0].Type, RuleTypeDLP)
	}

	if b.Rules[1].Type != RuleTypeInjection {
		t.Errorf("Rules[1].Type = %q, want %q", b.Rules[1].Type, RuleTypeInjection)
	}

	if b.Rules[2].Type != RuleTypeToolPoison {
		t.Errorf("Rules[2].Type = %q, want %q", b.Rules[2].Type, RuleTypeToolPoison)
	}

	// Verify tool-poison scan_field.
	if b.Rules[2].Pattern.ScanField != "description" {
		t.Errorf("Rules[2].Pattern.ScanField = %q, want %q", b.Rules[2].Pattern.ScanField, "description")
	}
}

func TestParseBundle_UnknownFieldTopLevel(t *testing.T) {
	t.Parallel()

	yaml := `format_version: 1
name: test-bundle
version: "2026.03.1"
author: Test
description: Test bundle
unknown_field: oops
rules: []
`
	_, err := ParseBundle([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for unknown top-level field, got nil")
	}

	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("error %q should mention 'unknown'", err.Error())
	}
}

func TestParseBundle_UnknownFieldInRule(t *testing.T) {
	t.Parallel()

	yaml := `format_version: 1
name: test-bundle
version: "2026.03.1"
author: Test
description: Test bundle
rules:
  - id: test-rule-one
    type: dlp
    status: stable
    name: Test Rule
    description: A test rule
    severity: high
    confidence: high
    sneaky_field: gotcha
    pattern:
      regex: "test"
`
	_, err := ParseBundle([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for unknown field in rule, got nil")
	}
}

func TestParseBundle_UnknownFieldInPattern(t *testing.T) {
	t.Parallel()

	yaml := `format_version: 1
name: test-bundle
version: "2026.03.1"
author: Test
description: Test bundle
rules:
  - id: test-rule-one
    type: dlp
    status: stable
    name: Test Rule
    description: A test rule
    severity: high
    confidence: high
    pattern:
      regex: "test"
      secret_bypass: true
`
	_, err := ParseBundle([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for unknown field in pattern, got nil")
	}
}

func TestValidateBundleName(t *testing.T) {
	t.Parallel()

	valid := []struct {
		name  string
		input string
	}{
		{"simple", "abc"},
		{"with hyphens", "my-cool-bundle"},
		{"min length", "abc"},
		{"digits", "bundle123"},
		{"all digits", "123"},
		{"max length 64", "a" + strings.Repeat("b", 62) + "c"},
	}

	for _, tc := range valid {
		t.Run("valid/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateBundleName(tc.input); err != nil {
				t.Errorf("ValidateBundleName(%q) unexpected error: %v", tc.input, err)
			}
		})
	}

	invalid := []struct {
		name  string
		input string
	}{
		{"uppercase", "MyBundle"},
		{"leading hyphen", "-bundle"},
		{"trailing hyphen", "bundle-"},
		{"too short one char", "a"},
		{"too short two chars", "ab"},
		{"too long 65", "a" + strings.Repeat("b", 63) + "c"},
		{"underscore", "my_bundle"},
		{"spaces", "my bundle"},
		{"empty", ""},
		{"dots", "my.bundle"},
		{"special chars", "my@bundle"},
		{"leading digit with hyphen end", "1-"},
	}

	for _, tc := range invalid {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateBundleName(tc.input); err == nil {
				t.Errorf("ValidateBundleName(%q) expected error, got nil", tc.input)
			}
		})
	}
}

func TestValidateRuleID(t *testing.T) {
	t.Parallel()

	valid := []struct {
		name  string
		input string
	}{
		{"simple", "abc"},
		{"with hyphens", "dlp-aws-key"},
		{"min length", "abc"},
		{"max length 96", "a" + strings.Repeat("b", 94) + "c"},
		{"digits only", "123"},
	}

	for _, tc := range valid {
		t.Run("valid/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateRuleID(tc.input); err != nil {
				t.Errorf("ValidateRuleID(%q) unexpected error: %v", tc.input, err)
			}
		})
	}

	invalid := []struct {
		name  string
		input string
	}{
		{"uppercase", "DLP-Key"},
		{"leading hyphen", "-rule"},
		{"trailing hyphen", "rule-"},
		{"too short", "ab"},
		{"too long 97", "a" + strings.Repeat("b", 95) + "c"},
		{"empty", ""},
		{"underscore", "my_rule"},
	}

	for _, tc := range invalid {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateRuleID(tc.input); err == nil {
				t.Errorf("ValidateRuleID(%q) expected error, got nil", tc.input)
			}
		})
	}
}

func TestValidate_FormatVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version int
		wantErr bool
	}{
		{"version 0 rejected", 0, true},
		{"version 1 accepted", 1, false},
		{"version 2 rejected", 2, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := &Bundle{
				FormatVersion: tc.version,
				Name:          testValidBundleName,
				Version:       testValidVersion,
				Author:        testValidAuthor,
				Description:   testValidDesc,
				Rules:         nil,
			}
			err := b.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidate_DuplicateRuleIDs(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion: 1,
		Name:          testValidBundleName,
		Version:       testValidVersion,
		Author:        testValidAuthor,
		Description:   testValidDesc,
		Rules: []Rule{
			{
				ID: "dlp-aws-key", Type: RuleTypeDLP, Status: StatusStable,
				Name: "Rule 1", Description: "First rule",
				Severity: severityHigh, Confidence: confidenceHigh,
				Pattern: RulePattern{Regex: "test1"},
			},
			{
				ID: "dlp-aws-key", Type: RuleTypeDLP, Status: StatusStable,
				Name: "Rule 2", Description: "Duplicate ID",
				Severity: severityHigh, Confidence: confidenceHigh,
				Pattern: RulePattern{Regex: "test2"},
			},
		},
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for duplicate rule IDs, got nil")
	}

	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error %q should mention 'duplicate'", err.Error())
	}
}

func TestValidate_InvalidRegex(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion: 1,
		Name:          testValidBundleName,
		Version:       testValidVersion,
		Author:        testValidAuthor,
		Description:   testValidDesc,
		Rules: []Rule{
			{
				ID: "bad-regex-rule", Type: RuleTypeDLP, Status: StatusStable,
				Name: "Bad Regex", Description: "Has invalid regex",
				Severity: severityHigh, Confidence: confidenceHigh,
				Pattern: RulePattern{Regex: "[invalid("},
			},
		},
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}

	if !strings.Contains(err.Error(), "regex") {
		t.Errorf("error %q should mention 'regex'", err.Error())
	}
}

func TestValidate_RegexTooLong(t *testing.T) {
	t.Parallel()

	longRegex := strings.Repeat("a", MaxRegexLength+1)

	b := &Bundle{
		FormatVersion: 1,
		Name:          testValidBundleName,
		Version:       testValidVersion,
		Author:        testValidAuthor,
		Description:   testValidDesc,
		Rules: []Rule{
			{
				ID: "long-regex-rule", Type: RuleTypeDLP, Status: StatusStable,
				Name: "Long Regex", Description: "Regex exceeds max length",
				Severity: severityHigh, Confidence: confidenceHigh,
				Pattern: RulePattern{Regex: longRegex},
			},
		},
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for regex exceeding max length, got nil")
	}

	if !strings.Contains(err.Error(), "regex") {
		t.Errorf("error %q should mention 'regex'", err.Error())
	}
}

func TestValidate_TooManyRules(t *testing.T) {
	t.Parallel()

	rules := make([]Rule, MaxRuleCount+1)
	for i := range rules {
		// Each rule ID must be unique and 3-96 chars lowercase alphanumeric + hyphens.
		rules[i] = Rule{
			ID: fmt.Sprintf("rule-%06d", i), Type: RuleTypeDLP, Status: StatusStable,
			Name: "Rule", Description: "A rule",
			Severity: severityHigh, Confidence: confidenceHigh,
			Pattern: RulePattern{Regex: "test"},
		}
	}

	b := &Bundle{
		FormatVersion: 1,
		Name:          testValidBundleName,
		Version:       testValidVersion,
		Author:        testValidAuthor,
		Description:   testValidDesc,
		Rules:         rules,
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for too many rules, got nil")
	}

	if !strings.Contains(err.Error(), "rules") {
		t.Errorf("error %q should mention 'rules'", err.Error())
	}
}

func TestValidate_InvalidType(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion: 1,
		Name:          testValidBundleName,
		Version:       testValidVersion,
		Author:        testValidAuthor,
		Description:   testValidDesc,
		Rules: []Rule{
			{
				ID: "bad-type-rule", Type: "unknown-type", Status: StatusStable,
				Name: "Bad Type", Description: "Has invalid type",
				Severity: severityHigh, Confidence: confidenceHigh,
				Pattern: RulePattern{Regex: "test"},
			},
		},
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for invalid type, got nil")
	}
}

func TestValidate_InvalidStatus(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion: 1,
		Name:          testValidBundleName,
		Version:       testValidVersion,
		Author:        testValidAuthor,
		Description:   testValidDesc,
		Rules: []Rule{
			{
				ID: "bad-status-rule", Type: RuleTypeDLP, Status: "invalid",
				Name: "Bad Status", Description: "Has invalid status",
				Severity: severityHigh, Confidence: confidenceHigh,
				Pattern: RulePattern{Regex: "test"},
			},
		},
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for invalid status, got nil")
	}
}

func TestValidate_InvalidSeverity(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion: 1,
		Name:          testValidBundleName,
		Version:       testValidVersion,
		Author:        testValidAuthor,
		Description:   testValidDesc,
		Rules: []Rule{
			{
				ID: "bad-severity-rule", Type: RuleTypeDLP, Status: StatusStable,
				Name: "Bad Severity", Description: "Has invalid severity",
				Severity: "extreme", Confidence: confidenceHigh,
				Pattern: RulePattern{Regex: "test"},
			},
		},
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for invalid severity, got nil")
	}
}

func TestValidate_InvalidConfidence(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion: 1,
		Name:          testValidBundleName,
		Version:       testValidVersion,
		Author:        testValidAuthor,
		Description:   testValidDesc,
		Rules: []Rule{
			{
				ID: "bad-confidence-rule", Type: RuleTypeDLP, Status: StatusStable,
				Name: "Bad Confidence", Description: "Has invalid confidence",
				Severity: severityHigh, Confidence: "uncertain",
				Pattern: RulePattern{Regex: "test"},
			},
		},
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for invalid confidence, got nil")
	}
}

func TestValidate_MissingRequiredFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule Rule
	}{
		{"missing id", Rule{
			Type: RuleTypeDLP, Status: StatusStable,
			Name: "Test", Description: "Test",
			Severity: severityHigh, Confidence: confidenceHigh,
			Pattern: RulePattern{Regex: "test"},
		}},
		{"missing type", Rule{
			ID: "test-rule-aaa", Status: StatusStable,
			Name: "Test", Description: "Test",
			Severity: severityHigh, Confidence: confidenceHigh,
			Pattern: RulePattern{Regex: "test"},
		}},
		{"missing name", Rule{
			ID: "test-rule-bbb", Type: RuleTypeDLP, Status: StatusStable,
			Description: "Test",
			Severity:    severityHigh, Confidence: confidenceHigh,
			Pattern: RulePattern{Regex: "test"},
		}},
		{"missing description", Rule{
			ID: "test-rule-ccc", Type: RuleTypeDLP, Status: StatusStable,
			Name:     "Test",
			Severity: severityHigh, Confidence: confidenceHigh,
			Pattern: RulePattern{Regex: "test"},
		}},
		{"missing status", Rule{
			ID: "test-rule-ddd", Type: RuleTypeDLP,
			Name: "Test", Description: "Test",
			Severity: severityHigh, Confidence: confidenceHigh,
			Pattern: RulePattern{Regex: "test"},
		}},
		{"missing severity", Rule{
			ID: "test-rule-eee", Type: RuleTypeDLP, Status: StatusStable,
			Name: "Test", Description: "Test",
			Confidence: confidenceHigh,
			Pattern:    RulePattern{Regex: "test"},
		}},
		{"missing confidence", Rule{
			ID: "test-rule-fff", Type: RuleTypeDLP, Status: StatusStable,
			Name: "Test", Description: "Test",
			Severity: severityHigh,
			Pattern:  RulePattern{Regex: "test"},
		}},
		{"missing regex", Rule{
			ID: "test-rule-ggg", Type: RuleTypeDLP, Status: StatusStable,
			Name: "Test", Description: "Test",
			Severity: severityHigh, Confidence: confidenceHigh,
			Pattern: RulePattern{},
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := &Bundle{
				FormatVersion: 1,
				Name:          testValidBundleName,
				Version:       testValidVersion,
				Author:        testValidAuthor,
				Description:   testValidDesc,
				Rules:         []Rule{tc.rule},
			}
			err := b.Validate()
			if err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestValidate_MissingBundleFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		bundle Bundle
	}{
		{"missing author", Bundle{
			FormatVersion: 1, Name: testValidBundleName,
			Version: testValidVersion, Description: testValidDesc,
		}},
		{"missing description", Bundle{
			FormatVersion: 1, Name: testValidBundleName,
			Version: testValidVersion, Author: testValidAuthor,
		}},
		{"missing version", Bundle{
			FormatVersion: 1, Name: testValidBundleName,
			Author: testValidAuthor, Description: testValidDesc,
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.bundle.Validate()
			if err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestValidate_ScanFieldToolPoison(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		scanField string
		wantErr   bool
	}{
		{"description explicit", "description", false},
		{"name explicit", "name", false},
		{"empty defaults to description", "", false},
		{"invalid scan_field", "body", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := &Bundle{
				FormatVersion: 1,
				Name:          testValidBundleName,
				Version:       testValidVersion,
				Author:        testValidAuthor,
				Description:   testValidDesc,
				Rules: []Rule{
					{
						ID: "tool-poison-test", Type: RuleTypeToolPoison, Status: StatusStable,
						Name: "Test", Description: "Test rule",
						Severity: severityHigh, Confidence: confidenceHigh,
						Pattern: RulePattern{Regex: "test", ScanField: tc.scanField},
					},
				},
			}

			err := b.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestNamespacedID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		bundleName string
		ruleID     string
		want       string
	}{
		{"basic", "community", "dlp-aws-key", "community:dlp-aws-key"},
		{"hyphens", "my-bundle", "my-rule", "my-bundle:my-rule"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := NamespacedID(tc.bundleName, tc.ruleID)
			if got != tc.want {
				t.Errorf("NamespacedID(%q, %q) = %q, want %q", tc.bundleName, tc.ruleID, got, tc.want)
			}
		})
	}
}

func TestCheckMinPipelock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		minVersion string
		curVersion string
		wantErr    bool
	}{
		{"empty min always ok", "", "1.3.0", false},
		{"exact match", "1.3.0", "1.3.0", false},
		{"current exceeds min", "1.2.0", "1.3.0", false},
		{"current below min", "1.4.0", "1.3.0", true},
		{"major below", "2.0.0", "1.3.0", true},
		{"major above", "1.0.0", "2.0.0", false},
		{"pre-release stripped from current", "1.3.0", "1.3.0-rc1", false},
		{"pre-release stripped from min", "1.3.0-beta", "1.3.0", false},
		{"patch comparison", "1.3.1", "1.3.0", true},
		{"patch meets", "1.3.0", "1.3.1", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := CheckMinPipelock(tc.minVersion, tc.curVersion)
			if (err != nil) != tc.wantErr {
				t.Errorf("CheckMinPipelock(%q, %q) error = %v, wantErr = %v",
					tc.minVersion, tc.curVersion, err, tc.wantErr)
			}
		})
	}
}

func TestCheckMinPipelock_InvalidVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		minVersion string
		curVersion string
	}{
		{"invalid min", "abc", "1.3.0"},
		{"invalid current", "1.3.0", "abc"},
		{"both invalid", "abc", "def"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := CheckMinPipelock(tc.minVersion, tc.curVersion)
			if err == nil {
				t.Errorf("CheckMinPipelock(%q, %q) expected error for invalid version, got nil",
					tc.minVersion, tc.curVersion)
			}
		})
	}
}

func TestValidate_AllSeverities(t *testing.T) {
	t.Parallel()

	validSeverities := []string{severityCritical, severityHigh, severityMedium, severityLow}

	for _, sev := range validSeverities {
		t.Run("severity/"+sev, func(t *testing.T) {
			t.Parallel()

			b := &Bundle{
				FormatVersion: 1,
				Name:          testValidBundleName,
				Version:       testValidVersion,
				Author:        testValidAuthor,
				Description:   testValidDesc,
				Rules: []Rule{
					{
						ID: "severity-test", Type: RuleTypeDLP, Status: StatusStable,
						Name: "Test", Description: "Test",
						Severity: sev, Confidence: confidenceHigh,
						Pattern: RulePattern{Regex: "test"},
					},
				},
			}
			if err := b.Validate(); err != nil {
				t.Errorf("Validate() with severity %q: %v", sev, err)
			}
		})
	}
}

func TestValidate_AllStatuses(t *testing.T) {
	t.Parallel()

	allStatuses := []string{StatusExperimental, StatusStable, StatusDeprecated}

	for _, s := range allStatuses {
		t.Run("status/"+s, func(t *testing.T) {
			t.Parallel()

			b := &Bundle{
				FormatVersion: 1,
				Name:          testValidBundleName,
				Version:       testValidVersion,
				Author:        testValidAuthor,
				Description:   testValidDesc,
				Rules: []Rule{
					{
						ID: "status-test", Type: RuleTypeDLP, Status: s,
						Name: "Test", Description: "Test",
						Severity: severityHigh, Confidence: confidenceHigh,
						Pattern: RulePattern{Regex: "test"},
					},
				},
			}
			if err := b.Validate(); err != nil {
				t.Errorf("Validate() with status %q: %v", s, err)
			}
		})
	}
}

func TestValidate_AllConfidences(t *testing.T) {
	t.Parallel()

	allConfidences := []string{confidenceHigh, confidenceMedium, confidenceLow}

	for _, c := range allConfidences {
		t.Run("confidence/"+c, func(t *testing.T) {
			t.Parallel()

			b := &Bundle{
				FormatVersion: 1,
				Name:          testValidBundleName,
				Version:       testValidVersion,
				Author:        testValidAuthor,
				Description:   testValidDesc,
				Rules: []Rule{
					{
						ID: "confidence-test", Type: RuleTypeDLP, Status: StatusStable,
						Name: "Test", Description: "Test",
						Severity: severityHigh, Confidence: c,
						Pattern: RulePattern{Regex: "test"},
					},
				},
			}
			if err := b.Validate(); err != nil {
				t.Errorf("Validate() with confidence %q: %v", c, err)
			}
		})
	}
}

func TestValidate_ScanFieldOnNonToolPoison(t *testing.T) {
	t.Parallel()

	// scan_field on DLP type should be ignored (no error).
	b := &Bundle{
		FormatVersion: 1,
		Name:          testValidBundleName,
		Version:       testValidVersion,
		Author:        testValidAuthor,
		Description:   testValidDesc,
		Rules: []Rule{
			{
				ID: "dlp-with-scanfield", Type: RuleTypeDLP, Status: StatusStable,
				Name: "Test", Description: "Test",
				Severity: severityHigh, Confidence: confidenceHigh,
				Pattern: RulePattern{Regex: "test", ScanField: "name"},
			},
		},
	}

	// scan_field must be rejected on non-tool-poison rules to catch authoring mistakes.
	err := b.Validate()
	if err == nil {
		t.Error("Validate() should reject scan_field on DLP rules")
	}
}

func TestParseBundle_EmptyRules(t *testing.T) {
	t.Parallel()

	yaml := `format_version: 1
name: empty-rules
version: "2026.03.1"
author: Test
description: An empty bundle
rules: []
`
	b, err := ParseBundle([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseBundle() unexpected error: %v", err)
	}

	if len(b.Rules) != 0 {
		t.Errorf("len(Rules) = %d, want 0", len(b.Rules))
	}
}

func TestValidate_InvalidCalVer(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion: 1,
		Name:          testValidBundleName,
		Version:       "not-a-version",
		Author:        testValidAuthor,
		Description:   testValidDesc,
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for invalid CalVer version, got nil")
	}

	if !strings.Contains(err.Error(), "version") {
		t.Errorf("error %q should mention 'version'", err.Error())
	}
}

func TestValidate_V2Bundle_Valid(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion:    2,
		Name:             testValidBundleName,
		Version:          testValidVersion,
		Author:           testValidAuthor,
		Description:      testValidDesc,
		Tier:             TierStandard,
		MonotonicVersion: 1,
		PublishedAt:      "2026-04-01T00:00:00Z",
		ExpiresAt:        "2026-06-01T00:00:00Z",
		KeyID:            "sha256:test-key",
		Rules: []Rule{
			{
				ID: "test-001", Type: RuleTypeDLP, Status: StatusStable,
				Name: "Test", Description: "Test rule",
				Severity: severityHigh, Confidence: confidenceHigh,
				Pattern: RulePattern{Regex: "test"},
			},
		},
	}

	if err := b.Validate(); err != nil {
		t.Errorf("valid v2 bundle should pass: %v", err)
	}
}

func TestValidate_V2Bundle_MissingTier(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion:    2,
		Name:             testValidBundleName,
		Version:          testValidVersion,
		Author:           testValidAuthor,
		Description:      testValidDesc,
		MonotonicVersion: 1,
		PublishedAt:      "2026-04-01T00:00:00Z",
		ExpiresAt:        "2026-06-01T00:00:00Z",
		KeyID:            "sha256:test-key",
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for missing tier")
	}
	if !strings.Contains(err.Error(), "tier") {
		t.Errorf("error %q should mention tier", err.Error())
	}
}

func TestValidate_V2Bundle_InvalidTier(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion:    2,
		Name:             testValidBundleName,
		Version:          testValidVersion,
		Author:           testValidAuthor,
		Description:      testValidDesc,
		Tier:             "enterprise",
		MonotonicVersion: 1,
		PublishedAt:      "2026-04-01T00:00:00Z",
		ExpiresAt:        "2026-06-01T00:00:00Z",
		KeyID:            "sha256:test-key",
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for invalid tier")
	}
	if !strings.Contains(err.Error(), "tier") {
		t.Errorf("error %q should mention tier", err.Error())
	}
}

func TestValidate_V2Bundle_ZeroMonotonicVersion(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion: 2,
		Name:          testValidBundleName,
		Version:       testValidVersion,
		Author:        testValidAuthor,
		Description:   testValidDesc,
		Tier:          TierStandard,
		PublishedAt:   "2026-04-01T00:00:00Z",
		ExpiresAt:     "2026-06-01T00:00:00Z",
		KeyID:         "sha256:test-key",
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for zero monotonic_version")
	}
	if !strings.Contains(err.Error(), "monotonic_version") {
		t.Errorf("error %q should mention monotonic_version", err.Error())
	}
}

func TestValidate_V2Bundle_InvalidTimestamp(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion:    2,
		Name:             testValidBundleName,
		Version:          testValidVersion,
		Author:           testValidAuthor,
		Description:      testValidDesc,
		Tier:             TierCommunity,
		MonotonicVersion: 1,
		PublishedAt:      "not-a-date",
		ExpiresAt:        "2026-06-01T00:00:00Z",
		KeyID:            "sha256:test-key",
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for invalid published_at timestamp")
	}
}

func TestValidate_V2Bundle_MissingKeyID(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion:    2,
		Name:             testValidBundleName,
		Version:          testValidVersion,
		Author:           testValidAuthor,
		Description:      testValidDesc,
		Tier:             TierPro,
		MonotonicVersion: 1,
		PublishedAt:      "2026-04-01T00:00:00Z",
		ExpiresAt:        "2026-06-01T00:00:00Z",
	}

	err := b.Validate()
	if err == nil {
		t.Fatal("expected error for missing key_id")
	}
}

func TestValidate_V1Bundle_IgnoresV2Fields(t *testing.T) {
	t.Parallel()

	// V1 bundles should pass even without v2 fields.
	b := &Bundle{
		FormatVersion: 1,
		Name:          testValidBundleName,
		Version:       testValidVersion,
		Author:        testValidAuthor,
		Description:   testValidDesc,
		Rules: []Rule{
			{
				ID: "test-001", Type: RuleTypeDLP, Status: StatusStable,
				Name: "Test", Description: "Test rule",
				Severity: severityHigh, Confidence: confidenceHigh,
				Pattern: RulePattern{Regex: "test"},
			},
		},
	}

	if err := b.Validate(); err != nil {
		t.Errorf("v1 bundle without v2 fields should pass: %v", err)
	}
}

func TestCheckRequiredFeatures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		features []string
		wantErr  string
	}{
		{
			name:     "empty features",
			features: nil,
		},
		{
			name:     "single known feature",
			features: []string{"dlp"},
		},
		{
			name:     "multiple known features",
			features: []string{"dlp", "injection", "checksum", "encoding_aware"},
		},
		{
			name:     "all known features",
			features: []string{"dlp", "injection", "tool_poison", "chain", "ssrf", "response", "encoding_aware", "checksum"},
		},
		{
			name:     "unknown feature",
			features: []string{"quantum_crypto"},
			wantErr:  "unknown feature",
		},
		{
			name:     "one known one unknown",
			features: []string{"dlp", "neural_scan"},
			wantErr:  "unknown feature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := CheckRequiredFeatures(tt.features)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidate_V2Bundle_InvalidFeatureName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		features []string
		wantErr  bool
	}{
		{name: "valid feature", features: []string{"dlp"}, wantErr: false},
		{name: "valid underscore", features: []string{"encoding_aware"}, wantErr: false},
		{name: "empty string", features: []string{""}, wantErr: true},
		{name: "uppercase", features: []string{"DLP"}, wantErr: true},
		{name: "spaces", features: []string{"my feature"}, wantErr: true},
		{name: "special chars", features: []string{"dlp-v2"}, wantErr: true},
		{name: "starts with number", features: []string{"2fast"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &Bundle{
				FormatVersion:    2,
				Name:             testValidBundleName,
				Version:          testValidVersion,
				Author:           testValidAuthor,
				Description:      testValidDesc,
				Tier:             TierStandard,
				MonotonicVersion: 1,
				PublishedAt:      "2026-04-01T00:00:00Z",
				ExpiresAt:        "2026-06-01T00:00:00Z",
				KeyID:            "sha256:test-key",
				RequiredFeatures: tt.features,
				Rules: []Rule{
					{
						ID: "test-001", Type: RuleTypeDLP, Status: StatusStable,
						Name: "Test", Description: "Test rule",
						Severity: severityHigh, Confidence: confidenceHigh,
						Pattern: RulePattern{Regex: "test"},
					},
				},
			}
			err := b.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
