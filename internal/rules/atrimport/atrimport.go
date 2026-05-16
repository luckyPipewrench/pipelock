// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package atrimport is an opt-in adapter that loads Agent Threat Rules (ATR,
// https://github.com/Agent-Threat-Rule/agent-threat-rules, MIT licensed)
// YAML files and converts the regex subset into Pipelock pattern types.
// It does NOT touch the signed bundle pipeline. Non-regex ATR rules are
// surfaced in Result.Skipped with a reason so operators can audit what
// they are giving up.
package atrimport

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Safety caps.
const (
	MaxRuleFileBytes = 1 << 20 // 1 MiB per file
	MaxRegexLength   = 4096
	MaxRules         = 2000 // hard cap per LoadDir call
	SourceName       = "atr"
)

// Options configures a single import.
type Options struct {
	MinSeverity         string   // low|medium|high|critical; empty = no filter
	IncludeExperimental bool     // accept status=experimental|draft and maturity=experimental|test
	ScanTargets         []string // allow list against tags.scan_target; empty = no filter
}

// Result is what LoadDir returns. DLP / Injection map onto the existing
// Pipelock pattern types. Skipped records every rule we parsed but did not
// import, with a reason.
type Result struct {
	DLP       []config.DLPPattern
	Injection []config.ResponseScanPattern
	Skipped   []SkipRecord
}

// SkipRecord explains why a single ATR rule was not imported.
type SkipRecord struct {
	RuleID string
	Path   string
	Reason string
}

type atrRule struct {
	ID            string       `yaml:"id"`
	Status        string       `yaml:"status"`
	Maturity      string       `yaml:"maturity"`
	DetectionTier string       `yaml:"detection_tier"`
	Severity      string       `yaml:"severity"`
	Tags          atrTags      `yaml:"tags"`
	Detection     atrDetection `yaml:"detection"`
}

type atrTags struct {
	ScanTarget string `yaml:"scan_target"`
}

type atrDetection struct {
	Condition  string         `yaml:"condition"`
	Conditions []atrCondition `yaml:"conditions"`
}

type atrCondition struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"`
	Value    string `yaml:"value"`
}

var (
	idRegex      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,95}$`)
	severityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	errSkip      = errors.New("atrimport: rule skipped")
)

// LoadDir walks dir, parses every *.yaml/*.yml file as an ATR rule, and
// returns the regex subset mapped onto Pipelock pattern types. Per-file
// errors become Skipped records; only directory-level errors abort.
func LoadDir(dir string, opts Options) (*Result, error) {
	if dir == "" {
		return nil, errors.New("atrimport: dir is empty")
	}
	files, err := walkRuleFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("atrimport: walking %s: %w", dir, err)
	}
	sort.Strings(files)

	result := &Result{}
	minRank := severityRank[strings.ToLower(opts.MinSeverity)]
	for _, p := range files {
		if len(result.DLP)+len(result.Injection) >= MaxRules {
			result.Skipped = append(result.Skipped, SkipRecord{Path: p, Reason: fmt.Sprintf("rule cap %d reached", MaxRules)})
			continue
		}
		rule, readErr := readRuleFile(p)
		if readErr != nil {
			result.Skipped = append(result.Skipped, SkipRecord{Path: p, Reason: readErr.Error()})
			continue
		}
		convErr := convertRule(rule, p, opts, minRank, result)
		if convErr != nil && !errors.Is(convErr, errSkip) {
			result.Skipped = append(result.Skipped, SkipRecord{RuleID: rule.ID, Path: p, Reason: convErr.Error()})
		}
	}
	return result, nil
}

func walkRuleFiles(dir string) ([]string, error) {
	var out []string
	walkErr := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		base := d.Name()
		if d.IsDir() {
			if p != dir && strings.HasPrefix(base, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(base, ".") || (!strings.HasSuffix(base, ".yaml") && !strings.HasSuffix(base, ".yml")) {
			return nil
		}
		out = append(out, p)
		return nil
	})
	return out, walkErr
}

func readRuleFile(p string) (*atrRule, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	if info.Size() > MaxRuleFileBytes {
		return nil, fmt.Errorf("file size %d exceeds %d", info.Size(), MaxRuleFileBytes)
	}
	data, err := os.ReadFile(filepath.Clean(p))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	var rule atrRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return &rule, nil
}

func convertRule(rule *atrRule, path string, opts Options, minRank int, result *Result) error {
	if !idRegex.MatchString(rule.ID) {
		return fmt.Errorf("rule id %q does not match %s", rule.ID, idRegex)
	}
	skip := func(reason string) error {
		result.Skipped = append(result.Skipped, SkipRecord{RuleID: rule.ID, Path: path, Reason: reason})
		return errSkip
	}

	if !opts.IncludeExperimental {
		s, m := strings.ToLower(rule.Status), strings.ToLower(rule.Maturity)
		if s == "experimental" || s == "draft" || m == "experimental" || m == "test" {
			return skip("experimental status not opted in")
		}
	}
	if tier := strings.ToLower(rule.DetectionTier); tier != "" && tier != "pattern" {
		return skip(fmt.Sprintf("detection_tier=%s not supported (only pattern)", tier))
	}
	severity := normalizeSeverity(rule.Severity)
	if minRank > 0 && severityRank[severity] < minRank {
		return skip(fmt.Sprintf("severity %s below minimum", severity))
	}
	scanTarget := strings.ToLower(rule.Tags.ScanTarget)
	if len(opts.ScanTargets) > 0 && !containsFold(opts.ScanTargets, scanTarget) {
		return skip(fmt.Sprintf("scan_target %q not in allow list", scanTarget))
	}
	if strings.ToLower(rule.Detection.Condition) == "all" && len(rule.Detection.Conditions) > 1 {
		return skip("multi-condition all-of rules require boolean composition")
	}

	imported := 0
	total := len(rule.Detection.Conditions)
	for i, c := range rule.Detection.Conditions {
		if strings.ToLower(c.Operator) != "regex" || c.Value == "" {
			continue
		}
		if len(c.Value) > MaxRegexLength {
			result.Skipped = append(result.Skipped, SkipRecord{RuleID: rule.ID, Path: path, Reason: fmt.Sprintf("regex %d exceeds %d chars", i, MaxRegexLength)})
			continue
		}
		if _, err := regexp.Compile(c.Value); err != nil {
			return fmt.Errorf("rule %s condition %d invalid regex: %w", rule.ID, i, err)
		}
		name := SourceName + ":" + rule.ID
		if total > 1 {
			name = fmt.Sprintf("%s:%s.%d", SourceName, rule.ID, i)
		}
		if strings.ToLower(c.Field) == "content" || scanTarget == "llm" {
			result.Injection = append(result.Injection, config.ResponseScanPattern{
				Name: name, Regex: c.Value, Bundle: SourceName, BundleVersion: rule.ID,
			})
		} else {
			result.DLP = append(result.DLP, config.DLPPattern{
				Name: name, Regex: c.Value, Severity: severity, Bundle: SourceName, BundleVersion: rule.ID,
			})
		}
		imported++
	}
	if imported == 0 {
		return skip("no regex conditions found")
	}
	return nil
}

func normalizeSeverity(s string) string {
	v := strings.ToLower(strings.TrimSpace(s))
	if _, ok := severityRank[v]; ok {
		return v
	}
	return "medium"
}

func containsFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}
