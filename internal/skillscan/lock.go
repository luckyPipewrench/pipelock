// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package skillscan

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

type LockFile struct {
	SchemaVersion string               `yaml:"schema_version"`
	BaselinedAt   string               `yaml:"baselined_at"`
	EmitterHost   string               `yaml:"emitter_host"`
	Skills        map[string]LockSkill `yaml:"skills"`
}

type LockSkill struct {
	SkillPath           string                    `yaml:"skill_path"`
	SkillSHA256         string                    `yaml:"skill_sha256"`
	ReferencedFiles     map[string]LockReferenced `yaml:"referenced_files"`
	CapabilitiesSummary []string                  `yaml:"capabilities_summary"`
	Combos              []LockCombo               `yaml:"combos,omitempty"`
}

type LockReferenced struct {
	SHA256 string `yaml:"sha256"`
	Mode   string `yaml:"mode"`
}

// LockCombo records a combination present at baseline time. After baselining,
// only combos whose fingerprint is absent from the lock are reported, so an
// existing skill library does not turn red on day one while a newly introduced
// risky combination still surfaces (the detect-secrets baseline model).
type LockCombo struct {
	Kind        string `yaml:"kind"`
	Severity    string `yaml:"severity"`
	Region      string `yaml:"region"`
	Fingerprint string `yaml:"fingerprint"`
}

func BuildLock(skills []Skill, now time.Time) LockFile {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	lock := LockFile{
		SchemaVersion: SchemaVersion,
		BaselinedAt:   now.UTC().Format(time.RFC3339),
		EmitterHost:   host,
		Skills:        map[string]LockSkill{},
	}
	for _, skill := range skills {
		refs := map[string]LockReferenced{}
		for _, ref := range skill.ReferencedFiles {
			refs[ref.Path] = LockReferenced{SHA256: ref.SHA256, Mode: ref.Mode}
		}
		lock.Skills[skill.ID] = LockSkill{
			SkillPath:           skill.Path,
			SkillSHA256:         skill.ContentSHA256,
			ReferencedFiles:     refs,
			CapabilitiesSummary: capabilitySummary(skill),
			Combos:              lockCombos(skill.Combos),
		}
	}
	return lock
}

func lockCombos(combos []Combo) []LockCombo {
	if len(combos) == 0 {
		return nil
	}
	out := make([]LockCombo, 0, len(combos))
	for _, c := range combos {
		out = append(out, LockCombo{
			Kind:        string(c.Kind),
			Severity:    string(c.Severity),
			Region:      c.RegionID,
			Fingerprint: c.Fingerprint,
		})
	}
	return out
}

// baselinedCombos returns the set of combo fingerprints recorded in the lock.
func (l LockFile) baselinedCombos() map[string]struct{} {
	set := map[string]struct{}{}
	for _, skill := range l.Skills {
		for _, combo := range skill.Combos {
			if combo.Fingerprint != "" {
				set[combo.Fingerprint] = struct{}{}
			}
		}
	}
	return set
}

func LoadLock(path string) (LockFile, error) {
	clean := filepath.Clean(path)
	data, err := os.ReadFile(clean)
	if err != nil {
		return LockFile{}, fmt.Errorf("read lock file %s: %w", clean, err)
	}
	var lock LockFile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return LockFile{}, fmt.Errorf("parse lock file %s: %w", clean, err)
	}
	if lock.SchemaVersion != SchemaVersion {
		return LockFile{}, fmt.Errorf("lock file %s has schema_version %q, want %q", clean, lock.SchemaVersion, SchemaVersion)
	}
	if lock.Skills == nil {
		lock.Skills = map[string]LockSkill{}
	}
	return lock, nil
}

func SaveLock(path string, lock LockFile) error {
	clean := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(clean), 0o750); err != nil {
		return fmt.Errorf("create lock directory: %w", err)
	}
	data, err := yaml.Marshal(lock)
	if err != nil {
		return fmt.Errorf("marshal lock file: %w", err)
	}
	if err := os.WriteFile(clean, data, 0o600); err != nil {
		return fmt.Errorf("write lock file %s: %w", clean, err)
	}
	return nil
}

func diffLock(lock LockFile, skills []Skill) []Finding {
	current := map[string]Skill{}
	for _, skill := range skills {
		current[skill.ID] = skill
	}
	var ids []string
	for id := range current {
		ids = append(ids, id)
	}
	for id := range lock.Skills {
		if _, ok := current[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	var findings []Finding
	seen := map[string]struct{}{}
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		skill, hasCurrent := current[id]
		baseline, hasBaseline := lock.Skills[id]
		switch {
		case hasCurrent && !hasBaseline:
			findings = append(findings, driftFinding(SeverityHigh, id, "new skill is not in the lock", skill.Path, "new"))
		case !hasCurrent && hasBaseline:
			findings = append(findings, driftFinding(SeverityLow, id, "skill from the lock is removed", baseline.SkillPath, "removed"))
		case hasCurrent:
			findings = append(findings, compareLockedSkill(id, skill, baseline)...)
		}
	}
	return findings
}

func compareLockedSkill(id string, skill Skill, baseline LockSkill) []Finding {
	var findings []Finding
	if skill.ContentSHA256 != baseline.SkillSHA256 {
		findings = append(findings, driftFinding(SeverityHigh, id, "skill content changed", skill.Path, "changed"))
	}
	findings = append(findings, compareReferencedFiles(id, skill, baseline)...)
	if widened := widenedCapabilities(capabilitySummary(skill), baseline.CapabilitiesSummary); len(widened) > 0 {
		findings = append(findings, driftFinding(SeverityMedium, id, "capability set widened: "+joinSorted(widened), skill.Path, "changed"))
	}
	return findings
}

func compareReferencedFiles(id string, skill Skill, baseline LockSkill) []Finding {
	current := map[string]ReferencedFile{}
	for _, ref := range skill.ReferencedFiles {
		current[ref.Path] = ref
	}
	var findings []Finding
	for rel, ref := range current {
		base, ok := baseline.ReferencedFiles[rel]
		path := filepath.Join(filepath.Dir(skill.Path), filepath.FromSlash(rel))
		if !ok {
			findings = append(findings, driftFinding(SeverityHigh, id, "referenced file is new", path, "new"))
			continue
		}
		if ref.SHA256 != base.SHA256 {
			findings = append(findings, driftFinding(SeverityHigh, id, "referenced file content changed", path, "changed"))
		}
		if ref.Mode != base.Mode {
			findings = append(findings, driftFinding(SeverityMedium, id, fmt.Sprintf("referenced file mode changed from %s to %s", base.Mode, ref.Mode), path, "changed"))
		}
	}
	for rel := range baseline.ReferencedFiles {
		if _, ok := current[rel]; !ok {
			path := filepath.Join(filepath.Dir(skill.Path), filepath.FromSlash(rel))
			findings = append(findings, driftFinding(SeverityHigh, id, "referenced file from the lock is removed", path, "removed"))
		}
	}
	return findings
}

func driftFinding(severity Severity, skillID, message, path, pattern string) Finding {
	return Finding{
		Kind:     FindingDrift,
		Severity: severity,
		SkillID:  skillID,
		Message:  message,
		Evidence: []Evidence{{Path: path, Pattern: pattern}},
	}
}

func widenedCapabilities(current, baseline []string) []string {
	have := map[string]struct{}{}
	for _, cap := range baseline {
		have[cap] = struct{}{}
	}
	var widened []string
	for _, cap := range current {
		if _, ok := have[cap]; !ok {
			widened = append(widened, cap)
		}
	}
	sort.Strings(widened)
	return widened
}

func joinSorted(items []string) string {
	sort.Strings(items)
	out := ""
	for i, item := range items {
		if i > 0 {
			out += ", "
		}
		out += item
	}
	return out
}
