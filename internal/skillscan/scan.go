// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package skillscan

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/filescan"
)

func Scan(opts Options) (Result, error) {
	inputs, err := discoverSkills(opts.Paths)
	if err != nil {
		return Result{}, err
	}
	allowlist, err := loadAllowlist(opts.AllowlistFile)
	if err != nil {
		return Result{}, err
	}
	now := time.Now()

	// Combos and drift only compare against a prior lock on a plain scan;
	// baseline and update establish or refresh the lock instead.
	refreshLock := opts.Baseline || opts.Update
	useLock := opts.LockFile != "" && !opts.InventoryOnly && !refreshLock
	var lock LockFile
	if useLock {
		lock, err = LoadLock(opts.LockFile)
		if err != nil {
			return Result{}, err
		}
	}
	baselined := lock.baselinedCombos()

	result := Result{LockFile: opts.LockFile}
	var hiddenPaths, oversizePaths []string
	var uninspectable []uninspectableRef
	for _, input := range inputs {
		skill := buildSkill(input, opts.IncludeDeps)
		if !opts.InventoryOnly {
			skill.Combos = detectCombos(input)
		}
		result.Skills = append(result.Skills, skill)
		result.FilesScanned += len(input.scanFiles)
		hiddenPaths = append(hiddenPaths, input.scanFiles...)
		oversizePaths = append(oversizePaths, input.oversize...)
		uninspectable = append(uninspectable, input.uninspectable...)
	}
	sort.Slice(result.Skills, func(i, j int) bool { return result.Skills[i].ID < result.Skills[j].ID })

	// The hidden-instruction pass runs whenever its RESULT is needed, which is
	// wider than "are we emitting findings". Under --inventory-only it was
	// skipped entirely, so a refresh had no way to know a file went unscanned
	// and wrote a lock over it. A lock is a durable reviewed baseline; deciding
	// it needs these facts even in a mode that reports nothing.
	var hidden filescan.Result
	if !opts.InventoryOnly || refreshLock {
		scanned, err := filescan.ScanPaths(uniqueStrings(hiddenPaths), filescan.Options{IncludeDepDirs: opts.IncludeDeps})
		if err != nil {
			return Result{}, fmt.Errorf("hidden-instruction scan: %w", err)
		}
		hidden = scanned
	}
	// Unread paths bar a lock refresh regardless of reporting mode, so collect
	// them outside the findings block.
	// Consume BOTH buckets. filescan now separates a refusal, an agent-context
	// file whose content could not be inspected, from an ordinary advisory skip.
	// SKILL.md is an agent-context name, so reading only Skipped would move every
	// unread skill file into a bucket nobody looks at and silently reopen the gap
	// that reporting these closed.
	for _, skip := range hidden.Skipped {
		uninspectable = append(uninspectable, uninspectableRef{
			path:   skip.Path,
			reason: skip.Reason,
		})
	}
	for _, refused := range hidden.Refused {
		uninspectable = append(uninspectable, uninspectableRef{
			path:   refused.Path,
			reason: refused.Reason,
		})
	}

	if !opts.InventoryOnly {
		// Combination findings are suppressed by the baseline (already-reviewed
		// combos) and by exact-fingerprint allowlist entries, and are skipped
		// while refreshing the lock so baselining never alerts on what it
		// records. Hidden-Unicode and oversize findings, by contrast, run in
		// every mode INCLUDING baseline/update: a provable high hidden
		// instruction must never be silently blessed into a lock.
		if !refreshLock {
			result.Findings = append(result.Findings, comboFindings(result.Skills, baselined, allowlist, now)...)
		}

		for _, finding := range hidden.Findings {
			result.Findings = append(result.Findings, Finding{
				Kind:     FindingHidden,
				Severity: mapHiddenSeverity(finding.Severity),
				Message:  "hidden Unicode/control character flagged by file scan",
				Evidence: []Evidence{{
					Path:    finding.Path,
					Line:    finding.Line,
					Pattern: fmt.Sprintf("%s %s", finding.CodePoint, finding.Category),
				}},
			})
		}
		for _, path := range uniqueStrings(oversizePaths) {
			result.Findings = append(result.Findings, Finding{
				Kind:     FindingOversize,
				Severity: SeverityHigh,
				Message:  fmt.Sprintf("file exceeds the %d-byte scan limit and was not scanned", maxScanFileBytes),
				Evidence: []Evidence{{Path: path}},
			})
		}
		// A path the scanner did not read must not present as clean; the skips
		// were collected above so they bar a lock refresh in every mode.
		seenUninspectable := make(map[string]struct{}, len(uninspectable))
		for _, ref := range uninspectable {
			if _, ok := seenUninspectable[ref.path]; ok {
				continue
			}
			seenUninspectable[ref.path] = struct{}{}
			result.Findings = append(result.Findings, Finding{
				Kind:     FindingUninspectable,
				Severity: SeverityHigh,
				Message:  "path was not scanned and its content is therefore unknown: " + ref.reason,
				Evidence: []Evidence{{Path: ref.path}},
			})
		}
	}

	if useLock {
		result.Findings = append(result.Findings, diffLock(lock, result.Skills)...)
	}
	// Refuse to refresh the lock when any path went uninspected. BuildLock
	// records a skill's hashes and an EMPTY capability summary, so locking an
	// unread SKILL.md freezes "this skill does nothing" as the approved
	// baseline and every later scan compares clean against it. That is the
	// silent blessing the hidden-instruction pass above exists to prevent, and
	// it is worse than not baselining at all.
	if refreshLock {
		if result.LockFile == "" {
			// Resolve the default BEFORE deciding, so a refusal can name the
			// file it declined to write instead of reporting an empty path.
			result.LockFile = DefaultLockFile()
		}
		// Decide from the unread paths themselves, not from result.Findings.
		// Findings are only emitted when InventoryOnly is false, so a guard
		// reading them was bypassed entirely by --inventory-only and wrote a
		// lock over content nobody had read.
		if len(oversizePaths) > 0 || len(uninspectable) > 0 {
			result.LockRefused = true
			sortFindings(result.Findings)
			return result, nil
		}
		if err := SaveLock(result.LockFile, BuildLock(result.Skills, now)); err != nil {
			return Result{}, err
		}
	}
	sortFindings(result.Findings)
	return result, nil
}

// comboFindings converts detected combos into findings, suppressing those
// recorded in the baseline and those covered by an active allowlist entry, and
// reports allowlist entries that no longer match any combination.
func comboFindings(skills []Skill, baselined map[string]struct{}, allowlist Allowlist, now time.Time) []Finding {
	var findings []Finding
	matched := map[string]struct{}{}
	for _, skill := range skills {
		for _, combo := range skill.Combos {
			entry, hasEntry := allowlist.entry(combo.Fingerprint)
			if hasEntry {
				// Mark matched even when the baseline suppresses below, so a
				// fingerprint that is both baselined and allowlisted is not
				// then reported as a stale allowlist entry.
				matched[combo.Fingerprint] = struct{}{}
			}
			if _, ok := baselined[combo.Fingerprint]; ok {
				continue
			}
			if hasEntry {
				if entry.suppresses(now) {
					continue
				}
				findings = append(findings, Finding{
					Kind:        FindingAllowlist,
					Severity:    SeverityLow,
					SkillID:     skill.ID,
					Fingerprint: combo.Fingerprint,
					Message:     "allowlist entry inactive (missing justification or expired); combination resurfaced",
				})
			}
			findings = append(findings, Finding{
				Kind:        FindingCombination,
				Severity:    combo.Severity,
				SkillID:     skill.ID,
				Combo:       combo.Kind,
				Fingerprint: combo.Fingerprint,
				Message:     combo.Message,
				Evidence:    combo.Evidence,
			})
		}
	}
	for _, entry := range allowlist.Allow {
		if _, ok := matched[entry.Fingerprint]; ok {
			continue
		}
		findings = append(findings, Finding{
			Kind:        FindingAllowlist,
			Severity:    SeverityLow,
			Fingerprint: entry.Fingerprint,
			Message:     "allowlist entry does not match any current combination (stale; remove or re-review)",
		})
	}
	return findings
}

func mapHiddenSeverity(sev filescan.Severity) Severity {
	switch sev {
	case filescan.SeverityLow:
		return SeverityLow
	case filescan.SeverityMed:
		return SeverityMedium
	case filescan.SeverityHigh:
		return SeverityHigh
	default:
		return SeverityMedium
	}
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.SkillID != b.SkillID {
			return a.SkillID < b.SkillID
		}
		if a.Severity != b.Severity {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Message < b.Message
	})
}

func uniqueStrings(items []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func (r Result) WriteReport(w io.Writer) {
	bw := bufio.NewWriter(w)
	defer func() { _ = bw.Flush() }()
	for _, skill := range r.Skills {
		_, _ = fmt.Fprintf(bw, "%s inventory: %d capabilities, %d referenced file(s)\n",
			skill.ID, len(skill.Capabilities), len(skill.ReferencedFiles))
		for _, cap := range skill.Capabilities {
			_, _ = fmt.Fprintf(bw, "  %s: %d evidence item(s)\n", cap.Kind, len(cap.Evidence))
		}
	}
	for _, finding := range r.Findings {
		_, _ = fmt.Fprintf(bw, "%s [%s] %s", finding.Kind, finding.Severity, finding.Message)
		if finding.SkillID != "" {
			_, _ = fmt.Fprintf(bw, " (%s)", finding.SkillID)
		}
		if finding.Combo != "" {
			_, _ = fmt.Fprintf(bw, " combo=%s", finding.Combo)
		}
		if finding.Fingerprint != "" {
			_, _ = fmt.Fprintf(bw, " fingerprint=%s", finding.Fingerprint)
		}
		_, _ = bw.WriteString("\n")
		for _, ev := range finding.Evidence {
			_, _ = fmt.Fprintf(bw, "  - %s\n", ev.String())
		}
	}
	_, _ = fmt.Fprintf(bw, "scanned %d file(s), %d skill(s), %d finding(s)\n",
		r.FilesScanned, len(r.Skills), len(r.Findings))
	switch {
	case r.LockRefused:
		_, _ = fmt.Fprintf(bw,
			"lock NOT written to %s: content went unscanned, so a baseline would record an inventory that was never established\n",
			r.LockFile)
	case r.LockFile != "":
		_, _ = fmt.Fprintf(bw, "lock file: %s\n", r.LockFile)
	}
}
