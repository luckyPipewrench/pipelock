// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/rules"
)

const (
	ruleBundlePhaseStartup = "startup"
	ruleBundlePhaseReload  = "reload"

	ruleBundleOutcomeDegraded = "degraded"
	ruleBundleOutcomeRefused  = "refused"
	ruleBundleOutcomeRejected = "rejected"
)

func (s *Server) reportStartupRuleBundleResult(cfg *config.Config, result *rules.LoadResult) error {
	if result == nil {
		return nil
	}
	applyDegradedRuleBundleState(cfg, result.DegradedBundleNames())
	publishDegradedRuleBundleMetrics(s.metrics, cfg)

	for _, e := range result.Errors {
		class := e.ClassOrDefault()
		outcome := ruleBundleOutcomeDegraded
		severity := config.SeverityWarn
		if cfg.Mode == config.ModeStrict && class == rules.BundleErrorClassIntegrity && !cfg.Rules.AllowDegraded {
			outcome = ruleBundleOutcomeRefused
			severity = config.SeverityCritical
		}
		_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: SECURITY WARNING: rule bundle %s degraded (%s): %s\n", e.Name, class, e.Reason)
		s.logger.LogRuleBundleDegraded(e.Name, string(class), e.Reason, ruleBundlePhaseStartup, outcome, severity, cfg.Rules.AllowDegraded, 0)
	}
	for _, w := range result.Warnings {
		_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: %s\n", w)
	}
	if result.Degraded {
		_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: DEGRADED — %d rule bundle(s) unavailable: %s\n",
			len(cfg.Rules.DegradedBundles), strings.Join(cfg.Rules.DegradedBundles, ", "))
		if cfg.Mode == config.ModeStrict && cfg.Rules.AllowDegraded && len(result.IntegrityErrors()) > 0 {
			_, _ = fmt.Fprintln(s.opts.Stderr, "pipelock: SECURITY WARNING: rules.allow_degraded=true; strict mode is booting with degraded rule-bundle integrity after explicit operator opt-in")
		}
	}
	if cfg.Mode != config.ModeStrict || cfg.Rules.AllowDegraded {
		return nil
	}
	for _, e := range result.Errors {
		if e.ClassOrDefault() == rules.BundleErrorClassIntegrity {
			return fmt.Errorf("rule bundle integrity failure in strict mode: bundle %s failed with class %s: %s (verify or reinstall the bundle, or set rules.allow_degraded: true only as an emergency override)",
				e.Name, e.ClassOrDefault(), e.Reason)
		}
	}
	return nil
}

func reportReloadRuleBundleResult(stderr io.Writer, logger ruleBundleAuditLogger, cfg *config.Config, result *rules.LoadResult) {
	if result == nil {
		return
	}
	for _, e := range result.Errors {
		class := e.ClassOrDefault()
		_, _ = fmt.Fprintf(stderr, "WARNING: config reload: rule bundle %s degraded (%s): %s\n", e.Name, class, e.Reason)
		logger.LogRuleBundleDegraded(e.Name, string(class), e.Reason, ruleBundlePhaseReload, ruleBundleOutcomeDegraded, config.SeverityWarn, cfg.Rules.AllowDegraded, 0)
	}
	for _, w := range result.Warnings {
		_, _ = fmt.Fprintf(stderr, "WARNING: config reload: %s\n", w)
	}
	if result.Degraded {
		names := result.DegradedBundleNames()
		_, _ = fmt.Fprintf(stderr, "WARNING: config reload: DEGRADED — %d rule bundle(s) unavailable: %s\n", len(names), strings.Join(names, ", "))
	}
}

type ruleBundleAuditLogger interface {
	LogRuleBundleDegraded(bundle, failureClass, reason, phase, outcome, severity string, allowDegraded bool, droppedPatterns int)
}

func applyDegradedRuleBundleState(cfg *config.Config, names []string) {
	if cfg == nil {
		return
	}
	copied := append([]string(nil), names...)
	sort.Strings(copied)
	cfg.Rules.DegradedBundles = copied
}

func publishDegradedRuleBundleMetrics(m ruleBundleMetrics, cfg *config.Config) {
	if m == nil || cfg == nil {
		return
	}
	m.SetRuleBundlesDegraded(cfg.Rules.DegradedBundles)
}

type ruleBundleMetrics interface {
	SetRuleBundlesDegraded(names []string)
}

type bundleCoverageDrop struct {
	Name       string
	DLP        int
	Response   int
	ToolPoison int
}

func (d bundleCoverageDrop) Total() int {
	return d.DLP + d.Response + d.ToolPoison
}

func (d bundleCoverageDrop) Reason() string {
	var parts []string
	if d.DLP > 0 {
		parts = append(parts, fmt.Sprintf("dlp=%d", d.DLP))
	}
	if d.Response > 0 {
		parts = append(parts, fmt.Sprintf("response=%d", d.Response))
	}
	if d.ToolPoison > 0 {
		parts = append(parts, fmt.Sprintf("tool_poison=%d", d.ToolPoison))
	}
	return "clean bundle removal dropped live patterns: " + strings.Join(parts, ", ")
}

func cleanBundleCoverageDrops(oldCfg, newCfg *config.Config, oldToolPoison []*tools.ExtraPoisonPattern, newToolPoison []rules.CompiledToolPoisonRule) []bundleCoverageDrop {
	if oldCfg == nil || newCfg == nil {
		return nil
	}
	dropsByBundle := make(map[string]*bundleCoverageDrop)
	for _, dropped := range removedBundleDLPPatternDrops(oldCfg.DLP.Patterns, newCfg.DLP.Patterns) {
		drop := coverageDropForBundle(dropsByBundle, dropped.Bundle)
		drop.DLP++
	}
	for _, dropped := range removedBundleResponsePatternDrops(oldCfg.ResponseScanning.Patterns, newCfg.ResponseScanning.Patterns) {
		drop := coverageDropForBundle(dropsByBundle, dropped.Bundle)
		drop.Response++
	}
	for _, dropped := range removedBundleToolPoisonPatternDrops(oldToolPoison, rules.ConvertToolPoison(newToolPoison)) {
		drop := coverageDropForBundle(dropsByBundle, dropped.Bundle)
		drop.ToolPoison++
	}
	drops := make([]bundleCoverageDrop, 0, len(dropsByBundle))
	for _, drop := range dropsByBundle {
		drops = append(drops, *drop)
	}
	sort.Slice(drops, func(i, j int) bool {
		return drops[i].Name < drops[j].Name
	})
	return drops
}

func coverageDropForBundle(drops map[string]*bundleCoverageDrop, name string) *bundleCoverageDrop {
	drop := drops[name]
	if drop == nil {
		drop = &bundleCoverageDrop{Name: name}
		drops[name] = drop
	}
	return drop
}

func appendBundleDropNames(base []string, drops []bundleCoverageDrop) []string {
	seen := make(map[string]struct{}, len(base)+len(drops))
	for _, name := range base {
		if name != "" {
			seen[name] = struct{}{}
		}
	}
	for _, drop := range drops {
		if drop.Name != "" {
			seen[drop.Name] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func bundleCoverageDropSummary(drops []bundleCoverageDrop) string {
	parts := make([]string, 0, len(drops))
	for _, drop := range drops {
		parts = append(parts, fmt.Sprintf("%s dropped %d pattern(s)", drop.Name, drop.Total()))
	}
	return strings.Join(parts, ", ")
}

func filterAllowedRuleBundleCoverageWarnings(oldCfg, newCfg *config.Config, warnings []config.ReloadWarning) []config.ReloadWarning {
	if len(warnings) == 0 {
		return warnings
	}
	dlpBundleOnly := removedOrWeakenedDLPIsBundleOnly(oldCfg.DLP.Patterns, newCfg.DLP.Patterns)
	responseBundleOnly := removedOrWeakenedResponseIsBundleOnly(oldCfg.ResponseScanning.Patterns, newCfg.ResponseScanning.Patterns)
	filtered := make([]config.ReloadWarning, 0, len(warnings))
	for _, w := range warnings {
		switch w.Field {
		case "dlp.patterns":
			if dlpBundleOnly {
				continue
			}
		case "sentry":
			if dlpBundleOnly && strings.Contains(w.Message, "DLP patterns changed") {
				continue
			}
		case "response_scanning.patterns":
			if responseBundleOnly {
				continue
			}
		}
		filtered = append(filtered, w)
	}
	return filtered
}

func removedOrWeakenedDLPIsBundleOnly(old, updated []config.DLPPattern) bool {
	return removedOrWeakenedIsBundleOnly(old, updated,
		func(p config.DLPPattern) string { return p.Name },
		func(p config.DLPPattern) string { return p.Regex },
		func(p config.DLPPattern) string { return p.Bundle })
}

func removedOrWeakenedResponseIsBundleOnly(old, updated []config.ResponseScanPattern) bool {
	return removedOrWeakenedIsBundleOnly(old, updated,
		func(p config.ResponseScanPattern) string { return p.Name },
		func(p config.ResponseScanPattern) string { return p.Regex },
		func(p config.ResponseScanPattern) string { return p.Bundle })
}

func removedOrWeakenedIsBundleOnly[T any](old, updated []T, nameOf, regexOf, bundleOf func(T) string) bool {
	updatedByName := make(map[string]string, len(updated))
	for _, p := range updated {
		updatedByName[nameOf(p)] = regexOf(p)
	}
	var removedBundle, removedNonBundle bool
	for _, p := range old {
		name := nameOf(p)
		updatedRegex, ok := updatedByName[name]
		if ok && updatedRegex == regexOf(p) {
			continue
		}
		if bundleOf(p) == "" {
			removedNonBundle = true
			continue
		}
		removedBundle = true
	}
	return removedBundle && !removedNonBundle
}
