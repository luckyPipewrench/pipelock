// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Confidence ordering for filtering: high=3 > medium=2 > low=1.
var confidenceRank = map[string]int{
	confidenceHigh:   3,
	confidenceMedium: 2,
	confidenceLow:    1,
}

// reservedBundlePrefix is the namespace reserved for official bundles.
const reservedBundlePrefix = "pipelock-"

// LoadOptions controls bundle loading behavior.
type LoadOptions struct {
	MinConfidence       string              // high, medium, low
	IncludeExperimental bool                // load experimental-status rules
	Disabled            []string            // namespaced rule IDs or glob patterns
	TrustedKeys         []config.TrustedKey // additional trusted signing keys
	PipelockVersion     string              // current binary version for min_pipelock check
	AllowStale          bool                // accept expired bundles with warning
	TierKeyMapping      map[string]string   // tier → expected signing key fingerprint
}

// LoadResult contains patterns extracted from all loaded bundles.
type LoadResult struct {
	DLP        []config.DLPPattern
	Injection  []config.ResponseScanPattern
	ToolPoison []CompiledToolPoisonRule
	Errors     []BundleError
	Loaded     []LoadedBundle
	Degraded   bool     // standard pack failed to load — core-only mode
	Warnings   []string // non-fatal warnings (expired bundles, etc.)
}

// CompiledToolPoisonRule is a pre-compiled regex for tool-poison detection.
type CompiledToolPoisonRule struct {
	Name          string
	RuleID        string // namespaced (bundle:rule)
	Re            *regexp.Regexp
	ScanField     string // "description" or "name"
	Bundle        string
	BundleVersion string
}

// BundleError describes a per-bundle load failure.
type BundleError struct {
	Name   string
	Reason string
}

// LoadedBundle describes a successfully loaded bundle (for diagnostics).
type LoadedBundle struct {
	Name             string
	Version          string
	Tier             string // standard, community, pro (v2+)
	MonotonicVersion uint64 // rollback-prevention counter (v2+)
	Source           string
	Rules            int // total rules loaded after filtering
	DLP              int
	Injection        int
	ToolPoison       int
	Unsigned         bool
	Expired          bool // bundle is past expires_at but loaded in stale mode
}

// LoadBundles reads all bundles from rulesDir, verifies integrity,
// filters by options, and returns merged patterns. For v2+ bundles,
// freshness checks (rollback prevention, expiry) are enforced.
// If the standard pack fails to load, Degraded is set to true.
func LoadBundles(rulesDir string, opts LoadOptions) *LoadResult {
	result := &LoadResult{}

	if rulesDir == "" {
		return result
	}

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return result
		}
		// Permission errors, ENOTDIR, I/O failures: report, don't swallow.
		result.Errors = append(result.Errors, BundleError{
			Name:   rulesDir,
			Reason: fmt.Sprintf("reading rules directory: %v", err),
		})
		return result
	}

	// Collect subdirectory names alphabetically (ReadDir returns sorted).
	var dirs []os.DirEntry
	for _, e := range entries {
		// Skip non-directories, hidden staging dirs (.stage-*), and backup dirs (.bak suffix)
		// left by interrupted install/update operations.
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && !strings.HasSuffix(e.Name(), ".bak") {
			dirs = append(dirs, e)
		}
	}

	sort.Slice(dirs, func(i, j int) bool {
		return dirs[i].Name() < dirs[j].Name()
	})

	minRank := confidenceRank[opts.MinConfidence]
	now := time.Now()

	// Load → check → record → save freshness state under flock to prevent
	// concurrent processes from racing on .freshness.json.
	freshnessState := &FreshnessState{HighestSeen: make(map[string]uint64)}
	lockErr := WithFreshnessLock(rulesDir, func() error {
		var err error
		freshnessState, err = LoadFreshnessState(rulesDir)
		if err != nil {
			result.Errors = append(result.Errors, BundleError{
				Name:   ".freshness.json",
				Reason: err.Error(),
			})
			result.Degraded = true
			freshnessState = &FreshnessState{HighestSeen: make(map[string]uint64)}
		}

		for _, d := range dirs {
			bundleDir := filepath.Join(rulesDir, d.Name())
			loadOneBundle(bundleDir, d.Name(), opts, minRank, result, freshnessState, now)
		}

		// Save updated freshness state if any v2+ bundles were loaded.
		for _, lb := range result.Loaded {
			if lb.MonotonicVersion > 0 {
				if saveErr := SaveFreshnessState(rulesDir, freshnessState); saveErr != nil {
					result.Warnings = append(result.Warnings, fmt.Sprintf("saving freshness state: %v", saveErr))
				}
				break
			}
		}
		return nil
	})
	if lockErr != nil {
		// Flock failure: load bundles without freshness protection.
		result.Warnings = append(result.Warnings, fmt.Sprintf("freshness lock: %v (continuing without cross-process protection)", lockErr))
		for _, d := range dirs {
			bundleDir := filepath.Join(rulesDir, d.Name())
			loadOneBundle(bundleDir, d.Name(), opts, minRank, result, freshnessState, now)
		}
	}

	// Detect standard pack degradation: if any bundle with the reserved
	// prefix failed to load, set Degraded flag.
	for _, be := range result.Errors {
		if strings.HasPrefix(be.Name, "pipelock-") {
			result.Degraded = true
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("DEGRADED: standard pack %q failed to load: %s — running core-only", be.Name, be.Reason))
			break
		}
	}

	return result
}

// loadOneBundle loads a single bundle directory and appends results or errors.
func loadOneBundle(bundleDir, dirName string, opts LoadOptions, minRank int, result *LoadResult, freshnessState *FreshnessState, now time.Time) {
	bundlePath := filepath.Join(bundleDir, bundleFilename)
	lockPath := filepath.Join(bundleDir, lockFilename)

	// Read and size-check bundle.yaml.
	data, err := readBundleFile(bundlePath)
	if err != nil {
		result.Errors = append(result.Errors, BundleError{Name: dirName, Reason: err.Error()})
		return
	}

	// Read lock file.
	lock, err := ReadLockFile(lockPath)
	if err != nil {
		result.Errors = append(result.Errors, BundleError{Name: dirName, Reason: fmt.Sprintf("reading lock file: %v", err)})
		return
	}

	// Verify integrity against the exact bytes we just read (no TOCTOU).
	if err := VerifyIntegrityBytes(data, bundleDir, lock.Unsigned, lock.SignerFingerprint, lock.BundleSHA256, opts.TrustedKeys); err != nil {
		result.Errors = append(result.Errors, BundleError{Name: dirName, Reason: fmt.Sprintf("integrity check: %v", err)})
		return
	}

	// Parse and validate bundle YAML.
	bundle, err := ParseBundle(data)
	if err != nil {
		result.Errors = append(result.Errors, BundleError{Name: dirName, Reason: fmt.Sprintf("parse error: %v", err)})
		return
	}

	// Check min_pipelock version requirement.
	if err := CheckMinPipelock(bundle.MinPipelock, opts.PipelockVersion); err != nil {
		result.Errors = append(result.Errors, BundleError{Name: dirName, Reason: err.Error()})
		return
	}

	// Check pipelock-* name reservation: only official signers allowed.
	if strings.HasPrefix(bundle.Name, reservedBundlePrefix) {
		if !isOfficialFingerprint(lock.SignerFingerprint) {
			result.Errors = append(result.Errors, BundleError{
				Name:   dirName,
				Reason: fmt.Sprintf("bundle name %q uses reserved prefix %q but signer is not official", bundle.Name, reservedBundlePrefix),
			})
			return
		}
	}

	// V2+ freshness checks: rollback prevention, expiry, tier-key binding.
	if bundle.FormatVersion >= 2 {
		// V2 bundles MUST be signed. Unsigned v2 bundles could forge any
		// tier/key_id and bypass tier-key binding entirely.
		if lock.Unsigned {
			result.Errors = append(result.Errors, BundleError{
				Name:   dirName,
				Reason: "format_version 2 bundles must be signed (unsigned v2 bundles are rejected)",
			})
			return
		}

		// Tier-key binding: verify the signing key matches the declared tier.
		if err := CheckTierKeyBinding(bundle, lock.SignerFingerprint, opts.TierKeyMapping); err != nil {
			result.Errors = append(result.Errors, BundleError{Name: dirName, Reason: err.Error()})
			return
		}

		// Freshness: rollback prevention and expiry.
		fr := CheckFreshness(bundle, freshnessState, now, opts.AllowStale)
		if !fr.OK {
			result.Errors = append(result.Errors, BundleError{Name: dirName, Reason: fr.Message})
			return
		}
		if fr.Expired {
			result.Warnings = append(result.Warnings, fr.Message)
		}

		// Record version for future rollback prevention.
		RecordVersion(freshnessState, bundle.Tier, bundle.Name, bundle.MonotonicVersion)
	}

	// Filter and convert rules.
	loaded := LoadedBundle{
		Name:             bundle.Name,
		Version:          bundle.Version,
		Tier:             bundle.Tier,
		MonotonicVersion: bundle.MonotonicVersion,
		Source:           lock.Source,
		Unsigned:         lock.Unsigned,
	}

	for i := range bundle.Rules {
		r := &bundle.Rules[i]

		// Status filter: deprecated always skipped.
		if r.Status == StatusDeprecated {
			continue
		}

		// Status filter: experimental skipped unless opted in.
		if r.Status == StatusExperimental && !opts.IncludeExperimental {
			continue
		}

		// Confidence filter.
		ruleRank := confidenceRank[r.Confidence]
		if ruleRank < minRank {
			continue
		}

		// Disabled filter: check namespaced ID against exact match and globs.
		nsID := NamespacedID(bundle.Name, r.ID)
		if isDisabled(nsID, opts.Disabled) {
			continue
		}

		// Convert rule to config-compatible type.
		switch r.Type {
		case RuleTypeDLP:
			result.DLP = append(result.DLP, config.DLPPattern{
				Name:          nsID,
				Regex:         r.Pattern.Regex,
				Severity:      r.Severity,
				Bundle:        bundle.Name,
				BundleVersion: bundle.Version,
			})
			loaded.DLP++

		case RuleTypeInjection:
			result.Injection = append(result.Injection, config.ResponseScanPattern{
				Name:          nsID,
				Regex:         r.Pattern.Regex,
				Bundle:        bundle.Name,
				BundleVersion: bundle.Version,
			})
			loaded.Injection++

		case RuleTypeToolPoison:
			// Tool-poison regexes use case-insensitive matching.
			compiled, err := regexp.Compile("(?i)" + r.Pattern.Regex)
			if err != nil {
				// Pattern was already validated by ParseBundle, but guard anyway.
				continue
			}
			result.ToolPoison = append(result.ToolPoison, CompiledToolPoisonRule{
				Name:          nsID,
				RuleID:        nsID,
				Re:            compiled,
				ScanField:     r.Pattern.ScanField,
				Bundle:        bundle.Name,
				BundleVersion: bundle.Version,
			})
			loaded.ToolPoison++
		}
	}

	loaded.Rules = loaded.DLP + loaded.Injection + loaded.ToolPoison
	result.Loaded = append(result.Loaded, loaded)
}

// readBundleFile reads bundle.yaml with a size check.
func readBundleFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat bundle file: %w", err)
	}

	if info.Size() > MaxBundleFileSize {
		return nil, fmt.Errorf("bundle file size %d exceeds maximum %d bytes", info.Size(), MaxBundleFileSize)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading bundle file: %w", err)
	}

	return data, nil
}

// isDisabled checks whether a namespaced rule ID matches any entry in the
// disabled list. Exact string match is tried first, then glob patterns
// using path.Match (not filepath.Match, which is OS-specific).
func isDisabled(nsID string, disabled []string) bool {
	for _, pattern := range disabled {
		// Exact match first.
		if nsID == pattern {
			return true
		}

		// Glob match (path.Match uses forward-slash semantics, suitable
		// for colon-separated namespace IDs).
		if matched, err := path.Match(pattern, nsID); err == nil && matched {
			return true
		}
	}

	return false
}

// isOfficialFingerprint checks whether the given fingerprint matches any
// key in the embedded keyring. This compares hex fingerprint strings rather
// than raw keys, since the lock file stores the fingerprint, not the key.
func isOfficialFingerprint(fp string) bool {
	for _, key := range EmbeddedKeyring() {
		if KeyFingerprint(key) == fp {
			return true
		}
	}
	return false
}
