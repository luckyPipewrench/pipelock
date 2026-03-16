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
}

// LoadResult contains patterns extracted from all loaded bundles.
type LoadResult struct {
	DLP        []config.DLPPattern
	Injection  []config.ResponseScanPattern
	ToolPoison []CompiledToolPoisonRule
	Errors     []BundleError
	Loaded     []LoadedBundle
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
	Name       string
	Version    string
	Source     string
	Rules      int // total rules loaded after filtering
	DLP        int
	Injection  int
	ToolPoison int
	Unsigned   bool
}

// LoadBundles reads all bundles from rulesDir, verifies integrity,
// filters by options, and returns merged patterns.
func LoadBundles(rulesDir string, opts LoadOptions) *LoadResult {
	result := &LoadResult{}

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		// Non-existent dir is normal (no bundles installed).
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

	for _, d := range dirs {
		bundleDir := filepath.Join(rulesDir, d.Name())
		loadOneBundle(bundleDir, d.Name(), opts, minRank, result)
	}

	return result
}

// loadOneBundle loads a single bundle directory and appends results or errors.
func loadOneBundle(bundleDir, dirName string, opts LoadOptions, minRank int, result *LoadResult) {
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

	// Verify integrity (signature or SHA-256).
	if err := VerifyIntegrity(bundleDir, lock.Unsigned, lock.SignerFingerprint, lock.BundleSHA256, opts.TrustedKeys); err != nil {
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

	// Filter and convert rules.
	loaded := LoadedBundle{
		Name:     bundle.Name,
		Version:  bundle.Version,
		Source:   lock.Source,
		Unsigned: lock.Unsigned,
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
				ExemptDomains: r.Pattern.ExemptDomains,
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
