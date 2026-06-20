// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
)

// FreshnessState tracks the highest seen version per bundle identity for
// rollback prevention. Stored at ~/.local/share/pipelock/rules/.freshness.json.
// Concurrent access is protected by WithFreshnessLock (flock on Unix, no-op on Windows).
type FreshnessState struct {
	HighestSeen map[string]uint64 `json:"highest_seen"` // "tier:name" → monotonic_version
	Context     string            `json:"context,omitempty"`
	Digest      string            `json:"digest,omitempty"`
}

// freshnessFilename is the state file for version tracking.
const freshnessFilename = ".freshness.json"

const freshnessContextFile = "context.json"

type freshnessContext struct {
	Context string `json:"context"`
}

// FreshnessResult describes the outcome of freshness validation.
type FreshnessResult struct {
	OK       bool
	Expired  bool   // bundle is past expires_at
	Rollback bool   // version < highest_seen
	Message  string // human-readable explanation
}

// freshnessKey returns the state map key for a bundle identity.
// Using tier:name ensures that bundles sharing a tier track versions
// independently (e.g., two community bundles don't block each other).
func freshnessKey(tier, name string) string {
	return tier + ":" + name
}

// CheckFreshness validates a v2+ bundle's freshness against stored state.
// Returns OK=true if the bundle passes all checks.
//
// Checks (in order):
//  1. Version >= highest_seen for this bundle identity (rollback prevention)
//  2. Not expired (expires_at > now), unless allowStale is true
//  3. min_pipelock version satisfied (handled separately by caller)
func CheckFreshness(b *Bundle, state *FreshnessState, now time.Time, allowStale bool) FreshnessResult {
	if b.FormatVersion < 2 {
		return FreshnessResult{OK: true}
	}

	// Rollback prevention: reject if version < highest seen for this bundle.
	key := freshnessKey(b.Tier, b.Name)
	if highest, ok := state.HighestSeen[key]; ok {
		if b.MonotonicVersion < highest {
			return FreshnessResult{
				Rollback: true,
				Message: fmt.Sprintf("version rollback: bundle %q v%d is below highest seen v%d for tier %q",
					b.Name, b.MonotonicVersion, highest, b.Tier),
			}
		}
	}

	// Expiry check.
	if b.ExpiresAt != "" {
		expiresAt, err := parseRFC3339(b.ExpiresAt)
		if err == nil && now.After(expiresAt) {
			if !allowStale {
				return FreshnessResult{
					Expired: true,
					Message: fmt.Sprintf("bundle %q expired at %s (use --allow-stale to override)",
						b.Name, b.ExpiresAt),
				}
			}
			// Allow stale with warning - caller should emit a loud warning.
			return FreshnessResult{
				OK:      true,
				Expired: true,
				Message: fmt.Sprintf("WARNING: bundle %q expired at %s (running in stale mode)", b.Name, b.ExpiresAt),
			}
		}
	}

	return FreshnessResult{OK: true}
}

// RecordVersion updates the freshness state with the bundle's version.
// Should be called after a bundle passes all validation checks.
func RecordVersion(state *FreshnessState, tier, name string, version uint64) {
	if state.HighestSeen == nil {
		state.HighestSeen = make(map[string]uint64)
	}
	key := freshnessKey(tier, name)
	if version > state.HighestSeen[key] {
		state.HighestSeen[key] = version
	}
}

// LoadFreshnessState reads the freshness state from the rules directory.
// Returns an empty state if the file doesn't exist (first run).
// Returns an error if the file exists but is unreadable or corrupt - this
// fails closed to prevent an attacker from bypassing rollback protection
// by corrupting the state file. Delete the file manually to reset.
func LoadFreshnessState(rulesDir string) (*FreshnessState, error) {
	state, found, err := readFreshnessStatePair(rulesDir)
	if err != nil {
		return nil, err
	}
	if found {
		return state, nil
	}
	return &FreshnessState{HighestSeen: make(map[string]uint64)}, nil
}

func readFreshnessStatePair(rulesDir string) (*FreshnessState, bool, error) {
	primary, primaryFound, err := readFreshnessStateFile(filepath.Join(rulesDir, freshnessFilename), rulesDir, "freshness state")
	if err != nil {
		return nil, false, err
	}
	secondary, secondaryFound, err := readFreshnessStateFile(freshnessSecondaryPath(rulesDir), rulesDir, "freshness secondary state")
	if err != nil {
		return nil, false, err
	}
	switch {
	case primaryFound && secondaryFound:
		if !freshnessStatesEqual(primary, secondary) {
			return nil, false, fmt.Errorf("freshness state mismatch between primary and secondary copy")
		}
		return primary, true, nil
	case primaryFound:
		if err := writeFreshnessStateFile(freshnessSecondaryPath(rulesDir), rulesDir, primary); err != nil {
			return nil, false, fmt.Errorf("backfill freshness secondary state: %w", err)
		}
		if err := writeFreshnessContext(rulesDir); err != nil {
			return nil, false, fmt.Errorf("backfill freshness context: %w", err)
		}
		return primary, true, nil
	case secondaryFound:
		if err := writeFreshnessStateFile(filepath.Join(rulesDir, freshnessFilename), rulesDir, secondary); err != nil {
			return nil, false, fmt.Errorf("restore freshness primary state: %w", err)
		}
		if err := writeFreshnessContext(rulesDir); err != nil {
			return nil, false, fmt.Errorf("backfill freshness context: %w", err)
		}
		return secondary, true, nil
	default:
		contextFound, contextErr := readFreshnessContext(rulesDir)
		if contextErr != nil {
			return nil, false, contextErr
		}
		if contextFound {
			return nil, false, fmt.Errorf("freshness state missing while freshness context is present (fail-closed: run `pipelock rules reset-freshness --rules-dir %s` after verifying installed bundles)", rulesDir)
		}
		return nil, false, nil
	}
}

func readFreshnessStateFile(path, rulesDir, label string) (*FreshnessState, bool, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		// Fail closed: corrupt/unreadable state could mask rollback.
		return nil, false, fmt.Errorf("load %s: %w (fail-closed: run explicit reset)", label, err)
	}

	var state FreshnessState
	if err := json.Unmarshal(data, &state); err != nil {
		// Fail closed: corrupted JSON could mask rollback.
		return nil, false, fmt.Errorf("parse %s: %w (fail-closed: run explicit reset)", label, err)
	}
	if state.HighestSeen == nil {
		state.HighestSeen = make(map[string]uint64)
	}
	if state.Context != "" && state.Context != freshnessContextID(rulesDir) {
		return nil, false, fmt.Errorf("%s context mismatch", label)
	}
	if state.Digest != "" && state.Digest != freshnessDigest(rulesDir, state.HighestSeen) {
		return nil, false, fmt.Errorf("%s digest mismatch", label)
	}
	return &state, true, nil
}

// SaveFreshnessState writes the freshness state to the rules directory.
func SaveFreshnessState(rulesDir string, state *FreshnessState) error {
	path := filepath.Join(rulesDir, freshnessFilename)
	if err := writeFreshnessStateFile(path, rulesDir, state); err != nil {
		return err
	}
	if err := writeFreshnessStateFile(freshnessSecondaryPath(rulesDir), rulesDir, state); err != nil {
		return err
	}
	if err := writeFreshnessContext(rulesDir); err != nil {
		return err
	}
	return nil
}

func writeFreshnessStateFile(path, rulesDir string, state *FreshnessState) error {
	if err := os.MkdirAll(filepath.Dir(filepath.Clean(path)), 0o750); err != nil {
		return fmt.Errorf("create freshness state dir: %w", err)
	}
	copyState := &FreshnessState{HighestSeen: make(map[string]uint64, len(state.HighestSeen))}
	for key, value := range state.HighestSeen {
		copyState.HighestSeen[key] = value
	}
	copyState.Context = freshnessContextID(rulesDir)
	copyState.Digest = freshnessDigest(rulesDir, copyState.HighestSeen)
	data, err := json.MarshalIndent(copyState, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal freshness state: %w", err)
	}
	return atomicfile.Write(filepath.Clean(path), data, 0o600)
}

func freshnessSecondaryPath(rulesDir string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(rulesDir)))
	return filepath.Join(rulesDir, ".pipelock-state", "rules-freshness", hex.EncodeToString(sum[:16])+".json")
}

func freshnessContextPath(rulesDir string) string {
	return filepath.Join(rulesDir, ".pipelock-state", "rules-freshness", freshnessContextFile)
}

func freshnessContextID(rulesDir string) string {
	sum := sha256.Sum256([]byte("rules-freshness-v1\n" + filepath.Clean(rulesDir)))
	return hex.EncodeToString(sum[:])
}

func freshnessDigest(rulesDir string, highest map[string]uint64) string {
	keys := make([]string, 0, len(highest))
	for key := range highest {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("rules-freshness-v1\n")
	b.WriteString(freshnessContextID(rulesDir))
	for _, key := range keys {
		_, _ = fmt.Fprintf(&b, "\n%s=%d", key, highest[key])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func readFreshnessContext(rulesDir string) (bool, error) {
	data, err := os.ReadFile(filepath.Clean(freshnessContextPath(rulesDir))) // #nosec G304 -- path derives from configured rules dir
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read freshness context: %w", err)
	}
	var ctx freshnessContext
	if err := json.Unmarshal(data, &ctx); err != nil {
		return false, fmt.Errorf("parse freshness context: %w", err)
	}
	if ctx.Context != freshnessContextID(rulesDir) {
		return false, fmt.Errorf("freshness context mismatch")
	}
	return true, nil
}

func writeFreshnessContext(rulesDir string) error {
	path := freshnessContextPath(rulesDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create freshness context dir: %w", err)
	}
	data, err := json.Marshal(freshnessContext{Context: freshnessContextID(rulesDir)})
	if err != nil {
		return fmt.Errorf("marshal freshness context: %w", err)
	}
	return atomicfile.Write(filepath.Clean(path), append(data, '\n'), 0o600)
}

func freshnessStatesEqual(a, b *FreshnessState) bool {
	if len(a.HighestSeen) != len(b.HighestSeen) {
		return false
	}
	for key, value := range a.HighestSeen {
		if b.HighestSeen[key] != value {
			return false
		}
	}
	return true
}

func installedFreshnessContextPresent(rulesDir string) (bool, error) {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read rules directory for freshness context: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || strings.HasSuffix(entry.Name(), ".bak") {
			continue
		}
		bundleDir := filepath.Join(rulesDir, entry.Name())
		if _, err := os.Stat(filepath.Join(bundleDir, lockFilename)); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return false, fmt.Errorf("stat bundle lock for freshness context: %w", err)
		}
		data, err := os.ReadFile(filepath.Clean(filepath.Join(bundleDir, bundleFilename))) // #nosec G304 -- path is below configured rules dir
		if err != nil {
			return false, fmt.Errorf("read bundle for freshness context: %w", err)
		}
		bundle, err := ParseBundle(data)
		if err != nil {
			return false, fmt.Errorf("parse bundle for freshness context: %w", err)
		}
		if bundle.FormatVersion >= 2 {
			return true, nil
		}
	}
	return false, nil
}

// ResetFreshnessStateFromInstalledBundles explicitly seeds rollback floors from
// currently installed v2+ bundles. It is the operator recovery path after a
// legitimate state migration or wipe.
func ResetFreshnessStateFromInstalledBundles(rulesDir string) error {
	state := &FreshnessState{HighestSeen: make(map[string]uint64)}
	contextPresent, err := installedFreshnessContextPresent(rulesDir)
	if err != nil {
		return err
	}
	if !contextPresent {
		return SaveFreshnessState(rulesDir, state)
	}
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return SaveFreshnessState(rulesDir, state)
		}
		return fmt.Errorf("read rules directory for freshness reset: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || strings.HasSuffix(entry.Name(), ".bak") {
			continue
		}
		bundleDir := filepath.Join(rulesDir, entry.Name())
		if _, err := os.Stat(filepath.Join(bundleDir, lockFilename)); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("stat bundle lock for freshness reset: %w", err)
		}
		data, err := os.ReadFile(filepath.Clean(filepath.Join(bundleDir, bundleFilename))) // #nosec G304 -- path is below configured rules dir
		if err != nil {
			return fmt.Errorf("read bundle for freshness reset: %w", err)
		}
		bundle, err := ParseBundle(data)
		if err != nil {
			return fmt.Errorf("parse bundle for freshness reset: %w", err)
		}
		if bundle.FormatVersion >= 2 {
			RecordVersion(state, bundle.Tier, bundle.Name, bundle.MonotonicVersion)
		}
	}
	return SaveFreshnessState(rulesDir, state)
}

// CheckTierKeyBinding verifies that a bundle's key_id matches the expected
// signing key for its tier. This prevents a compromised community key from
// signing bundles that claim to be standard tier.
//
// keyMapping maps tier names to expected key_id values. If no mapping is
// configured for a tier, the check passes (future tier support).
func CheckTierKeyBinding(b *Bundle, signerFingerprint string, keyMapping map[string]string) error {
	if b.FormatVersion < 2 || b.KeyID == "" {
		return nil
	}

	// Verify key_id matches the signer fingerprint.
	if b.KeyID != signerFingerprint {
		return fmt.Errorf("key_id mismatch: bundle declares %q but signed by %q", b.KeyID, signerFingerprint)
	}

	// Verify tier-key binding if mapping is configured.
	if expectedKey, ok := keyMapping[b.Tier]; ok {
		if signerFingerprint != expectedKey {
			return fmt.Errorf("tier-key binding: tier %q requires key %q but signed by %q",
				b.Tier, expectedKey, signerFingerprint)
		}
	}

	return nil
}
