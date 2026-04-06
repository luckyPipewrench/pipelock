// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
)

// FreshnessState tracks the highest seen version per bundle identity for
// rollback prevention. Stored at ~/.local/share/pipelock/rules/.freshness.json.
// Concurrent access is protected by withFreshnessLock (flock-based).
type FreshnessState struct {
	HighestSeen map[string]uint64 `json:"highest_seen"` // "tier:name" → monotonic_version
}

// freshnessFilename is the state file for version tracking.
const freshnessFilename = ".freshness.json"

// WithFreshnessLock acquires an exclusive flock on a lock file in rulesDir,
// runs fn, then releases the lock. Prevents concurrent pipelock processes
// from racing on the freshness state file.
func WithFreshnessLock(rulesDir string, fn func() error) error {
	lockPath := filepath.Join(rulesDir, freshnessFilename+".lock")
	f, err := os.OpenFile(filepath.Clean(lockPath), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("freshness lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	fd := int(f.Fd()) //nolint:gosec // Fd() returns a valid file descriptor, no overflow risk on 64-bit
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("freshness lock acquire: %w", err)
	}
	defer func() { _ = syscall.Flock(fd, syscall.LOCK_UN) }()
	return fn()
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
			// Allow stale with warning — caller should emit a loud warning.
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
// Returns an error if the file exists but is unreadable or corrupt — this
// fails closed to prevent an attacker from bypassing rollback protection
// by corrupting the state file. Delete the file manually to reset.
func LoadFreshnessState(rulesDir string) (*FreshnessState, error) {
	path := filepath.Join(rulesDir, freshnessFilename)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return &FreshnessState{HighestSeen: make(map[string]uint64)}, nil
		}
		// Fail closed: corrupt/unreadable state could mask rollback.
		return nil, fmt.Errorf("load freshness state: %w (fail-closed: delete %s to reset)", err, path)
	}

	var state FreshnessState
	if err := json.Unmarshal(data, &state); err != nil {
		// Fail closed: corrupted JSON could mask rollback.
		return nil, fmt.Errorf("parse freshness state: %w (fail-closed: delete %s to reset)", err, path)
	}
	if state.HighestSeen == nil {
		state.HighestSeen = make(map[string]uint64)
	}
	return &state, nil
}

// SaveFreshnessState writes the freshness state to the rules directory.
func SaveFreshnessState(rulesDir string, state *FreshnessState) error {
	path := filepath.Join(rulesDir, freshnessFilename)
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal freshness state: %w", err)
	}
	return atomicfile.Write(filepath.Clean(path), data, 0o600)
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
