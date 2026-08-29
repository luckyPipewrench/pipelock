// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/securefile"
)

const (
	bundleTransactionDir      = "rules-transactions"
	bundleTransactionVersion  = 1
	maxBundleTransactionBytes = 1 << 20
)

// BundleTransactionRedo is a durable, self-describing redo record for a bundle
// swap whose candidate must not become visible without its freshness floor.
// It deliberately contains the candidate identity and the complete intended
// monotonic state, rather than a "commit pending" bit.
type BundleTransactionRedo struct {
	Version       int             `json:"version"`
	BundleName    string          `json:"bundle_name"`
	Candidate     bundleCandidate `json:"candidate"`
	NextFreshness FreshnessState  `json:"next_freshness"`
	Prior         *bundleArtifact `json:"prior,omitempty"`
}

type bundleCandidate struct {
	SHA256           string    `json:"sha256"`
	SignatureSHA256  string    `json:"signature_sha256,omitempty"`
	SignaturePresent bool      `json:"signature_present"`
	Name             string    `json:"name"`
	Version          string    `json:"version"`
	FormatVersion    int       `json:"format_version"`
	Tier             string    `json:"tier"`
	MonotonicVersion uint64    `json:"monotonic_version"`
	Lock             *LockFile `json:"lock"`
}

type bundleArtifact struct {
	BundleSHA256 string `json:"bundle_sha256"`
	LockSHA256   string `json:"lock_sha256"`
}

// NewBundleTransactionRedo describes the already-validated candidate and the
// freshness state that must be durable before it can remain active.
func NewBundleTransactionRedo(bundleName string, bundleData, sigData []byte, bundle *Bundle, lock *LockFile, next *FreshnessState) (*BundleTransactionRedo, error) {
	if bundle == nil || lock == nil || next == nil {
		return nil, fmt.Errorf("bundle transaction requires bundle, lock, and freshness state")
	}
	if bundleName == "" || bundle.Name != bundleName {
		return nil, fmt.Errorf("bundle transaction name mismatch")
	}
	digest := sha256Hex(bundleData)
	signatureDigest := ""
	if sigData != nil {
		signatureDigest = sha256Hex(sigData)
	}
	return &BundleTransactionRedo{
		Version:    bundleTransactionVersion,
		BundleName: bundleName,
		Candidate: bundleCandidate{
			SHA256: digest, SignatureSHA256: signatureDigest, SignaturePresent: sigData != nil, Name: bundle.Name, Version: bundle.Version,
			FormatVersion: bundle.FormatVersion, Tier: bundle.Tier, MonotonicVersion: bundle.MonotonicVersion,
			Lock: cloneLockFile(lock),
		},
		NextFreshness: *cloneFreshnessStateForTransaction(next),
	}, nil
}

// WriteBundleTransactionRedo persists the redo record before either rename in
// the bundle swap. It also captures the exact prior artifact, if one exists,
// so recovery can distinguish a pre-swap crash from an active candidate.
func WriteBundleTransactionRedo(rulesDir string, redo *BundleTransactionRedo) (string, error) {
	if redo == nil {
		return "", nil
	}
	if err := validateRedoShape(redo); err != nil {
		return "", err
	}
	prior, err := bundleArtifactFingerprint(filepath.Join(rulesDir, redo.BundleName))
	if err != nil {
		return "", fmt.Errorf("fingerprint prior bundle: %w", err)
	}
	copyRedo := *redo
	copyRedo.Prior = prior
	data, err := json.Marshal(&copyRedo)
	if err != nil {
		return "", fmt.Errorf("marshal bundle transaction: %w", err)
	}
	if len(data) > maxBundleTransactionBytes {
		return "", fmt.Errorf("bundle transaction exceeds %d bytes", maxBundleTransactionBytes)
	}
	path := bundleTransactionPath(rulesDir, redo.BundleName)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", fmt.Errorf("create bundle transaction directory: %w", err)
	}
	if err := atomicfile.Write(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write bundle transaction: %w", err)
	}
	return path, nil
}

func RemoveBundleTransactionRedo(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(filepath.Clean(path)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove bundle transaction: %w", err)
	}
	return nil
}

// RecoverBundleTransactions recovers every interrupted freshness-aware bundle
// swap before any consumer is allowed to read bundles or freshness state.
func RecoverBundleTransactions(rulesDir string) error {
	return WithFreshnessLock(rulesDir, func() error {
		return RecoverBundleTransactionsLocked(rulesDir)
	})
}

// RecoverBundleTransactionsLocked is RecoverBundleTransactions for callers
// that already own WithFreshnessLock.
func RecoverBundleTransactionsLocked(rulesDir string) error {
	dir := filepath.Join(rulesDir, ".pipelock-state", bundleTransactionDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		// A non-directory .pipelock-state cannot contain a redo record. Leave
		// the existing freshness-state reader to report its more specific
		// fail-closed error for that broken state layout.
		if parent, statErr := os.Stat(filepath.Dir(dir)); statErr == nil && !parent.IsDir() {
			return nil
		}
		return fmt.Errorf("read bundle transactions: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), ".tmp-") {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove abandoned bundle transaction temp file %q: %w", entry.Name(), err)
			}
			continue
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return fmt.Errorf("invalid bundle transaction artifact %q (fail-closed)", entry.Name())
		}
		path := filepath.Join(dir, entry.Name())
		redo, err := readBundleTransactionRedo(path)
		if err != nil {
			return err
		}
		if err := recoverBundleTransactionRedo(rulesDir, path, redo); err != nil {
			return err
		}
	}
	return nil
}

func recoverBundleTransactionRedo(rulesDir, recordPath string, redo *BundleTransactionRedo) error {
	dest := filepath.Join(rulesDir, redo.BundleName)
	current, err := bundleArtifactFingerprint(dest)
	if err != nil {
		return fmt.Errorf("recover bundle transaction %q: fingerprint destination: %w", redo.BundleName, err)
	}
	if current == nil {
		// The candidate was not renamed. A prior bundle may have been moved out;
		// restore only the exact artifact the record observed.
		if redo.Prior != nil {
			backup := dest + ".bak"
			backupFP, fpErr := bundleArtifactFingerprint(backup)
			if fpErr != nil {
				return fmt.Errorf("recover bundle transaction %q: fingerprint backup: %w", redo.BundleName, fpErr)
			}
			if !artifactsEqual(backupFP, redo.Prior) {
				return fmt.Errorf("recover bundle transaction %q: missing candidate and prior backup does not match redo record (fail-closed; preserving artifacts)", redo.BundleName)
			}
			if err := os.Rename(backup, dest); err != nil {
				return fmt.Errorf("recover bundle transaction %q: restore prior bundle: %w", redo.BundleName, err)
			}
		}
		if err := RemoveBundleTransactionRedo(recordPath); err != nil {
			return fmt.Errorf("recover bundle transaction %q: %w", redo.BundleName, err)
		}
		return nil
	}

	if candidateErr := validateActiveCandidate(dest, redo); candidateErr != nil {
		if artifactsEqual(current, redo.Prior) {
			// The record was durable but the old bundle was still active.
			if err := RemoveBundleTransactionRedo(recordPath); err != nil {
				return fmt.Errorf("recover bundle transaction %q: %w", redo.BundleName, err)
			}
			return nil
		}
		return fmt.Errorf("recover bundle transaction %q: %w (fail-closed; preserving artifacts)", redo.BundleName, candidateErr)
	}

	state, err := LoadFreshnessStateLocked(rulesDir)
	if err != nil {
		return fmt.Errorf("recover bundle transaction %q: load freshness state: %w", redo.BundleName, err)
	}
	mergeFreshnessState(state, &redo.NextFreshness)
	if err := SaveFreshnessState(rulesDir, state); err != nil {
		return fmt.Errorf("recover bundle transaction %q: persist merged freshness state: %w", redo.BundleName, err)
	}
	if redo.Prior != nil {
		backupFP, fpErr := bundleArtifactFingerprint(dest + ".bak")
		if fpErr != nil {
			return fmt.Errorf("recover bundle transaction %q: fingerprint prior backup: %w", redo.BundleName, fpErr)
		}
		if backupFP != nil && !artifactsEqual(backupFP, redo.Prior) {
			return fmt.Errorf("recover bundle transaction %q: prior backup does not match redo record (fail-closed; preserving artifacts)", redo.BundleName)
		}
		if err := os.RemoveAll(dest + ".bak"); err != nil {
			return fmt.Errorf("recover bundle transaction %q: remove prior backup: %w", redo.BundleName, err)
		}
	}
	if err := RemoveBundleTransactionRedo(recordPath); err != nil {
		return fmt.Errorf("recover bundle transaction %q: %w", redo.BundleName, err)
	}
	return nil
}

func validateActiveCandidate(dest string, redo *BundleTransactionRedo) error {
	data, err := ReadBundleFile(filepath.Join(dest, bundleFilename))
	if err != nil {
		return fmt.Errorf("read candidate bundle: %w", err)
	}
	if sha256Hex(data) != redo.Candidate.SHA256 {
		return fmt.Errorf("candidate digest mismatch")
	}
	signatureData, sigErr := os.ReadFile(filepath.Clean(filepath.Join(dest, bundleFilename+".sig")))
	if redo.Candidate.SignaturePresent {
		if sigErr != nil {
			return fmt.Errorf("read candidate signature: %w", sigErr)
		}
		if sha256Hex(signatureData) != redo.Candidate.SignatureSHA256 {
			return fmt.Errorf("candidate signature digest mismatch")
		}
	} else if sigErr == nil {
		return fmt.Errorf("unexpected candidate signature")
	} else if !os.IsNotExist(sigErr) {
		return fmt.Errorf("read candidate signature: %w", sigErr)
	}
	bundle, err := ParseBundle(data)
	if err != nil {
		return fmt.Errorf("parse candidate bundle: %w", err)
	}
	if bundle.Name != redo.Candidate.Name || bundle.Version != redo.Candidate.Version || bundle.FormatVersion != redo.Candidate.FormatVersion || bundle.Tier != redo.Candidate.Tier || bundle.MonotonicVersion != redo.Candidate.MonotonicVersion {
		return fmt.Errorf("candidate metadata mismatch")
	}
	lock, err := ReadLockFile(filepath.Join(dest, lockFilename))
	if err != nil {
		return fmt.Errorf("read candidate lock: %w", err)
	}
	if !lockFilesEqual(lock, redo.Candidate.Lock) || lock.BundleSHA256 != redo.Candidate.SHA256 {
		return fmt.Errorf("candidate lock mismatch")
	}
	return nil
}

func readBundleTransactionRedo(path string) (*BundleTransactionRedo, error) {
	data, err := securefile.Read(path, securefile.Options{MaxBytes: maxBundleTransactionBytes, OwnedState: true})
	if err != nil {
		return nil, fmt.Errorf("read bundle transaction: %w (fail-closed)", err)
	}
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("parse bundle transaction: %w (fail-closed)", err)
	}
	var redo BundleTransactionRedo
	if err := json.Unmarshal(data, &redo); err != nil {
		return nil, fmt.Errorf("parse bundle transaction: %w (fail-closed)", err)
	}
	if err := validateRedoShape(&redo); err != nil {
		return nil, fmt.Errorf("invalid bundle transaction: %w (fail-closed)", err)
	}
	return &redo, nil
}

func validateRedoShape(redo *BundleTransactionRedo) error {
	if redo.Version != bundleTransactionVersion || redo.BundleName == "" || redo.BundleName == "." || redo.BundleName == ".." || filepath.Base(redo.BundleName) != redo.BundleName {
		return fmt.Errorf("unsupported version or invalid bundle name")
	}
	if redo.Candidate.Lock == nil || redo.Candidate.Name != redo.BundleName || redo.Candidate.SHA256 == "" || (redo.Candidate.SignaturePresent && redo.Candidate.SignatureSHA256 == "") {
		return fmt.Errorf("missing or inconsistent candidate identity")
	}
	return nil
}

func bundleTransactionPath(rulesDir, bundleName string) string {
	sum := sha256.Sum256([]byte("rules-transaction-v1\n" + bundleName))
	return filepath.Join(rulesDir, ".pipelock-state", bundleTransactionDir, hex.EncodeToString(sum[:16])+".json")
}

func bundleArtifactFingerprint(dir string) (*bundleArtifact, error) {
	bundleData, err := ReadBundleFile(filepath.Join(dir, bundleFilename))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	lockData, err := ReadBundleFile(filepath.Join(dir, lockFilename))
	if err != nil {
		return nil, fmt.Errorf("read bundle lock: %w", err)
	}
	return &bundleArtifact{BundleSHA256: sha256Hex(bundleData), LockSHA256: sha256Hex(lockData)}, nil
}

func artifactsEqual(a, b *bundleArtifact) bool {
	return a != nil && b != nil && a.BundleSHA256 == b.BundleSHA256 && a.LockSHA256 == b.LockSHA256
}

func cloneFreshnessStateForTransaction(state *FreshnessState) *FreshnessState {
	copyState := &FreshnessState{HighestSeen: make(map[string]uint64, len(state.HighestSeen)), FormatFloor: make(map[string]int, len(state.FormatFloor))}
	for key, value := range state.HighestSeen {
		copyState.HighestSeen[key] = value
	}
	for key, value := range state.FormatFloor {
		copyState.FormatFloor[key] = value
	}
	return copyState
}

func mergeFreshnessState(dst, src *FreshnessState) {
	if dst.HighestSeen == nil {
		dst.HighestSeen = make(map[string]uint64)
	}
	if dst.FormatFloor == nil {
		dst.FormatFloor = make(map[string]int)
	}
	for key, value := range src.HighestSeen {
		if value > dst.HighestSeen[key] {
			dst.HighestSeen[key] = value
		}
	}
	for key, value := range src.FormatFloor {
		if value > dst.FormatFloor[key] {
			dst.FormatFloor[key] = value
		}
	}
}

func cloneLockFile(lock *LockFile) *LockFile { copyLock := *lock; return &copyLock }

func lockFilesEqual(a, b *LockFile) bool {
	// LockFile must remain composed only of comparable fields while equality
	// uses a direct struct comparison.
	return a != nil && b != nil && *a == *b
}

func sha256Hex(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
