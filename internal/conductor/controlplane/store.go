// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package controlplane provides the Conductor follower-facing HTTP boundary.
//
// Scope and non-scope of this package:
//
//   - The store enforces per-audience forward-chain publication, hash-bound
//     records, durable on-disk persistence with private modes, and idempotent
//     re-publication of identical bundles.
//   - The handler enforces strict JSON decoding (DisallowUnknownFields, no
//     trailing document), body size caps, method validation, and ETag
//     responses on the latest-bundle endpoint.
//   - The handler does NOT cryptographically verify bundle signatures.
//     [conductor.PolicyBundle.Validate] only checks signature count, purpose,
//     and wire format; it does not invoke a [conductor.SignatureKeyResolver].
//     Cryptographic verification happens on followers via
//     [conductor.PolicyBundle.VerifySignaturesAt] using their pinned trust
//     roster.
//   - The handler does NOT enforce mTLS or any transport authentication. The
//     advertised `required_mtls` capability is a descriptor of operator
//     deployment intent. The hosting server must terminate mTLS and pass an
//     authenticated identity to the handler via [FollowerIdentityResolver]
//     and [PublisherAuthorizer]. Wiring either resolver to trust unauthenticated
//     request headers in production breaks the security model.
//   - The handler does NOT enforce a publisher-to-org binding. Production
//     [PublisherAuthorizer] implementations must restrict each publisher to
//     the orgs/fleets/environments it is permitted to publish into; this
//     package only invokes the hook.
package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
)

const (
	bundlesDirName          = "bundles"
	bundleRecordFileMode    = 0o600
	bundleStoreDirMode      = 0o700
	bundleStoreTempPattern  = ".bundle-*.tmp"
	maxBundleRecordJSONSize = conductor.MaxConfigYAMLBytes * 2
)

var (
	ErrStoreRequired       = errors.New("conductor control plane store required")
	ErrBundleNotFound      = errors.New("conductor policy bundle not found")
	ErrBundleConflict      = errors.New("conductor policy bundle conflicts with active stream")
	ErrInvalidStoreRecord  = errors.New("conductor control plane store record invalid")
	ErrFollowerRequired    = errors.New("conductor follower identity required")
	ErrPublisherForbidden  = errors.New("conductor publisher authorization failed")
	ErrUnsupportedRollback = errors.New("conductor control plane rollback publication not implemented")
)

type FollowerIdentity struct {
	OrgID       string
	FleetID     string
	InstanceID  string
	Environment string
	Labels      map[string]string
}

type PublishedBundle struct {
	Bundle      conductor.PolicyBundle `json:"bundle"`
	BundleHash  string                 `json:"bundle_hash"`
	StreamKey   string                 `json:"stream_key"`
	PublishedAt time.Time              `json:"published_at"`
}

type PublishOptions struct {
	Now      time.Time
	Rollback bool
}

type BundleStore interface {
	Publish(ctx context.Context, bundle conductor.PolicyBundle, opts PublishOptions) (PublishedBundle, bool, error)
	Latest(ctx context.Context, follower FollowerIdentity, now time.Time) (PublishedBundle, error)
}

type FileBundleStore struct {
	dir        string
	bundlesDir string
	mu         sync.RWMutex
	records    map[string]PublishedBundle
	streams    map[string]PublishedBundle
}

func OpenFileBundleStore(dir string) (*FileBundleStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("conductor control plane bundle store dir required")
	}
	root, err := secureDir(dir)
	if err != nil {
		return nil, err
	}
	bundlesDir, err := secureDir(filepath.Join(root, bundlesDirName))
	if err != nil {
		return nil, err
	}
	if err := sweepTempFiles(bundlesDir); err != nil {
		return nil, err
	}
	store := &FileBundleStore{
		dir:        root,
		bundlesDir: bundlesDir,
		records:    make(map[string]PublishedBundle),
		streams:    make(map[string]PublishedBundle),
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileBundleStore) Publish(_ context.Context, bundle conductor.PolicyBundle, opts PublishOptions) (PublishedBundle, bool, error) {
	if s == nil {
		return PublishedBundle{}, false, ErrStoreRequired
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if opts.Rollback {
		return PublishedBundle{}, false, ErrUnsupportedRollback
	}
	if err := validatePublishableBundle(bundle, now); err != nil {
		return PublishedBundle{}, false, err
	}
	hash, err := bundle.CanonicalHash()
	if err != nil {
		return PublishedBundle{}, false, err
	}
	streamKey, err := streamKey(bundle)
	if err != nil {
		return PublishedBundle{}, false, err
	}
	record := PublishedBundle{
		Bundle:      bundle,
		BundleHash:  hash,
		StreamKey:   streamKey,
		PublishedAt: now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.records[hash]; ok {
		return existing, false, nil
	}
	if err := s.authorizeForwardLocked(record); err != nil {
		return PublishedBundle{}, false, err
	}
	if err := writeBundleRecord(s.bundlesDir, record); err != nil {
		return PublishedBundle{}, false, err
	}
	s.records[hash] = record
	if current, ok := s.streams[streamKey]; !ok || newerRecord(record, current) {
		s.streams[streamKey] = record
	}
	return record, true, nil
}

func (s *FileBundleStore) Latest(_ context.Context, follower FollowerIdentity, now time.Time) (PublishedBundle, error) {
	if s == nil {
		return PublishedBundle{}, ErrStoreRequired
	}
	if err := follower.Validate(); err != nil {
		return PublishedBundle{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best PublishedBundle
	bestSpecificity := 0
	for _, record := range s.records {
		specificity := matchingSpecificity(record.Bundle, follower, now)
		if specificity > 0 && (best.BundleHash == "" || specificity > bestSpecificity ||
			(specificity == bestSpecificity && newerRecord(record, best))) {
			best = record
			bestSpecificity = specificity
		}
	}
	if best.BundleHash == "" {
		return PublishedBundle{}, ErrBundleNotFound
	}
	return best, nil
}

func (f FollowerIdentity) Validate() error {
	switch {
	case strings.TrimSpace(f.OrgID) == "":
		return fmt.Errorf("%w: org_id", ErrFollowerRequired)
	case strings.TrimSpace(f.FleetID) == "":
		return fmt.Errorf("%w: fleet_id", ErrFollowerRequired)
	case strings.TrimSpace(f.InstanceID) == "":
		return fmt.Errorf("%w: instance_id", ErrFollowerRequired)
	case strings.TrimSpace(f.Environment) == "":
		return fmt.Errorf("%w: environment", ErrFollowerRequired)
	default:
		return nil
	}
}

func (s *FileBundleStore) load() error {
	entries, err := os.ReadDir(s.bundlesDir)
	if err != nil {
		return fmt.Errorf("conductor control plane read bundle dir: %w", err)
	}
	// Sort by filename so load order is deterministic across filesystems;
	// stream-head selection in newerRecord still uses version/time/hash.
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	for _, name := range names {
		path := filepath.Join(s.bundlesDir, name)
		record, err := readBundleRecord(path)
		if err != nil {
			return err
		}
		if _, exists := s.records[record.BundleHash]; exists {
			return fmt.Errorf("%w: duplicate bundle_hash %q", ErrInvalidStoreRecord, record.BundleHash)
		}
		s.records[record.BundleHash] = record
		if current, ok := s.streams[record.StreamKey]; !ok || newerRecord(record, current) {
			s.streams[record.StreamKey] = record
		}
	}
	// Defense in depth: re-verify the forward-chain integrity of every
	// stream after load. authorizeForwardLocked enforces this on Publish,
	// but the on-disk records are the durable state: handcrafted or
	// half-restored directories could present a stream whose head's
	// previous_bundle_hash does not chain through records we hold. Refuse
	// to open in that case rather than silently serving a fork.
	if err := s.verifyStreamChainsLocked(); err != nil {
		return err
	}
	return nil
}

// verifyStreamChainsLocked walks each stream head back through
// previous_bundle_hash, ensuring every same-stream record on disk is reachable
// from the selected head in strictly decreasing version order. Gap publication
// (e.g., v1 then v3 with previous_bundle_hash=v1) is explicitly allowed:
// Publish never required v2 to exist, so load mirrors that. The check rejects:
// (a) a head pointing at a missing ancestor, (b) an ancestor on a different
// stream key, (c) an ancestor whose version does not strictly decrease, and
// (d) any same-stream record not reachable from the selected head. The seen-map
// check is structurally unreachable for chains that pass the strict-decrease
// check (a decreasing integer sequence cannot loop), but is retained as
// defense-in-depth: a future reordering of these checks must not silently allow
// infinite chain traversal.
// Callers must either hold s.mu or run before the store is shared.
func (s *FileBundleStore) verifyStreamChainsLocked() error {
	for streamKey, head := range s.streams {
		seen := make(map[string]struct{}, 4)
		cursor := head
		for {
			if _, cycle := seen[cursor.BundleHash]; cycle {
				return fmt.Errorf("%w: stream %q chain has cycle at %s",
					ErrInvalidStoreRecord, streamKey, cursor.BundleHash)
			}
			seen[cursor.BundleHash] = struct{}{}
			if cursor.Bundle.PreviousBundleHash == "" {
				break
			}
			prev, ok := s.records[cursor.Bundle.PreviousBundleHash]
			if !ok {
				return fmt.Errorf("%w: stream %q references missing previous_bundle_hash %s",
					ErrInvalidStoreRecord, streamKey, cursor.Bundle.PreviousBundleHash)
			}
			if prev.StreamKey != cursor.StreamKey {
				return fmt.Errorf("%w: stream %q ancestor %s belongs to different stream",
					ErrInvalidStoreRecord, streamKey, prev.BundleHash)
			}
			if prev.Bundle.Version >= cursor.Bundle.Version {
				return fmt.Errorf("%w: stream %q ancestor %s version %d does not decrease from %d",
					ErrInvalidStoreRecord, streamKey, prev.BundleHash, prev.Bundle.Version, cursor.Bundle.Version)
			}
			cursor = prev
		}
		for hash, record := range s.records {
			if record.StreamKey != streamKey {
				continue
			}
			if _, ok := seen[hash]; !ok {
				return fmt.Errorf("%w: stream %q record %s is not reachable from stream head %s",
					ErrInvalidStoreRecord, streamKey, hash, head.BundleHash)
			}
		}
	}
	return nil
}

func (s *FileBundleStore) authorizeForwardLocked(record PublishedBundle) error {
	current, ok := s.streams[record.StreamKey]
	if !ok {
		if record.Bundle.PreviousBundleHash != "" {
			return fmt.Errorf("%w: initial bundle has previous_bundle_hash", ErrBundleConflict)
		}
		return nil
	}
	switch {
	case record.Bundle.Version == current.Bundle.Version:
		return fmt.Errorf("%w: same version with different content", ErrBundleConflict)
	case record.Bundle.Version < current.Bundle.Version:
		return fmt.Errorf("%w: %w", ErrBundleConflict, ErrUnsupportedRollback)
	case record.Bundle.PreviousBundleHash != current.BundleHash:
		return fmt.Errorf("%w: previous_bundle_hash does not match stream head", ErrBundleConflict)
	default:
		return nil
	}
}

func validatePublishableBundle(bundle conductor.PolicyBundle, now time.Time) error {
	if err := bundle.Validate(); err != nil {
		return err
	}
	if bundle.ExpiresAt.Before(now) {
		return conductor.ErrExpired
	}
	return nil
}

func readBundleRecord(path string) (PublishedBundle, error) {
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil {
		return PublishedBundle{}, fmt.Errorf("conductor control plane stat bundle record: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return PublishedBundle{}, fmt.Errorf("%w: non-regular bundle record %s", ErrInvalidStoreRecord, path)
	}
	if info.Size() > maxBundleRecordJSONSize {
		return PublishedBundle{}, fmt.Errorf("%w: bundle record too large", conductor.ErrPayloadTooLarge)
	}
	file, err := os.Open(clean)
	if err != nil {
		return PublishedBundle{}, fmt.Errorf("conductor control plane open bundle record: %w", err)
	}
	defer func() { _ = file.Close() }()
	var record PublishedBundle
	decoder := json.NewDecoder(io.LimitReader(file, maxBundleRecordJSONSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return PublishedBundle{}, fmt.Errorf("%w: decode bundle record: %w", ErrInvalidStoreRecord, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PublishedBundle{}, fmt.Errorf("%w: trailing JSON document", ErrInvalidStoreRecord)
	}
	if err := validateStoredRecord(record); err != nil {
		return PublishedBundle{}, err
	}
	return record, nil
}

func writeBundleRecord(dir string, record PublishedBundle) error {
	if err := validateStoredRecord(record); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("conductor control plane marshal bundle record: %w", err)
	}
	data = append(data, '\n')
	path := filepath.Join(dir, record.BundleHash+".json")
	return durableWrite(path, data, bundleRecordFileMode)
}

func validateStoredRecord(record PublishedBundle) error {
	if record.BundleHash == "" || len(record.BundleHash) != sha256.Size*2 {
		return fmt.Errorf("%w: invalid bundle_hash", ErrInvalidStoreRecord)
	}
	if _, err := hex.DecodeString(record.BundleHash); err != nil {
		return fmt.Errorf("%w: invalid bundle_hash", ErrInvalidStoreRecord)
	}
	hash, err := record.Bundle.CanonicalHash()
	if err != nil {
		return err
	}
	if hash != record.BundleHash {
		return fmt.Errorf("%w: bundle_hash mismatch", ErrInvalidStoreRecord)
	}
	expectedStream, err := streamKey(record.Bundle)
	if err != nil {
		return err
	}
	if record.StreamKey != expectedStream {
		return fmt.Errorf("%w: stream_key mismatch", ErrInvalidStoreRecord)
	}
	if record.PublishedAt.IsZero() {
		return fmt.Errorf("%w: published_at", ErrInvalidStoreRecord)
	}
	return validatePublishableBundle(record.Bundle, record.PublishedAt)
}

func streamKey(bundle conductor.PolicyBundle) (string, error) {
	audienceHash, err := audienceHash(bundle.Audience)
	if err != nil {
		return "", err
	}
	return bundle.OrgID + "\x00" + bundle.FleetID + "\x00" + bundle.Environment + "\x00" + audienceHash, nil
}

// audienceHash returns the canonical hash of an audience used as the stream
// discriminator. The hash MUST be order-invariant under semantically equivalent
// audiences: two audiences with the same instance IDs and labels but listed in
// different order must hash identically. Without this, a publisher could bypass
// per-stream forward-chain enforcement (forbidding rollback, requiring matching
// previous_bundle_hash) by reordering Audience.InstanceIDs to create a parallel
// stream. Both streams would still match the same follower via Audience.Matches,
// and Latest() would serve whichever has the higher Version, sidestepping the
// stream-head's previous-hash chain entirely.
//
// Map keys are already deterministic under encoding/json since Go 1.12, but
// slice order is preserved as-is. We sort and compact a copy of InstanceIDs to
// defend against accidental and adversarial reordering or duplicate IDs.
func audienceHash(audience conductor.Audience) (string, error) {
	canonical := conductor.Audience{
		Labels: audience.Labels,
	}
	if len(audience.InstanceIDs) > 0 {
		ids := slices.Clone(audience.InstanceIDs)
		slices.Sort(ids)
		ids = slices.Compact(ids)
		canonical.InstanceIDs = ids
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func newerRecord(candidate, current PublishedBundle) bool {
	if candidate.Bundle.Version != current.Bundle.Version {
		return candidate.Bundle.Version > current.Bundle.Version
	}
	if !candidate.PublishedAt.Equal(current.PublishedAt) {
		return candidate.PublishedAt.After(current.PublishedAt)
	}
	return candidate.BundleHash > current.BundleHash
}

func matchingSpecificity(bundle conductor.PolicyBundle, follower FollowerIdentity, now time.Time) int {
	if bundle.NotBefore.After(now) || bundle.ExpiresAt.Before(now) || bundle.Environment != follower.Environment {
		return 0
	}
	if bundle.ValidateForFollower(follower.OrgID, follower.FleetID, follower.InstanceID, follower.Labels) != nil {
		return 0
	}
	if slices.Contains(bundle.Audience.InstanceIDs, follower.InstanceID) {
		return 3
	}
	if len(bundle.Audience.Labels) > 0 {
		return 2
	}
	if slices.Contains(bundle.Audience.InstanceIDs, "*") {
		return 1
	}
	return 0
}

func secureDir(dir string) (string, error) {
	clean := filepath.Clean(dir)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("conductor control plane dir must be absolute: %s", dir)
	}
	if err := os.MkdirAll(clean, bundleStoreDirMode); err != nil {
		return "", fmt.Errorf("conductor control plane create dir %s: %w", clean, err)
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", fmt.Errorf("conductor control plane resolve dir %s: %w", clean, err)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("conductor control plane stat dir %s: %w", resolved, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("conductor control plane dir %s must be a real directory", resolved)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(resolved, bundleStoreDirMode); err != nil {
			return "", fmt.Errorf("conductor control plane chmod dir %s: %w", resolved, err)
		}
	}
	return resolved, nil
}

func durableWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, bundleStoreTempPattern)
	if err != nil {
		return fmt.Errorf("conductor control plane create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("conductor control plane write temp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("conductor control plane chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("conductor control plane fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("conductor control plane close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("conductor control plane rename temp: %w", err)
	}
	return fsyncDir(dir)
}

func fsyncDir(dir string) error {
	f, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return fmt.Errorf("conductor control plane open dir for fsync %s: %w", dir, err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("conductor control plane fsync dir %s: %w", dir, err)
	}
	return nil
}

func sweepTempFiles(dir string) error {
	matches, err := filepath.Glob(filepath.Join(dir, bundleStoreTempPattern))
	if err != nil {
		return fmt.Errorf("conductor control plane scan stale temps: %w", err)
	}
	slices.Sort(matches)
	for _, match := range matches {
		if err := os.Remove(match); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("conductor control plane remove stale temp %s: %w", filepath.Base(match), err)
		}
	}
	return nil
}
