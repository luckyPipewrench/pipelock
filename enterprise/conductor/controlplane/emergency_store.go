//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
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

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

const (
	emergencyStateFileName    = "emergency-controls.json"
	maxEmergencyStateJSONSize = conductor.MaxConfigYAMLBytes * 2
)

var (
	ErrEmergencyStoreRequired = errors.New("conductor emergency control store required")
	ErrEmergencyNotFound      = errors.New("conductor emergency control message not found")
	ErrEmergencyConflict      = errors.New("conductor emergency control message conflicts with stored message")
	ErrEmergencyStaleCounter  = errors.New("conductor emergency control counter is stale")
	ErrInvalidEmergencyRecord = errors.New("conductor emergency control store record invalid")
)

type StoredRemoteKill struct {
	Message     conductor.RemoteKillMessage `json:"message"`
	MessageHash string                      `json:"message_hash"`
	PublishedAt time.Time                   `json:"published_at"`
}

type RollbackLookup struct {
	CurrentBundleID string
	CurrentVersion  uint64
	TargetBundleID  string
	TargetVersion   uint64
}

type StoredRollbackAuthorization struct {
	Authorization     conductor.RollbackAuthorization `json:"authorization"`
	AuthorizationHash string                          `json:"authorization_hash"`
	PublishedAt       time.Time                       `json:"published_at"`
}

type EmergencyStore interface {
	PublishRemoteKill(ctx context.Context, msg conductor.RemoteKillMessage, now time.Time) (StoredRemoteKill, bool, error)
	LatestRemoteKill(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRemoteKill, error)
	PublishRollbackAuthorization(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) (StoredRollbackAuthorization, bool, error)
	LatestRollbackAuthorization(ctx context.Context, follower FollowerIdentity, lookup RollbackLookup, now time.Time) (StoredRollbackAuthorization, error)
	ActiveRollbackForFollower(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRollbackAuthorization, bool, error)
}

type FileEmergencyStore struct {
	dir               string
	statePath         string
	mu                sync.RWMutex
	remoteKills       []StoredRemoteKill
	remoteKillHashes  map[string]StoredRemoteKill
	remoteKillIDs     map[string]string
	rollbacks         []StoredRollbackAuthorization
	rollbackHashes    map[string]StoredRollbackAuthorization
	rollbackAuthIDMap map[string]string
}

type emergencyStateRecord struct {
	RemoteKills []StoredRemoteKill            `json:"remote_kills,omitempty"`
	Rollbacks   []StoredRollbackAuthorization `json:"rollback_authorizations,omitempty"`
}

func OpenFileEmergencyStore(dir string) (*FileEmergencyStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("conductor emergency control store dir required")
	}
	root, err := secureDir(dir)
	if err != nil {
		return nil, err
	}
	store := &FileEmergencyStore{
		dir:               root,
		statePath:         filepath.Join(root, emergencyStateFileName),
		remoteKillHashes:  make(map[string]StoredRemoteKill),
		remoteKillIDs:     make(map[string]string),
		rollbackHashes:    make(map[string]StoredRollbackAuthorization),
		rollbackAuthIDMap: make(map[string]string),
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileEmergencyStore) PublishRemoteKill(_ context.Context, msg conductor.RemoteKillMessage, now time.Time) (StoredRemoteKill, bool, error) {
	if s == nil {
		return StoredRemoteKill{}, false, ErrEmergencyStoreRequired
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if err := msg.ValidateAtTime(now); err != nil {
		return StoredRemoteKill{}, false, err
	}
	hash, err := msg.CanonicalHash()
	if err != nil {
		return StoredRemoteKill{}, false, err
	}
	record := StoredRemoteKill{
		Message:     msg,
		MessageHash: hash,
		PublishedAt: now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.remoteKillHashes[hash]; ok {
		return existing, false, nil
	}
	if existingHash, ok := s.remoteKillIDs[msg.MessageID]; ok && existingHash != hash {
		return StoredRemoteKill{}, false, ErrEmergencyConflict
	}
	if maxCounter, ok := s.maxRemoteKillCounterForOrgFleetLocked(msg.OrgID, msg.FleetID); ok && msg.Counter <= maxCounter {
		return StoredRemoteKill{}, false, fmt.Errorf("%w: counter=%d max=%d", ErrEmergencyStaleCounter, msg.Counter, maxCounter)
	}
	s.remoteKills = append(s.remoteKills, record)
	s.remoteKillHashes[hash] = record
	s.remoteKillIDs[msg.MessageID] = hash
	if err := s.writeLocked(); err != nil {
		s.remoteKills = s.remoteKills[:len(s.remoteKills)-1]
		delete(s.remoteKillHashes, hash)
		delete(s.remoteKillIDs, msg.MessageID)
		return StoredRemoteKill{}, false, err
	}
	return record, true, nil
}

func (s *FileEmergencyStore) LatestRemoteKill(_ context.Context, follower FollowerIdentity, now time.Time) (StoredRemoteKill, error) {
	if s == nil {
		return StoredRemoteKill{}, ErrEmergencyStoreRequired
	}
	if err := follower.Validate(); err != nil {
		return StoredRemoteKill{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best StoredRemoteKill
	for _, record := range s.remoteKills {
		if err := record.Message.ValidateAtTime(now); err != nil {
			continue
		}
		if err := record.Message.ValidateForFollower(follower.OrgID, follower.FleetID, follower.InstanceID, follower.Labels); err != nil {
			continue
		}
		if best.MessageHash == "" || newerRemoteKill(record, best) {
			best = record
		}
	}
	if best.MessageHash == "" {
		return StoredRemoteKill{}, ErrEmergencyNotFound
	}
	return best, nil
}

func (s *FileEmergencyStore) PublishRollbackAuthorization(_ context.Context, auth conductor.RollbackAuthorization, now time.Time) (StoredRollbackAuthorization, bool, error) {
	if s == nil {
		return StoredRollbackAuthorization{}, false, ErrEmergencyStoreRequired
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if err := auth.ValidateAtTime(now); err != nil {
		return StoredRollbackAuthorization{}, false, err
	}
	hash, err := auth.CanonicalHash()
	if err != nil {
		return StoredRollbackAuthorization{}, false, err
	}
	record := StoredRollbackAuthorization{
		Authorization:     auth,
		AuthorizationHash: hash,
		PublishedAt:       now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.rollbackHashes[hash]; ok {
		return existing, false, nil
	}
	if existingHash, ok := s.rollbackAuthIDMap[auth.AuthorizationID]; ok && existingHash != hash {
		return StoredRollbackAuthorization{}, false, ErrEmergencyConflict
	}
	if maxCounter, ok := s.maxRollbackCounterForOrgFleetLocked(auth.OrgID, auth.FleetID); ok && auth.Counter <= maxCounter {
		return StoredRollbackAuthorization{}, false, fmt.Errorf("%w: counter=%d max=%d", ErrEmergencyStaleCounter, auth.Counter, maxCounter)
	}
	s.rollbacks = append(s.rollbacks, record)
	s.rollbackHashes[hash] = record
	s.rollbackAuthIDMap[auth.AuthorizationID] = hash
	if err := s.writeLocked(); err != nil {
		s.rollbacks = s.rollbacks[:len(s.rollbacks)-1]
		delete(s.rollbackHashes, hash)
		delete(s.rollbackAuthIDMap, auth.AuthorizationID)
		return StoredRollbackAuthorization{}, false, err
	}
	return record, true, nil
}

func (s *FileEmergencyStore) LatestRollbackAuthorization(_ context.Context, follower FollowerIdentity, lookup RollbackLookup, now time.Time) (StoredRollbackAuthorization, error) {
	if s == nil {
		return StoredRollbackAuthorization{}, ErrEmergencyStoreRequired
	}
	if err := follower.Validate(); err != nil {
		return StoredRollbackAuthorization{}, err
	}
	if err := lookup.Validate(); err != nil {
		return StoredRollbackAuthorization{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best StoredRollbackAuthorization
	for _, record := range s.rollbacks {
		auth := record.Authorization
		if auth.CurrentBundleID != lookup.CurrentBundleID ||
			auth.CurrentVersion != lookup.CurrentVersion ||
			auth.TargetBundleID != lookup.TargetBundleID ||
			auth.TargetVersion != lookup.TargetVersion {
			continue
		}
		if err := auth.ValidateAtTime(now); err != nil {
			continue
		}
		if auth.OrgID != follower.OrgID || auth.FleetID != follower.FleetID {
			continue
		}
		if best.AuthorizationHash == "" || newerRollback(record, best) {
			best = record
		}
	}
	if best.AuthorizationHash == "" {
		return StoredRollbackAuthorization{}, ErrEmergencyNotFound
	}
	return best, nil
}

func (s *FileEmergencyStore) ActiveRollbackForFollower(_ context.Context, follower FollowerIdentity, now time.Time) (StoredRollbackAuthorization, bool, error) {
	if s == nil {
		return StoredRollbackAuthorization{}, false, ErrEmergencyStoreRequired
	}
	if err := follower.Validate(); err != nil {
		return StoredRollbackAuthorization{}, false, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best StoredRollbackAuthorization
	for _, record := range s.rollbacks {
		auth := record.Authorization
		if err := auth.ValidateAtTime(now); err != nil {
			continue
		}
		if auth.OrgID != follower.OrgID || auth.FleetID != follower.FleetID {
			continue
		}
		if best.AuthorizationHash == "" || newerRollback(record, best) {
			best = record
		}
	}
	if best.AuthorizationHash == "" {
		return StoredRollbackAuthorization{}, false, nil
	}
	return best, true, nil
}

func (l RollbackLookup) Validate() error {
	if err := conductor.ValidateIdentifier("current_bundle_id", l.CurrentBundleID); err != nil {
		return err
	}
	if err := conductor.ValidateIdentifier("target_bundle_id", l.TargetBundleID); err != nil {
		return err
	}
	if l.CurrentVersion == 0 || l.TargetVersion == 0 {
		return fmt.Errorf("%w: rollback lookup versions", conductor.ErrMissingField)
	}
	if l.TargetVersion >= l.CurrentVersion {
		return fmt.Errorf("%w: lookup target_version must be lower than current_version", conductor.ErrInvalidRollback)
	}
	return nil
}

func (s *FileEmergencyStore) load() error {
	record, err := readEmergencyState(s.statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, rk := range record.RemoteKills {
		if err := validateStoredRemoteKill(rk); err != nil {
			return err
		}
		if _, dup := s.remoteKillHashes[rk.MessageHash]; dup {
			return fmt.Errorf("%w: duplicate remote kill hash %q", ErrInvalidEmergencyRecord, rk.MessageHash)
		}
		if existingHash, dup := s.remoteKillIDs[rk.Message.MessageID]; dup && existingHash != rk.MessageHash {
			return fmt.Errorf("%w: duplicate remote kill message_id %q", ErrInvalidEmergencyRecord, rk.Message.MessageID)
		}
		s.remoteKills = append(s.remoteKills, rk)
		s.remoteKillHashes[rk.MessageHash] = rk
		s.remoteKillIDs[rk.Message.MessageID] = rk.MessageHash
	}
	for _, rb := range record.Rollbacks {
		if err := validateStoredRollback(rb); err != nil {
			return err
		}
		if _, dup := s.rollbackHashes[rb.AuthorizationHash]; dup {
			return fmt.Errorf("%w: duplicate rollback authorization hash %q", ErrInvalidEmergencyRecord, rb.AuthorizationHash)
		}
		if existingHash, dup := s.rollbackAuthIDMap[rb.Authorization.AuthorizationID]; dup && existingHash != rb.AuthorizationHash {
			return fmt.Errorf("%w: duplicate rollback authorization_id %q", ErrInvalidEmergencyRecord, rb.Authorization.AuthorizationID)
		}
		s.rollbacks = append(s.rollbacks, rb)
		s.rollbackHashes[rb.AuthorizationHash] = rb
		s.rollbackAuthIDMap[rb.Authorization.AuthorizationID] = rb.AuthorizationHash
	}
	return nil
}

func (s *FileEmergencyStore) RollbackAuthorizations(_ context.Context) ([]StoredRollbackAuthorization, error) {
	if s == nil {
		return nil, ErrEmergencyStoreRequired
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.rollbacks), nil
}

// RemoteKills returns a snapshot of every stored remote-kill record. It is the
// enumeration counterpart of [FileEmergencyStore.RollbackAuthorizations] and is
// consumed by the operator stream-overview read; callers apply their own
// org/fleet scope and validity filtering. The returned slice is a clone so the
// caller cannot mutate the store's backing array.
func (s *FileEmergencyStore) RemoteKills(_ context.Context) ([]StoredRemoteKill, error) {
	if s == nil {
		return nil, ErrEmergencyStoreRequired
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.remoteKills), nil
}

func (s *FileEmergencyStore) writeLocked() error {
	return writeEmergencyState(s.statePath, emergencyStateRecord{
		RemoteKills: s.remoteKills,
		Rollbacks:   s.rollbacks,
	})
}

func readEmergencyState(path string) (emergencyStateRecord, error) {
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil {
		return emergencyStateRecord{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return emergencyStateRecord{}, fmt.Errorf("%w: non-regular emergency state %s", ErrInvalidEmergencyRecord, path)
	}
	if info.Size() > maxEmergencyStateJSONSize {
		return emergencyStateRecord{}, fmt.Errorf("%w: emergency state too large", conductor.ErrPayloadTooLarge)
	}
	file, err := os.Open(clean)
	if err != nil {
		return emergencyStateRecord{}, fmt.Errorf("conductor emergency store open state: %w", err)
	}
	defer func() { _ = file.Close() }()
	var record emergencyStateRecord
	decoder := json.NewDecoder(io.LimitReader(file, maxEmergencyStateJSONSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return emergencyStateRecord{}, fmt.Errorf("%w: decode emergency state: %w", ErrInvalidEmergencyRecord, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return emergencyStateRecord{}, fmt.Errorf("%w: trailing JSON document", ErrInvalidEmergencyRecord)
	}
	return record, nil
}

func writeEmergencyState(path string, record emergencyStateRecord) error {
	for _, rk := range record.RemoteKills {
		if err := validateStoredRemoteKill(rk); err != nil {
			return err
		}
	}
	for _, rb := range record.Rollbacks {
		if err := validateStoredRollback(rb); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("conductor emergency store marshal state: %w", err)
	}
	data = append(data, '\n')
	return durableWrite(path, data)
}

func validateStoredRemoteKill(record StoredRemoteKill) error {
	if record.PublishedAt.IsZero() {
		return fmt.Errorf("%w: remote_kill published_at", ErrInvalidEmergencyRecord)
	}
	hash, err := record.Message.CanonicalHash()
	if err != nil {
		return err
	}
	if !strings.EqualFold(record.MessageHash, hash) {
		return fmt.Errorf("%w: remote_kill message_hash mismatch", ErrInvalidEmergencyRecord)
	}
	return record.Message.Validate()
}

func validateStoredRollback(record StoredRollbackAuthorization) error {
	if record.PublishedAt.IsZero() {
		return fmt.Errorf("%w: rollback published_at", ErrInvalidEmergencyRecord)
	}
	hash, err := record.Authorization.CanonicalHash()
	if err != nil {
		return err
	}
	if !strings.EqualFold(record.AuthorizationHash, hash) {
		return fmt.Errorf("%w: rollback authorization_hash mismatch", ErrInvalidEmergencyRecord)
	}
	return record.Authorization.Validate()
}

func newerRemoteKill(candidate, current StoredRemoteKill) bool {
	if candidate.Message.Counter != current.Message.Counter {
		return candidate.Message.Counter > current.Message.Counter
	}
	if !candidate.Message.CreatedAt.Equal(current.Message.CreatedAt) {
		return candidate.Message.CreatedAt.After(current.Message.CreatedAt)
	}
	return candidate.MessageHash > current.MessageHash
}

func newerRollback(candidate, current StoredRollbackAuthorization) bool {
	if candidate.Authorization.Counter != current.Authorization.Counter {
		return candidate.Authorization.Counter > current.Authorization.Counter
	}
	if !candidate.Authorization.CreatedAt.Equal(current.Authorization.CreatedAt) {
		return candidate.Authorization.CreatedAt.After(current.Authorization.CreatedAt)
	}
	return candidate.AuthorizationHash > current.AuthorizationHash
}

// ClearRollbackAuthorization removes a rollback authorization by its
// authorization_id. It is an admin-only state mutation: the operator uses it to
// clear an active rollback authorization that is no longer needed (e.g. after a
// forward publish succeeds) without waiting for the TTL to expire. Returns
// true when a record was found and removed.
func (s *FileEmergencyStore) ClearRollbackAuthorization(_ context.Context, authorizationID string) (bool, error) {
	if s == nil {
		return false, ErrEmergencyStoreRequired
	}
	if strings.TrimSpace(authorizationID) == "" {
		return false, fmt.Errorf("%w: authorization_id required", conductor.ErrMissingField)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.rollbackAuthIDMap[authorizationID]
	if !ok {
		return false, nil
	}
	// Capture what we are about to remove so we can restore the in-memory
	// state verbatim if the durable write fails (mirrors the rollback in
	// PublishRollbackAuthorization). Diverging memory from disk on a failed
	// write would let a cleared-in-memory-only authorization stop capping the
	// stream head while disk still has it.
	removed, hadRecord := s.rollbackHashes[hash]
	originalRollbacks := s.rollbacks
	// Remove from the ID→hash map and the hash→record map.
	delete(s.rollbackAuthIDMap, authorizationID)
	delete(s.rollbackHashes, hash)
	// Remove from the ordered slice (new backing array; originalRollbacks
	// still references the pre-clear contents for restore-on-error).
	filtered := make([]StoredRollbackAuthorization, 0, len(s.rollbacks))
	for _, record := range s.rollbacks {
		if record.Authorization.AuthorizationID != authorizationID {
			filtered = append(filtered, record)
		}
	}
	s.rollbacks = filtered
	if err := s.writeLocked(); err != nil {
		// Restore the exact pre-clear in-memory state: disk is the source of
		// truth and the write did not land.
		s.rollbackAuthIDMap[authorizationID] = hash
		if hadRecord {
			s.rollbackHashes[hash] = removed
		}
		s.rollbacks = originalRollbacks
		return false, fmt.Errorf("conductor emergency store write after clear: %w", err)
	}
	return true, nil
}

func (s *FileEmergencyStore) maxRemoteKillCounterForOrgFleetLocked(orgID, fleetID string) (uint64, bool) {
	var maxCounter uint64
	found := false
	for _, record := range s.remoteKills {
		msg := record.Message
		if msg.OrgID != orgID || msg.FleetID != fleetID {
			continue
		}
		if !found || msg.Counter > maxCounter {
			maxCounter = msg.Counter
			found = true
		}
	}
	return maxCounter, found
}

func (s *FileEmergencyStore) maxRollbackCounterForOrgFleetLocked(orgID, fleetID string) (uint64, bool) {
	var maxCounter uint64
	found := false
	for _, record := range s.rollbacks {
		auth := record.Authorization
		if auth.OrgID != orgID || auth.FleetID != fleetID {
			continue
		}
		if !found || auth.Counter > maxCounter {
			maxCounter = auth.Counter
			found = true
		}
	}
	return maxCounter, found
}
