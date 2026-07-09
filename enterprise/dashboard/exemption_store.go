//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
)

// Stale threshold for exemption records: if a record has a LastMatched
// timestamp older than this duration before "now", it is considered stale.
const staleThreshold = 30 * 24 * time.Hour // 30 days

// Bounded lifecycle status strings returned by ExemptionRecord.Status.
const (
	lifecycleActive     = "active"
	lifecycleExpired    = "EXPIRED — remove or renew"
	lifecycleStale      = "stale — not matched recently"
	lifecycleUnobserved = "not observed"
)

// ExemptionRecord is one operator-managed exemption lifecycle entry.
// It annotates a configured exemption (matched by Scope) with ownership,
// justification, expiry, and last-matched metadata that is NOT
// reconstructible from config or evidence alone.
type ExemptionRecord struct {
	ID          string     `json:"id"`
	Scope       string     `json:"scope"`
	Owner       string     `json:"owner"`
	Reason      string     `json:"reason"`
	CreatedBy   string     `json:"created_by,omitempty"`
	Created     time.Time  `json:"created"`
	Expiry      time.Time  `json:"expiry"`
	LastMatched *time.Time `json:"last_matched,omitempty"`
}

// Status returns a bounded lifecycle status string for the record given
// the current time. The caller injects "now" so tests never depend on
// wall-clock time.
func (r ExemptionRecord) Status(now time.Time) string {
	if now.After(r.Expiry) || now.Equal(r.Expiry) {
		return lifecycleExpired
	}
	if r.LastMatched == nil {
		return lifecycleUnobserved
	}
	if now.Sub(*r.LastMatched) > staleThreshold {
		return lifecycleStale
	}
	return lifecycleActive
}

// ExemptionStore is a durable, file-backed store for exemption lifecycle
// records. All writes are atomic (temp file + rename in the same directory).
// A missing store file is an empty store, not an error.
type ExemptionStore struct {
	mu      sync.Mutex
	path    string
	records []ExemptionRecord
}

var exemptionStorePathLocks sync.Map

func exemptionStorePathLock(path string) *sync.Mutex {
	cleanPath := filepath.Clean(path)
	if abs, err := filepath.Abs(cleanPath); err == nil {
		cleanPath = abs
	}
	mu, _ := exemptionStorePathLocks.LoadOrStore(cleanPath, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// OpenExemptionStore opens (or creates) a JSON-backed exemption store at
// the given path. The directory is created with mode 0o750 if absent; the
// file is created with mode 0o600. A missing file yields an empty store.
func OpenExemptionStore(path string) (*ExemptionStore, error) {
	cleanPath := filepath.Clean(path)
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("exemption store: create dir: %w", err)
	}

	s := &ExemptionStore{path: cleanPath}
	data, err := os.ReadFile(cleanPath)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("exemption store: read: %w", err)
	}
	if len(data) == 0 {
		return s, nil
	}
	if err := s.decodeRecords(data); err != nil {
		return nil, fmt.Errorf("exemption store: parse: %w", err)
	}
	return s, nil
}

// List returns all records, sorted deterministically by ID.
func (s *ExemptionStore) List() []ExemptionRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ExemptionRecord, len(s.records))
	copy(out, s.records)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Add inserts a new exemption record. It validates that Owner, Reason, and
// Scope are non-empty, Expiry is after Created, the ID is unique, and
// there is no existing ACTIVE (non-expired) record for the same Scope.
// The caller passes "now" for the active-scope duplicate check.
func (s *ExemptionStore) Add(rec ExemptionRecord, now time.Time) error {
	if err := validateExemptionRecordForAdd(rec); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.acquireMutationLock()
	if err != nil {
		return err
	}
	defer release()
	if err := s.reloadLocked(); err != nil {
		return err
	}

	for _, existing := range s.records {
		if existing.ID == rec.ID {
			return fmt.Errorf("exemption record: duplicate id %q", rec.ID)
		}
		if existing.Scope == rec.Scope && existing.Status(now) != lifecycleExpired {
			return fmt.Errorf("exemption record: an active record already exists for scope %q (id %s)", rec.Scope, existing.ID)
		}
	}

	s.records = append(s.records, rec)
	return s.persist()
}

// Expire marks the record's expiry to the given time, effectively making
// it expired immediately.
func (s *ExemptionStore) Expire(id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.acquireMutationLock()
	if err != nil {
		return err
	}
	defer release()
	if err := s.reloadLocked(); err != nil {
		return err
	}

	for i := range s.records {
		if s.records[i].ID == id {
			s.records[i].Expiry = now
			return s.persist()
		}
	}
	return fmt.Errorf("exemption record: id %q not found", id)
}

// Renew updates the expiry for an existing record.
func (s *ExemptionStore) Renew(id string, newExpiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.acquireMutationLock()
	if err != nil {
		return err
	}
	defer release()
	if err := s.reloadLocked(); err != nil {
		return err
	}

	for i := range s.records {
		if s.records[i].ID == id {
			if !newExpiry.After(s.records[i].Created) {
				return errors.New("exemption record: new expiry must be after created")
			}
			s.records[i].Expiry = newExpiry
			return s.persist()
		}
	}
	return fmt.Errorf("exemption record: id %q not found", id)
}

// Touch updates the LastMatched timestamp for a record.
func (s *ExemptionStore) Touch(id string, when time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.acquireMutationLock()
	if err != nil {
		return err
	}
	defer release()
	if err := s.reloadLocked(); err != nil {
		return err
	}

	for i := range s.records {
		if s.records[i].ID == id {
			s.records[i].LastMatched = &when
			return s.persist()
		}
	}
	return fmt.Errorf("exemption record: id %q not found", id)
}

// Remove deletes a record from the store.
func (s *ExemptionStore) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.acquireMutationLock()
	if err != nil {
		return err
	}
	defer release()
	if err := s.reloadLocked(); err != nil {
		return err
	}

	for i := range s.records {
		if s.records[i].ID == id {
			s.records = append(s.records[:i], s.records[i+1:]...)
			return s.persist()
		}
	}
	return fmt.Errorf("exemption record: id %q not found", id)
}

// Find returns the preferred record matching the given scope, or false if none.
// Active records are preferred over expired historical records; when several
// records have the same lifecycle state, the latest-created record wins.
func (s *ExemptionStore) Find(scope string, now time.Time) (ExemptionRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var found ExemptionRecord
	ok := false
	for _, rec := range s.records {
		if rec.Scope != scope {
			continue
		}
		if !ok {
			found = rec
			ok = true
			continue
		}
		foundExpired := found.Status(now) == lifecycleExpired
		recExpired := rec.Status(now) == lifecycleExpired
		if foundExpired && !recExpired {
			found = rec
			continue
		}
		if foundExpired == recExpired && rec.Created.After(found.Created) {
			found = rec
		}
	}
	return found, ok
}

func validateExemptionRecordForAdd(rec ExemptionRecord) error {
	if rec.Owner == "" {
		return errors.New("exemption record: owner is required")
	}
	if rec.Reason == "" {
		return errors.New("exemption record: reason is required")
	}
	if rec.Scope == "" {
		return errors.New("exemption record: scope is required")
	}
	if !rec.Expiry.After(rec.Created) {
		return errors.New("exemption record: expiry must be after created")
	}
	if rec.ID == "" {
		return errors.New("exemption record: id is required")
	}
	return nil
}

func (s *ExemptionStore) acquireMutationLock() (func(), error) {
	pathMu := exemptionStorePathLock(s.path)
	pathMu.Lock()
	lock, err := acquireExemptionStoreFileLock(s.path + ".lock")
	if err != nil {
		pathMu.Unlock()
		return nil, fmt.Errorf("exemption store: lock: %w", err)
	}
	return func() {
		_ = lock.Close()
		pathMu.Unlock()
	}, nil
}

func (s *ExemptionStore) reloadLocked() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.records = nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("exemption store: reload: %w", err)
	}
	if len(data) == 0 {
		s.records = nil
		return nil
	}
	if err := s.decodeRecords(data); err != nil {
		return fmt.Errorf("exemption store: reload parse: %w", err)
	}
	return nil
}

func (s *ExemptionStore) decodeRecords(data []byte) error {
	var records []ExemptionRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return err
	}
	s.records = records
	return nil
}

// persist writes the current records to disk atomically.
func (s *ExemptionStore) persist() error {
	data, err := json.MarshalIndent(s.records, "", "  ")
	if err != nil {
		return fmt.Errorf("exemption store: marshal: %w", err)
	}
	return atomicfile.Write(s.path, data, 0o600)
}
