//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

const (
	legalHoldFieldMaxBytes = 4096
	legalHoldMaxRecords    = 4096
	legalHoldFileMaxBytes  = 16 << 20
)

// LegalHold is operator-authored retention metadata. It is intentionally
// separate from receipt evidence because a hold cannot be reconstructed from
// mediated action records.
type LegalHold struct {
	ID       string     `json:"id"`
	Scope    string     `json:"scope"`
	Reason   string     `json:"reason"`
	Created  time.Time  `json:"created"`
	Released *time.Time `json:"released,omitempty"`
}

func (h LegalHold) Status() string {
	if h.Released != nil {
		return "released"
	}
	return "active"
}

func (h LegalHold) CreatedDisplay() string {
	return h.Created.UTC().Format(time.RFC3339)
}

func (h LegalHold) ReleasedDisplay() string {
	if h.Released == nil {
		return "-"
	}
	return h.Released.UTC().Format(time.RFC3339)
}

// LegalHoldStore is an atomic JSON store protected by the same per-path and
// platform file-locking discipline as ExemptionStore.
type LegalHoldStore struct {
	mu      sync.Mutex
	path    string
	records []LegalHold
}

var legalHoldStorePathLocks sync.Map

func legalHoldStorePathLock(path string) *sync.Mutex {
	cleanPath := filepath.Clean(path)
	if abs, err := filepath.Abs(cleanPath); err == nil {
		cleanPath = abs
	}
	mu, _ := legalHoldStorePathLocks.LoadOrStore(cleanPath, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// OpenLegalHoldStore opens a legal-hold metadata store. Missing files are
// empty; corrupt or invalid files fail closed instead of hiding hold state.
func OpenLegalHoldStore(path string) (*LegalHoldStore, error) {
	cleanPath := filepath.Clean(path)
	if strings.TrimSpace(path) == "" || cleanPath == "." {
		return nil, errors.New("legal hold store: path is required")
	}
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o750); err != nil {
		return nil, fmt.Errorf("legal hold store: create dir: %w", err)
	}
	s := &LegalHoldStore{path: cleanPath}
	if err := s.reloadLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *LegalHoldStore) List() []LegalHold {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := cloneLegalHolds(s.records)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Snapshot reloads from disk before returning records. The dashboard uses
// this path so CLI changes become visible without an HTTP mutation path, and
// post-start corruption fails closed instead of serving stale hold metadata.
func (s *LegalHoldStore) Snapshot() ([]LegalHold, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadLocked(); err != nil {
		return nil, err
	}
	out := cloneLegalHolds(s.records)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *LegalHoldStore) Add(hold LegalHold) error {
	id, err := canonicalLegalHoldID(hold.ID)
	if err != nil {
		return err
	}
	hold.ID = id
	if err := validateLegalHold(hold, false); err != nil {
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
		if existing.ID == hold.ID {
			return fmt.Errorf("legal hold: duplicate id %q", hold.ID)
		}
	}
	next := append(cloneLegalHolds(s.records), hold)
	if err := s.persistLocked(next); err != nil {
		return err
	}
	s.records = next
	return nil
}

func (s *LegalHoldStore) Release(id string, released time.Time) error {
	canonicalID, err := canonicalLegalHoldID(id)
	if err != nil {
		return err
	}
	id = canonicalID
	if released.IsZero() {
		return errors.New("legal hold: released time is required")
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
	for i := range s.records {
		if s.records[i].ID != id {
			continue
		}
		if s.records[i].Released != nil {
			return fmt.Errorf("legal hold: id %q is already released", id)
		}
		if released.Before(s.records[i].Created) {
			return errors.New("legal hold: released time must not precede created time")
		}
		next := cloneLegalHolds(s.records)
		next[i].Released = &released
		if err := s.persistLocked(next); err != nil {
			return err
		}
		s.records = next
		return nil
	}
	return fmt.Errorf("legal hold: id %q not found", id)
}

func validateLegalHold(hold LegalHold, allowReleased bool) error {
	canonicalID, err := canonicalLegalHoldID(hold.ID)
	if err != nil {
		return err
	}
	hold.ID = canonicalID
	for name, value := range map[string]string{"id": hold.ID, "scope": hold.Scope, "reason": hold.Reason} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("legal hold: %s is required", name)
		}
		if len(value) > legalHoldFieldMaxBytes {
			return fmt.Errorf("legal hold: %s exceeds %d bytes", name, legalHoldFieldMaxBytes)
		}
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("legal hold: %s contains a control character", name)
		}
	}
	if hold.Created.IsZero() {
		return errors.New("legal hold: created is required")
	}
	if hold.Released != nil {
		if !allowReleased {
			return errors.New("legal hold: new entries cannot be pre-released")
		}
		if hold.Released.Before(hold.Created) {
			return errors.New("legal hold: released time must not precede created time")
		}
	}
	return nil
}

func canonicalLegalHoldID(value string) (string, error) {
	id := strings.TrimSpace(value)
	if id == "" {
		return "", errors.New("legal hold: id is required")
	}
	if value != id {
		return "", errors.New("legal hold: id must not contain surrounding whitespace")
	}
	return id, nil
}

func cloneLegalHolds(records []LegalHold) []LegalHold {
	out := append([]LegalHold(nil), records...)
	for i := range out {
		if out[i].Released == nil {
			continue
		}
		released := *out[i].Released
		out[i].Released = &released
	}
	return out
}

func (s *LegalHoldStore) acquireMutationLock() (func(), error) {
	pathMu := legalHoldStorePathLock(s.path)
	pathMu.Lock()
	// The exemption store's lock helper is package-local and implements the
	// same cross-process advisory lock required by both dashboard stores.
	lock, err := acquireExemptionStoreFileLock(s.path + ".lock")
	if err != nil {
		pathMu.Unlock()
		return nil, fmt.Errorf("legal hold store: lock: %w", err)
	}
	return func() {
		_ = lock.Close()
		pathMu.Unlock()
	}, nil
}

func (s *LegalHoldStore) reloadLocked() error {
	file, info, err := openRegularDashboardFile(s.path, "legal hold store")
	if errors.Is(err, os.ErrNotExist) {
		s.records = nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("legal hold store: read: %w", err)
	}
	defer func() { _ = file.Close() }()
	if err := requireOwnerOnlyDashboardFile(file, info, "legal hold store"); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(file, legalHoldFileMaxBytes+1))
	if err != nil {
		return fmt.Errorf("legal hold store: read: %w", err)
	}
	if len(data) > legalHoldFileMaxBytes {
		return fmt.Errorf("legal hold store: file exceeds %d bytes", legalHoldFileMaxBytes)
	}
	if len(data) == 0 {
		return errors.New("legal hold store: empty file is invalid")
	}
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return fmt.Errorf("legal hold store: parse: %w", err)
	}
	var records []LegalHold
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&records); err != nil {
		return fmt.Errorf("legal hold store: parse: %w", err)
	}
	if records == nil {
		return errors.New("legal hold store: root must be a JSON array")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("legal hold store: parse: trailing JSON value")
	}
	if len(records) > legalHoldMaxRecords {
		return fmt.Errorf("legal hold store: record count exceeds %d", legalHoldMaxRecords)
	}
	seen := make(map[string]struct{}, len(records))
	for _, hold := range records {
		if err := validateLegalHold(hold, true); err != nil {
			return fmt.Errorf("legal hold store: invalid record: %w", err)
		}
		if _, ok := seen[hold.ID]; ok {
			return fmt.Errorf("legal hold store: duplicate id %q", hold.ID)
		}
		seen[hold.ID] = struct{}{}
	}
	s.records = records
	return nil
}

func (s *LegalHoldStore) persistLocked(records []LegalHold) error {
	if len(records) > legalHoldMaxRecords {
		return fmt.Errorf("legal hold store: record count exceeds %d", legalHoldMaxRecords)
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("legal hold store: marshal: %w", err)
	}
	if len(data) > legalHoldFileMaxBytes {
		return fmt.Errorf("legal hold store: file exceeds %d bytes", legalHoldFileMaxBytes)
	}
	if err := atomicfile.Write(s.path, data, 0o600); err != nil {
		return fmt.Errorf("legal hold store: write: %w", err)
	}
	return nil
}
