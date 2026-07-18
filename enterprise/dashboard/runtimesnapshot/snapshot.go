//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtimesnapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

const (
	Version       = 1
	MaxFileBytes  = 4 * 1024 * 1024
	MaxBudgetRows = 1000
	MaxFutureSkew = 5 * time.Second
	DefaultMaxAge = 30 * time.Second
)

var (
	ErrMissing            = errors.New("runtime snapshot missing")
	ErrOversized          = errors.New("runtime snapshot oversized")
	ErrMalformed          = errors.New("runtime snapshot malformed")
	ErrUnsupportedVersion = errors.New("runtime snapshot unsupported version")
	ErrFutureProducedAt   = errors.New("runtime snapshot produced_at is in the future")
	ErrStale              = errors.New("runtime snapshot stale")
)

type Envelope struct {
	Version    int                `json:"version"`
	ProducedAt time.Time          `json:"produced_at"`
	ProducerID string             `json:"producer_id"`
	PolicyHash string             `json:"policy_hash,omitempty"`
	Budgets    []AgentBudgetRow   `json:"budgets,omitempty"`
	Fleet      []FleetFollowerRow `json:"fleet,omitempty"`
	Truncated  Truncation         `json:"truncated,omitempty"`
}

type Truncation struct {
	Budgets bool `json:"budgets,omitempty"`
}

type AgentBudgetRow struct {
	Agent string `json:"agent"`

	RequestCount      int       `json:"request_count"`
	ByteCount         int64     `json:"byte_count"`
	UniqueDomainCount int       `json:"unique_domain_count"`
	WindowStart       time.Time `json:"window_start"`

	MaxRequests      int   `json:"max_requests"`
	MaxBytes         int64 `json:"max_bytes"`
	MaxUniqueDomains int   `json:"max_unique_domains"`
	WindowMinutes    int   `json:"window_minutes"`
}

type FleetFollowerRow struct {
	OrgID      string    `json:"org_id,omitempty"`
	FleetID    string    `json:"fleet_id,omitempty"`
	InstanceID string    `json:"instance_id,omitempty"`
	Status     string    `json:"status,omitempty"`
	SeenAt     time.Time `json:"seen_at,omitempty"`
}

type Freshness struct {
	ProducedAt time.Time
	Age        time.Duration
	Stale      bool
}

func NewEnvelope(producedAt time.Time, producerID, policyHash string, budgets []edition.AgentBudgetSnapshot) Envelope {
	rows, truncated := BudgetRowsFromSnapshots(budgets)
	return Envelope{
		Version:    Version,
		ProducedAt: producedAt.UTC(),
		ProducerID: producerID,
		PolicyHash: policyHash,
		Budgets:    rows,
		Truncated:  Truncation{Budgets: truncated},
	}
}

func BudgetRowsFromSnapshots(snapshots []edition.AgentBudgetSnapshot) ([]AgentBudgetRow, bool) {
	truncated := len(snapshots) > MaxBudgetRows
	if truncated {
		snapshots = snapshots[:MaxBudgetRows]
	}
	rows := make([]AgentBudgetRow, 0, len(snapshots))
	for _, snap := range snapshots {
		rows = append(rows, AgentBudgetRow{
			Agent:             snap.Agent,
			RequestCount:      snap.RequestCount,
			ByteCount:         snap.ByteCount,
			UniqueDomainCount: snap.UniqueDomainCount,
			WindowStart:       snap.WindowStart,
			MaxRequests:       snap.MaxRequests,
			MaxBytes:          int64(snap.MaxBytes),
			MaxUniqueDomains:  snap.MaxUniqueDomains,
			WindowMinutes:     snap.WindowMinutes,
		})
	}
	return rows, truncated
}

func Write(path string, snap Envelope) error {
	path = filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create runtime snapshot directory: %w", err)
	}
	snap.Version = Version
	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal runtime snapshot: %w", err)
	}
	if len(data) > MaxFileBytes {
		return fmt.Errorf("%w: %d bytes > %d", ErrOversized, len(data), MaxFileBytes)
	}
	return atomicfile.Write(path, data, 0o600)
}

func Read(path string, maxAge time.Duration, now time.Time) (Envelope, Freshness, error) {
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Envelope{}, Freshness{}, fmt.Errorf("%w: %s", ErrMissing, path)
		}
		return Envelope{}, Freshness{}, fmt.Errorf("stat runtime snapshot: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Envelope{}, Freshness{}, fmt.Errorf("%w: not a regular file", ErrMalformed)
	}
	if info.Mode().Perm() != 0o600 {
		return Envelope{}, Freshness{}, fmt.Errorf("%w: unsafe file permissions %04o", ErrMalformed, info.Mode().Perm())
	}
	if info.Size() > MaxFileBytes {
		return Envelope{}, Freshness{}, fmt.Errorf("%w: %d bytes > %d", ErrOversized, info.Size(), MaxFileBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return Envelope{}, Freshness{}, fmt.Errorf("open runtime snapshot: %w", err)
	}
	defer func() { _ = f.Close() }()
	openedInfo, err := f.Stat()
	if err != nil {
		return Envelope{}, Freshness{}, fmt.Errorf("stat open runtime snapshot: %w", err)
	}
	if !os.SameFile(info, openedInfo) {
		return Envelope{}, Freshness{}, fmt.Errorf("%w: changed while opening", ErrMalformed)
	}

	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return Envelope{}, Freshness{}, fmt.Errorf("read runtime snapshot: %w", err)
	}
	if len(data) > MaxFileBytes {
		return Envelope{}, Freshness{}, fmt.Errorf("%w: exceeded %d bytes", ErrOversized, MaxFileBytes)
	}
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return Envelope{}, Freshness{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	var snap Envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&snap); err != nil {
		return Envelope{}, Freshness{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Envelope{}, Freshness{}, fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	if snap.Version != Version {
		return snap, Freshness{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, snap.Version)
	}

	fresh := Freshness{ProducedAt: snap.ProducedAt.UTC()}
	if fresh.ProducedAt.After(now.Add(MaxFutureSkew)) {
		return snap, fresh, fmt.Errorf("%w: %s", ErrFutureProducedAt, fresh.ProducedAt.Format(time.RFC3339))
	}
	fresh.Age = now.Sub(fresh.ProducedAt)
	if fresh.Age > maxAge {
		fresh.Stale = true
		return snap, fresh, fmt.Errorf("%w: age %s > %s", ErrStale, fresh.Age, maxAge)
	}
	if len(snap.Budgets) > MaxBudgetRows {
		snap.Budgets = snap.Budgets[:MaxBudgetRows]
		snap.Truncated.Budgets = true
	}
	if err := validateBudgetRows(snap.Budgets); err != nil {
		return snap, fresh, err
	}
	return snap, fresh, nil
}

func validateBudgetRows(rows []AgentBudgetRow) error {
	for i, row := range rows {
		if row.Agent == "" {
			return fmt.Errorf("%w: budgets[%d].agent is required", ErrMalformed, i)
		}
		if row.RequestCount < 0 ||
			row.ByteCount < 0 ||
			row.UniqueDomainCount < 0 ||
			row.MaxRequests < 0 ||
			row.MaxBytes < 0 ||
			row.MaxUniqueDomains < 0 ||
			row.WindowMinutes < 0 {
			return fmt.Errorf("%w: budgets[%d] contains negative count or limit", ErrMalformed, i)
		}
	}
	return nil
}
