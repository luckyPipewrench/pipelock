// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
)

const (
	ExpirySeverityInfo  = "info"
	ExpirySeverityWarn  = "warn"
	ExpirySeverityError = "error"

	expiryDay = 24 * time.Hour
)

// ExpiryWarning describes the active renewal warning band for a license.
type ExpiryWarning struct {
	Active        bool
	LicenseID     string
	ThresholdDays int
	DaysRemaining int
	Severity      string
	ExpiresAt     time.Time
}

// ExpiryWarningState records the last emitted renewal warning. It is safe to
// persist locally because it contains only the opaque license ID and threshold.
type ExpiryWarningState struct {
	LicenseID      string    `json:"license_id"`
	ThresholdDays  int       `json:"threshold_days"`
	LastEmittedUTC time.Time `json:"last_emitted_utc"`
}

// ExpiryStatus returns the current warning band for lic at now. Perpetual and
// already-expired licenses do not produce renewal warnings.
func ExpiryStatus(lic License, now time.Time) ExpiryWarning {
	if lic.ExpiresAt <= 0 {
		return ExpiryWarning{LicenseID: lic.ID}
	}
	expiresAt := time.Unix(lic.ExpiresAt, 0).UTC()
	remaining := expiresAt.Sub(now.UTC())
	if remaining <= 0 {
		return ExpiryWarning{
			LicenseID:     lic.ID,
			DaysRemaining: 0,
			ExpiresAt:     expiresAt,
		}
	}
	days := int(math.Ceil(float64(remaining) / float64(expiryDay)))
	threshold := expiryThreshold(days)
	if threshold == 0 {
		return ExpiryWarning{
			LicenseID:     lic.ID,
			DaysRemaining: days,
			ExpiresAt:     expiresAt,
		}
	}
	return ExpiryWarning{
		Active:        true,
		LicenseID:     lic.ID,
		ThresholdDays: threshold,
		DaysRemaining: days,
		Severity:      expirySeverity(threshold),
		ExpiresAt:     expiresAt,
	}
}

// ShouldEmitExpiryWarning returns true when a warning should be emitted for
// the current band. The same license and threshold emits once; a new license
// or a lower threshold emits again.
func ShouldEmitExpiryWarning(current ExpiryWarning, previous ExpiryWarningState) bool {
	if !current.Active {
		return false
	}
	return previous.LicenseID != current.LicenseID ||
		previous.ThresholdDays != current.ThresholdDays
}

func NewExpiryWarningState(current ExpiryWarning, now time.Time) ExpiryWarningState {
	return ExpiryWarningState{
		LicenseID:      current.LicenseID,
		ThresholdDays:  current.ThresholdDays,
		LastEmittedUTC: now.UTC(),
	}
}

func LoadExpiryWarningState(path string) (ExpiryWarningState, error) {
	if path == "" {
		return ExpiryWarningState{}, nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return ExpiryWarningState{}, nil
	}
	if err != nil {
		return ExpiryWarningState{}, fmt.Errorf("read license expiry state: %w", err)
	}
	var state ExpiryWarningState
	if err := json.Unmarshal(data, &state); err != nil {
		return ExpiryWarningState{}, fmt.Errorf("parse license expiry state: %w", err)
	}
	return state, nil
}

func SaveExpiryWarningState(path string, state ExpiryWarningState) error {
	if path == "" {
		return nil
	}
	cleanPath := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o750); err != nil {
		return fmt.Errorf("create license expiry state dir: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal license expiry state: %w", err)
	}
	data = append(data, '\n')
	if err := atomicfile.Write(cleanPath, data, 0o600); err != nil {
		return fmt.Errorf("write license expiry state: %w", err)
	}
	return nil
}

func expiryThreshold(daysRemaining int) int {
	switch {
	case daysRemaining <= 1:
		return 1
	case daysRemaining <= 7:
		return 7
	case daysRemaining <= 14:
		return 14
	case daysRemaining <= 30:
		return 30
	default:
		return 0
	}
}

func expirySeverity(threshold int) string {
	switch threshold {
	case 1:
		return ExpirySeverityError
	case 7, 14:
		return ExpirySeverityWarn
	case 30:
		return ExpirySeverityInfo
	default:
		return ""
	}
}
