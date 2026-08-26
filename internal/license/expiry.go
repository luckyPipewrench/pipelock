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

	trialTier          = "trial"
	enterpriseEvalTier = "enterprise_eval"
	pricingURL         = "https://pipelab.org/pricing/"
)

type expiryBand struct {
	name     string
	divisor  int
	maximum  time.Duration
	severity string
}

var expiryBands = [...]expiryBand{
	{name: "early", divisor: 2, maximum: 30 * expiryDay, severity: ExpirySeverityInfo},
	{name: "mid", divisor: 4, maximum: 14 * expiryDay, severity: ExpirySeverityWarn},
	{name: "late", divisor: 8, maximum: 7 * expiryDay, severity: ExpirySeverityWarn},
	{name: "final", divisor: 2, maximum: expiryDay, severity: ExpirySeverityError},
}

// ExpiryWarning describes the active renewal warning band for a license.
type ExpiryWarning struct {
	Active        bool
	LicenseID     string
	Tier          string
	Band          string
	ThresholdDays int
	DaysRemaining int
	Severity      string
	ExpiresAt     time.Time
}

// ExpiryWarningState records the last emitted renewal warning. It is safe to
// persist locally because it contains only the opaque license ID and band.
type ExpiryWarningState struct {
	LicenseID      string    `json:"license_id"`
	Band           string    `json:"band,omitempty"`
	ThresholdDays  int       `json:"threshold_days"`
	LastEmittedUTC time.Time `json:"last_emitted_utc"`
}

// ExpiryStatus returns the current warning band for lic at now. A valid issued
// time makes each band relative to the token's own lifetime, capped at the
// long-lived-license thresholds. Perpetual and already-expired licenses do not
// produce renewal warnings. Tokens without a usable issued time fall back to
// the legacy absolute bands so a malformed claim cannot silently suppress a
// renewal warning.
func ExpiryStatus(lic License, now time.Time) ExpiryWarning {
	if lic.ExpiresAt <= 0 {
		return ExpiryWarning{LicenseID: lic.ID, Tier: lic.Tier}
	}
	expiresAt := time.Unix(lic.ExpiresAt, 0).UTC()
	remaining := expiresAt.Sub(now.UTC())
	if remaining <= 0 {
		return ExpiryWarning{
			LicenseID:     lic.ID,
			Tier:          lic.Tier,
			DaysRemaining: 0,
			ExpiresAt:     expiresAt,
		}
	}
	days := int(math.Ceil(float64(remaining) / float64(expiryDay)))
	band, threshold := expiryBandFor(lic.IssuedAt, now, expiresAt, remaining)
	if band == nil {
		return ExpiryWarning{
			LicenseID:     lic.ID,
			Tier:          lic.Tier,
			DaysRemaining: days,
			ExpiresAt:     expiresAt,
		}
	}
	return ExpiryWarning{
		Active:        true,
		LicenseID:     lic.ID,
		Tier:          lic.Tier,
		Band:          band.name,
		ThresholdDays: threshold,
		DaysRemaining: days,
		Severity:      band.severity,
		ExpiresAt:     expiresAt,
	}
}

// Message returns the operator-facing warning text for an active expiry band.
func (w ExpiryWarning) Message() string {
	if !w.Active {
		return ""
	}
	expiresAt := w.ExpiresAt.Format(time.DateOnly)
	switch w.Tier {
	case trialTier:
		return fmt.Sprintf("trial ends in %d day(s) on %s; Pro features stop at expiry. Subscribe at %s", w.DaysRemaining, expiresAt, pricingURL)
	case enterpriseEvalTier:
		return fmt.Sprintf("Enterprise evaluation ends in %d day(s) on %s; licensed runtime surfaces stop at expiry. See %s", w.DaysRemaining, expiresAt, pricingURL)
	default:
		return fmt.Sprintf("license expires in %d day(s) on %s; check billing or token delivery", w.DaysRemaining, expiresAt)
	}
}

// ShouldEmitExpiryWarning returns true when a warning should be emitted for
// the current band. The same license and band emits once; a new license or a
// later band emits again.
func ShouldEmitExpiryWarning(current ExpiryWarning, previous ExpiryWarningState) bool {
	if !current.Active {
		return false
	}
	if previous.LicenseID != current.LicenseID {
		return true
	}
	if current.Band != "" && previous.Band != "" {
		return previous.Band != current.Band
	}
	return previous.ThresholdDays != current.ThresholdDays
}

func NewExpiryWarningState(current ExpiryWarning, now time.Time) ExpiryWarningState {
	return ExpiryWarningState{
		LicenseID:      current.LicenseID,
		Band:           current.Band,
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

func expiryBandFor(issuedAt int64, now, expiresAt time.Time, remaining time.Duration) (*expiryBand, int) {
	issued := time.Unix(issuedAt, 0).UTC()
	if issuedAt <= 0 || issued.After(now.UTC()) || !issued.Before(expiresAt) {
		return legacyExpiryBand(daysRemaining(remaining))
	}

	lifetime := expiresAt.Sub(issued)
	for i := len(expiryBands) - 1; i >= 0; i-- {
		band := &expiryBands[i]
		threshold := min(lifetime/time.Duration(band.divisor), band.maximum)
		if remaining <= threshold {
			return band, daysRemaining(threshold)
		}
	}
	return nil, 0
}

func legacyExpiryBand(days int) (*expiryBand, int) {
	switch {
	case days <= 1:
		return &expiryBands[3], 1
	case days <= 7:
		return &expiryBands[2], 7
	case days <= 14:
		return &expiryBands[1], 14
	case days <= 30:
		return &expiryBands[0], 30
	default:
		return nil, 0
	}
}

func daysRemaining(remaining time.Duration) int {
	return int(math.Ceil(float64(remaining) / float64(expiryDay)))
}
