// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
	plsentry "github.com/luckyPipewrench/pipelock/internal/sentry"
)

const licenseExpiryStateFile = "license-expiry-warning.json"

func emitLicenseExpiryWarning(cfg *config.Config, logger *audit.Logger, sentryClient *plsentry.Client, stderr io.Writer) {
	if cfg == nil || cfg.LicenseID == "" || cfg.LicenseExpiresAt <= 0 {
		return
	}
	now := time.Now()
	status := license.ExpiryStatus(license.License{
		ID:        cfg.LicenseID,
		ExpiresAt: cfg.LicenseExpiresAt,
	}, now)
	if !status.Active {
		return
	}

	statePath := licenseExpiryStatePath()
	previous, err := license.LoadExpiryWarningState(statePath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "WARNING: license expiry state unavailable: %v\n", err)
	}
	if !license.ShouldEmitExpiryWarning(status, previous) {
		return
	}

	expiresAt := status.ExpiresAt.Format(time.DateOnly)
	if logger != nil {
		logger.LogLicenseExpiry(status.LicenseID, status.ThresholdDays, status.DaysRemaining, status.Severity, expiresAt)
	}
	_, _ = fmt.Fprintf(stderr, "WARNING: license expires in %d day(s) on %s\n",
		status.DaysRemaining, expiresAt)
	if sentryClient != nil {
		sentryClient.AddBreadcrumb("license", "license expiry warning", status.Severity, map[string]any{
			"threshold_days": fmt.Sprintf("%d", status.ThresholdDays),
			"days_remaining": fmt.Sprintf("%d", status.DaysRemaining),
			"expires_at":     expiresAt,
		})
	}
	if saveErr := license.SaveExpiryWarningState(statePath, license.NewExpiryWarningState(status, now)); saveErr != nil {
		_, _ = fmt.Fprintf(stderr, "WARNING: license expiry state update failed: %v\n", saveErr)
	}
}

func (s *Server) startLicenseExpiryWatcher(ctx context.Context) {
	ticker := time.NewTicker(licenseRuntimeCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cfg := s.proxy.CurrentConfig()
			emitLicenseExpiryWarning(cfg, s.logger, s.sentry, s.opts.Stderr)
		case <-ctx.Done():
			return
		}
	}
}

func licenseExpiryStatePath() string {
	home := cliutil.ResolvedHome()
	if home == "" {
		if userHome, err := os.UserHomeDir(); err == nil && userHome != "" {
			home = filepath.Join(userHome, ".pipelock")
		}
	}
	if home == "" {
		return ""
	}
	return filepath.Join(home, "state", licenseExpiryStateFile)
}
