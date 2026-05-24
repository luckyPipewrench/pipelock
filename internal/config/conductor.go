// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const (
	maxConductorCreatedSkewSeconds = 300
	minConductorThreshold          = 2
	// minConductorPollInterval bounds how aggressively a follower can poll
	// Conductor. Sub-second intervals serve no purpose and turn a
	// misconfigured follower (or a compromised one) into a trivial DoS lever
	// against the control plane.
	minConductorPollInterval = time.Second
)

func (c *Config) validateConductor(warnings *[]Warning) error {
	cfg := c.Conductor
	normalizeConductor(&cfg)
	if err := validateConductorDurations(cfg); err != nil {
		return err
	}
	if err := validateConductorStalePolicy(cfg, warnings); err != nil {
		return err
	}
	if cfg.MaxMinVersionMajorSkew < 0 {
		return fmt.Errorf("conductor.max_min_version_major_skew must be >= 0, got %d", cfg.MaxMinVersionMajorSkew)
	}
	if cfg.MaxMinVersionMinorSkew < 0 {
		return fmt.Errorf("conductor.max_min_version_minor_skew must be >= 0, got %d", cfg.MaxMinVersionMinorSkew)
	}
	if cfg.MaxCapabilityThreshold < minConductorThreshold {
		return fmt.Errorf("conductor.max_capability_threshold must be >= %d, got %d", minConductorThreshold, cfg.MaxCapabilityThreshold)
	}
	if !cfg.Enabled {
		return nil
	}

	if err := validateConductorURL(cfg.ConductorURL); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"conductor.org_id":      cfg.OrgID,
		"conductor.fleet_id":    cfg.FleetID,
		"conductor.instance_id": cfg.InstanceID,
	} {
		if err := validateConductorIdentifier(field, value); err != nil {
			return err
		}
	}
	for field, value := range map[string]string{
		"conductor.trust_roster_path":       cfg.TrustRosterPath,
		"conductor.server_ca_file":          cfg.ServerCAFile,
		"conductor.client_cert_path":        cfg.ClientCertPath,
		"conductor.client_key_path":         cfg.ClientKeyPath,
		"conductor.bundle_cache_dir":        cfg.BundleCacheDir,
		"conductor.durable_audit_queue_dir": cfg.DurableAuditQueueDir,
	} {
		if err := validateConductorAbsolutePath(field, value); err != nil {
			return err
		}
	}
	for field, value := range map[string]string{
		"conductor.bundle_cache_dir":        cfg.BundleCacheDir,
		"conductor.durable_audit_queue_dir": cfg.DurableAuditQueueDir,
	} {
		if err := validateConductorPrivateParent(field, value); err != nil {
			return err
		}
	}
	for field, value := range map[string]string{
		"conductor.trust_roster_path": cfg.TrustRosterPath,
		"conductor.server_ca_file":    cfg.ServerCAFile,
		"conductor.client_cert_path":  cfg.ClientCertPath,
		"conductor.client_key_path":   cfg.ClientKeyPath,
	} {
		if err := validateConductorPrivateParent(field, value); err != nil {
			return err
		}
	}
	return nil
}

func validateConductorDurations(cfg Conductor) error {
	interval, err := time.ParseDuration(cfg.PollInterval)
	if err != nil {
		return fmt.Errorf("conductor.poll_interval must be a duration: %w", err)
	}
	if interval <= 0 {
		return fmt.Errorf("conductor.poll_interval must be > 0, got %q", cfg.PollInterval)
	}
	if interval < minConductorPollInterval {
		return fmt.Errorf("conductor.poll_interval must be >= %s, got %q", minConductorPollInterval, cfg.PollInterval)
	}
	if cfg.CreatedSkewSeconds <= 0 {
		return fmt.Errorf("conductor.created_skew_seconds must be > 0, got %d", cfg.CreatedSkewSeconds)
	}
	if cfg.CreatedSkewSeconds > maxConductorCreatedSkewSeconds {
		return fmt.Errorf("conductor.created_skew_seconds must be <= %d, got %d", maxConductorCreatedSkewSeconds, cfg.CreatedSkewSeconds)
	}
	return nil
}

func validateConductorStalePolicy(cfg Conductor, warnings *[]Warning) error {
	if cfg.StalePolicy.GraceMultiplier <= 0 {
		return fmt.Errorf("conductor.stale_policy.grace_multiplier must be > 0, got %d", cfg.StalePolicy.GraceMultiplier)
	}
	switch cfg.StalePolicy.AfterGrace {
	case ConductorStaleStrictDenyAll:
	case ConductorStaleContinueLastKnownGood:
		if cfg.Enabled {
			*warnings = append(*warnings, Warning{
				Field:   "conductor.stale_policy.after_grace",
				Message: "continue_last_known_good weakens conductor fail-closed stale-bundle behavior",
			})
		}
	default:
		return fmt.Errorf("conductor.stale_policy.after_grace must be %q or %q, got %q",
			ConductorStaleStrictDenyAll, ConductorStaleContinueLastKnownGood, cfg.StalePolicy.AfterGrace)
	}
	return nil
}

func validateConductorURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("conductor.conductor_url required when conductor.enabled is true")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("conductor.conductor_url: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("conductor.conductor_url must be an https URL with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("conductor.conductor_url must not include userinfo, query, or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("conductor.conductor_url must not include a path component, got %q", u.Path)
	}
	return nil
}

func (c Conductor) EmergencyStreamEnabled() bool {
	return c.EmergencyStream == nil || *c.EmergencyStream
}

func validateConductorIdentifier(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s required when conductor.enabled is true", field)
	}
	if len(value) > 128 {
		return fmt.Errorf("%s must be <= 128 bytes", field)
	}
	for i, r := range value {
		if r > unicode.MaxASCII {
			return fmt.Errorf("%s contains non-ASCII character %q", field, r)
		}
		if r != '_' && r != '-' && r != '.' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return fmt.Errorf("%s contains invalid character %q", field, r)
		}
		if i == 0 && (r == '_' || r == '-' || r == '.') {
			return fmt.Errorf("%s must start with an ASCII letter or digit", field)
		}
	}
	return nil
}

func validateConductorAbsolutePath(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s required when conductor.enabled is true", field)
	}
	if !filepath.IsAbs(value) {
		return fmt.Errorf("%s must be an absolute path, got %q", field, value)
	}
	if filepath.Clean(value) != value {
		return fmt.Errorf("%s must be in canonical form, got %q", field, value)
	}
	return nil
}

func validateConductorPrivateParent(field, rawPath string) error {
	clean := filepath.Clean(rawPath)
	seen := make(map[string]struct{})
	for dir := filepath.Dir(clean); ; dir = filepath.Dir(dir) {
		if err := validateConductorParentPath(field, dir, seen); err != nil {
			return err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
	}
}

func validateConductorParentPath(field, dir string, seen map[string]struct{}) error {
	dir = filepath.Clean(dir)
	if _, ok := seen[dir]; ok {
		return nil
	}
	seen[dir] = struct{}{}

	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%s resolve parent %s: %w", field, dir, err)
	}
	if err := validateConductorResolvedParent(field, dir, resolved); err != nil {
		return err
	}
	if resolved == dir {
		return nil
	}

	intendedParent := filepath.Dir(dir)
	rel, err := filepath.Rel(intendedParent, resolved)
	if err != nil {
		return fmt.Errorf("%s compare resolved parent %s to %s: %w", field, resolved, intendedParent, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("%s parent %s resolves outside intended parent %s to %s", field, dir, intendedParent, resolved)
	}
	for realDir := resolved; ; realDir = filepath.Dir(realDir) {
		if err := validateConductorParentPath(field, realDir, seen); err != nil {
			return err
		}
		parent := filepath.Dir(realDir)
		if parent == realDir {
			return nil
		}
	}
}

func validateConductorResolvedParent(field, displayPath, resolved string) error {
	info, err := os.Stat(resolved)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%s stat parent %s: %w", field, resolved, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s parent %s is not a directory", field, displayPath)
	}
	if info.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("%s must not be under world-writable parent %s", field, displayPath)
	}
	return nil
}
