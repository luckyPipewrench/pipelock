// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads, parses, defaults, and validates a Pipelock config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	cfg := &Config{}
	// Strict parse: reject unknown top-level and nested fields so typos like
	// `sentinel_path` (should be `sentinel_file`) or `escalation_threshold`
	// misspelled as `threshold` fail loud at startup instead of being
	// silently dropped and leaving security features inert. yaml.v3 reports
	// the offending line and field name in the error message.
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	// Reject trailing documents. yaml.v3 Decoder.Decode consumes exactly one
	// document per call, so a config with `---`-separated extra documents
	// would otherwise silently load only the first. That is a bypass vector:
	// an attacker who can inject a leading document could shadow the real
	// config. Require a single document.
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, fmt.Errorf("parsing config %s: multiple YAML documents not supported (pipelock config must be a single document)", path)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	cfg.rawBytes = data

	// Detect omitted security booleans via raw YAML introspection and
	// default them to true (fail-closed). Must run before ApplyDefaults().
	applySecurityDefaults(data, cfg)

	cfg.ApplyDefaults()

	// Resolve license key from multiple sources. Priority:
	// - PIPELOCK_LICENSE_KEY env var (containers, CI)
	// - license_file config field (file path, read at startup)
	// - license_key config field (inline YAML, lowest priority)
	if err := cfg.resolveLicenseKey(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("license key: %w", err)
	}

	// Soft-gate premium features: disable agents section if no license key.
	if EnforceLicenseGateFunc != nil {
		EnforceLicenseGateFunc(cfg)
	}

	// Resolve relative secrets_file path relative to config file directory.
	if cfg.DLP.SecretsFile != "" && !filepath.IsAbs(cfg.DLP.SecretsFile) {
		cfg.DLP.SecretsFile = filepath.Join(filepath.Dir(path), cfg.DLP.SecretsFile)
	}

	// Resolve relative CA cert/key paths relative to config file directory.
	// This ensures TLS interception works under systemd (CWD=/), containers,
	// and when --config points to a non-local path.
	configDir := filepath.Dir(path)
	if cfg.TLSInterception.CACertPath != "" && !filepath.IsAbs(cfg.TLSInterception.CACertPath) {
		cfg.TLSInterception.CACertPath = filepath.Join(configDir, cfg.TLSInterception.CACertPath)
	}
	if cfg.TLSInterception.CAKeyPath != "" && !filepath.IsAbs(cfg.TLSInterception.CAKeyPath) {
		cfg.TLSInterception.CAKeyPath = filepath.Join(configDir, cfg.TLSInterception.CAKeyPath)
	}

	// Resolve relative file_sentry.watch_paths against config file directory.
	// "." in the config means the project directory, not whatever CWD the
	// process happens to have (systemd sets CWD=/, containers vary).
	//
	// Relative paths with ".." traversal are rejected to prevent
	// unintentional escapes. Absolute paths are allowed as-is since the
	// user explicitly chose the target directory.
	for i, p := range cfg.FileSentry.WatchPaths {
		if !filepath.IsAbs(p) {
			resolved := filepath.Clean(filepath.Join(configDir, p))
			// Verify the resolved path is still under the config directory.
			// filepath.Rel returns a ".." prefix if the target escapes.
			rel, err := filepath.Rel(configDir, resolved)
			// Separator-aware escape check: exact ".." or a path segment
			// starting with ".." + os.PathSeparator. Plain HasPrefix(rel, "..")
			// would reject valid names like "..cache" inside the config dir.
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				return nil, fmt.Errorf("file_sentry: watch_paths[%d] %q escapes config directory (use absolute path instead)", i, p)
			}
			cfg.FileSentry.WatchPaths[i] = resolved
		} else {
			cfg.FileSentry.WatchPaths[i] = filepath.Clean(cfg.FileSentry.WatchPaths[i])
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Eagerly warm the canonical policy hash cache so the hash is
	// computed once against the post-Validate / post-ApplyDefaults
	// snapshot that Load guarantees is immutable to the caller. Every
	// subsequent CanonicalPolicyHash() call (reload, emitter wiring,
	// per-request stamping) reads the same memoised value without
	// observing any post-Load mutation. Documented in
	// CanonicalPolicyHash's godoc; this is the Load-time half of the
	// "Config is frozen after Load" contract.
	_ = cfg.CanonicalPolicyHash()

	return cfg, nil
}

// resolveLicenseKey populates LicenseKey from the highest-priority source:
// env var > license_file > inline license_key. The configDir is used to
// resolve relative license_file paths.
func (c *Config) resolveLicenseKey(configDir string) error {
	// Env var takes highest priority. Trim before checking so that a
	// whitespace-only value (e.g. trailing newline) falls through to
	// lower-priority sources instead of winning with an empty token.
	if envKey := strings.TrimSpace(os.Getenv(EnvLicenseKey)); envKey != "" {
		c.LicenseKey = envKey
		return nil
	}

	// File path: read token from the file.
	if c.LicenseFile != "" {
		p := c.LicenseFile
		if !filepath.IsAbs(p) {
			p = filepath.Join(configDir, p)
		}
		p = filepath.Clean(p)
		// Reject non-regular files (FIFOs, devices) that could hang
		// startup, and oversized files since tokens are ~200 bytes.
		const maxLicenseFileBytes int64 = 16 * 1024
		info, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("stat license_file %s: %w", c.LicenseFile, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("license_file %s must be a regular file", c.LicenseFile)
		}
		// Reject group-write/execute and all other access. Group-read
		// (0o040) is allowed for k8s Secret volumes where fsGroup adds
		// group-read automatically.
		if info.Mode().Perm()&0o037 != 0 {
			return fmt.Errorf("license_file %s is too permissive (mode %04o): restrict to 0600 or 0640",
				c.LicenseFile, info.Mode().Perm())
		}
		if info.Size() > maxLicenseFileBytes {
			return fmt.Errorf("license_file %s exceeds %d bytes", c.LicenseFile, maxLicenseFileBytes)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("reading license_file %s: %w", c.LicenseFile, err)
		}
		token := strings.TrimSpace(string(data))
		if token == "" {
			return fmt.Errorf("license_file %s is empty", c.LicenseFile)
		}
		c.LicenseKey = token
		return nil
	}

	// Inline license_key from YAML stays as-is (already parsed).
	return nil
}

// Hash returns the SHA256 hex digest of the raw config file bytes.
// Returns "defaults" if the config was created via Defaults() (no file).
func (c *Config) Hash() string {
	if c.rawBytes == nil {
		return HashDefaults
	}
	h := sha256.Sum256(c.rawBytes)
	return hex.EncodeToString(h[:])
}
