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
	"strconv"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/secperm"
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
	cfg.resolveLicenseIntermediate(filepath.Dir(path))
	cfg.resolveLicenseRuntimeVerification()

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
	for i, wp := range cfg.FileSentry.WatchPaths {
		p := wp.Path
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
			cfg.FileSentry.WatchPaths[i].Path = resolved
		} else {
			cfg.FileSentry.WatchPaths[i].Path = filepath.Clean(p)
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	cfg.canonicalHashCache = &canonicalHashCacheHolder{}

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

// resolveLicenseIntermediate populates LicenseIntermediateCert from
// license_intermediate_file, resolving relative paths against configDir.
// Empty/omitted means legacy direct-root verification.
func (c *Config) resolveLicenseIntermediate(configDir string) {
	if strings.TrimSpace(c.LicenseIntermediateFile) == "" {
		c.LicenseIntermediateFile = ""
		c.LicenseIntermediateCert = nil
		c.LicenseIntermediateLoadError = ""
		return
	}
	p := c.LicenseIntermediateFile
	if !filepath.IsAbs(p) {
		p = filepath.Join(configDir, p)
	}
	p = filepath.Clean(p)
	data, err := license.LoadIntermediateCertFile(p)
	if err != nil {
		c.LicenseIntermediateFile = p
		c.LicenseIntermediateLoadError = err.Error()
		c.LicenseIntermediateCert = []byte("configured intermediate certificate unavailable")
		return
	}
	c.LicenseIntermediateFile = p
	c.LicenseIntermediateCert = data
	c.LicenseIntermediateLoadError = ""
}

// resolveLicenseRuntimeVerification folds the env-provided CRL path and verifier
// public key into the Config when not set inline, mirroring the fallbacks that
// VerifyFleetWithIntermediate / checkAssessLicense already apply at startup. This
// keeps runtime license enforcement (CRL watcher, expiry timer, reload
// re-verification — all of which read the resolved Config, not the env) in sync
// with startup verification. Inline config values win; env is a fallback only.
func (c *Config) resolveLicenseRuntimeVerification() {
	if c.LicenseCRLFile == "" {
		if env := strings.TrimSpace(os.Getenv(EnvLicenseCRLFile)); env != "" {
			c.LicenseCRLFile = env
		}
	}
	if c.LicensePublicKey == "" {
		if env := strings.TrimSpace(os.Getenv(EnvLicensePublicKey)); env != "" {
			c.LicensePublicKey = env
		}
	}
	c.resolveLicenseRequireIntermediate()
	c.resolveLicenseCRLMaxAge()
}

// resolveLicenseCRLMaxAge materializes the effective CRL freshness window into
// LicenseCRLMaxAgeResolved so runtime consumers read the same window the startup
// gate uses. An explicit config field wins; otherwise the env
// (EnvLicenseCRLMaxAge) is consulted. Unlike the require toggle, the fail-safe
// here is the DEFAULT, never "no check": a malformed or non-positive value is
// recorded (LicenseCRLMaxAgeError, surfaced as a WARNING) and clamped to
// DefaultCRLMaxAge. A value that parses but is <= 0 would DISABLE freshness if
// passed through, so it is treated as a misconfiguration and clamped too — a
// configured knob must never be able to turn the freshness gate off.
func (c *Config) resolveLicenseCRLMaxAge() {
	raw := strings.TrimSpace(c.LicenseCRLMaxAge)
	if raw == "" {
		if env := strings.TrimSpace(os.Getenv(EnvLicenseCRLMaxAge)); env != "" {
			raw = env
		}
	}
	if raw == "" {
		c.LicenseCRLMaxAgeResolved = license.DefaultCRLMaxAge
		c.LicenseCRLMaxAgeError = ""
		return
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		c.LicenseCRLMaxAgeResolved = license.DefaultCRLMaxAge
		c.LicenseCRLMaxAgeError = fmt.Sprintf("%q is not a valid duration", raw)
		return
	}
	if d <= 0 {
		c.LicenseCRLMaxAgeResolved = license.DefaultCRLMaxAge
		c.LicenseCRLMaxAgeError = fmt.Sprintf("%q must be a positive duration", raw)
		return
	}
	c.LicenseCRLMaxAgeResolved = d
	c.LicenseCRLMaxAgeError = ""
}

// resolveLicenseRequireIntermediate materializes the effective
// require-intermediate value into LicenseRequireIntermediateResolved so runtime
// consumers (CRL watcher, reload classifier, EnforceLicenseGate) read the same
// value the startup gate uses. An explicit config field wins; otherwise the env
// is consulted. A malformed env value is recorded
// (LicenseRequireIntermediateEnvError) and resolved to TRUE — fail closed to the
// strictest interpretation: an operator who set this env was trying to ENABLE
// require mode, so a typo must never silently re-open the direct-root fallback.
// Validate surfaces the error as a WARNING and the free proxy never crashes on a
// license-trust misconfiguration (require=true + no intermediate just disables
// paid surfaces), so failing closed here is safe and matches operator intent.
func (c *Config) resolveLicenseRequireIntermediate() {
	if c.LicenseRequireIntermediate != nil {
		c.LicenseRequireIntermediateResolved = *c.LicenseRequireIntermediate
		c.LicenseRequireIntermediateEnvError = ""
		return
	}
	raw, ok := os.LookupEnv(EnvLicenseRequireIntermediate)
	if !ok {
		c.LicenseRequireIntermediateResolved = false
		c.LicenseRequireIntermediateEnvError = ""
		return
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		c.LicenseRequireIntermediateResolved = false
		c.LicenseRequireIntermediateEnvError = ""
		return
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		// Fail closed: a malformed enable-toggle resolves to ON, never OFF, so a
		// typo cannot silently re-enable the legacy direct-root fallback.
		c.LicenseRequireIntermediateResolved = true
		c.LicenseRequireIntermediateEnvError = fmt.Sprintf("%q is not a boolean", raw)
		return
	}
	c.LicenseRequireIntermediateResolved = v
	c.LicenseRequireIntermediateEnvError = ""
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
		if secperm.TooPermissive(info.Mode().Perm(), 0o037) {
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
