//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package applycache verifies and durably activates Conductor policy bundles.
package applycache

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/rules"
)

const (
	dirMode       = 0o750
	fileMode      = 0o600
	recordVersion = 1

	activeRecordName = "active.json"
	bundlesDirName   = "bundles"
	configsDirName   = "configs"
	configExt        = ".yaml"
	recordExt        = ".json"
)

var (
	ErrCacheRequired         = errors.New("conductor apply cache required")
	ErrNoValidBundle         = errors.New("conductor apply cache has no valid bundle")
	ErrRollbackRequired      = errors.New("conductor rollback authorization required")
	ErrInvalidActiveRecord   = errors.New("conductor apply cache active record invalid")
	ErrUnsupportedMinVersion = errors.New("conductor policy bundle requires unsupported pipelock version")
	// ErrEntitlementLost aborts an in-flight policy-bundle apply when the fleet
	// entitlement is revoked/expired/downgraded mid-apply (Boundary.StillEntitled
	// reports false). It fires before the live-config Reload, so an aborted apply
	// never reaches the running proxy and never activates a durable bundle.
	ErrEntitlementLost = errors.New("conductor fleet entitlement lost during policy bundle apply")

	hashPattern = regexp.MustCompile(`\A[a-fA-F0-9]{64}\z`)
)

type Config struct {
	Dir string
}

type Identity struct {
	OrgID      string
	FleetID    string
	InstanceID string
	Labels     map[string]string
}

type verifyOptions struct {
	Identity      Identity
	Resolver      conductor.SignatureKeyResolver
	Rollback      *conductor.RollbackAuthorization
	LocalVersion  string
	Now           func() time.Time
	AllowRollback bool
}

type Cache struct {
	dir        string
	bundlesDir string
	configsDir string
	now        func() time.Time
	mu         sync.Mutex
}

type VerifiedBundle struct {
	Bundle     conductor.PolicyBundle
	BundleHash string
	VerifiedAt time.Time
	ConfigPath string
}

type diskBundleRecord struct {
	Version    int                    `json:"version"`
	VerifiedAt time.Time              `json:"verified_at"`
	BundleHash string                 `json:"bundle_hash"`
	BaseHash   string                 `json:"base_hash,omitempty"`
	Bundle     conductor.PolicyBundle `json:"bundle"`
}

type activeRecord struct {
	Version       int       `json:"version"`
	ActivatedAt   time.Time `json:"activated_at"`
	BundleHash    string    `json:"bundle_hash"`
	BundleID      string    `json:"bundle_id"`
	BundleVersion uint64    `json:"bundle_version"`
	PolicyHash    string    `json:"policy_hash"`
	ConfigFile    string    `json:"config_file"`
}

func Open(cfg Config) (*Cache, error) {
	if strings.TrimSpace(cfg.Dir) == "" {
		return nil, fmt.Errorf("%w: cache dir required", ErrCacheRequired)
	}
	root, bundlesDir, configsDir, err := ensurePrivateDirs(filepath.Clean(cfg.Dir))
	if err != nil {
		return nil, err
	}
	for _, dir := range []string{root, bundlesDir, configsDir} {
		if err := sweepStaleTemps(dir); err != nil {
			return nil, err
		}
	}
	return &Cache{
		dir:        root,
		bundlesDir: bundlesDir,
		configsDir: configsDir,
		now:        func() time.Time { return time.Now().UTC() },
	}, nil
}

func (c *Cache) storeVerified(bundle conductor.PolicyBundle, opts verifyOptions) (VerifiedBundle, error) {
	verified, err := c.stageVerified(bundle, opts)
	if err != nil {
		return VerifiedBundle{}, err
	}
	if err := c.activate(verified); err != nil {
		return VerifiedBundle{}, err
	}
	return verified, nil
}

func (c *Cache) stageVerified(bundle conductor.PolicyBundle, opts verifyOptions) (VerifiedBundle, error) {
	if c == nil {
		return VerifiedBundle{}, ErrCacheRequired
	}
	now := c.nowUTC(opts)
	if err := verifyBundle(now, bundle, opts); err != nil {
		return VerifiedBundle{}, err
	}
	bundleHash, err := bundle.CanonicalHash()
	if err != nil {
		return VerifiedBundle{}, err
	}
	if err := validateHash(bundleHash); err != nil {
		return VerifiedBundle{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	current, currentErr := c.readActiveLocked()
	baseHash := ""
	if currentErr != nil && !errors.Is(currentErr, ErrNoValidBundle) {
		return VerifiedBundle{}, currentErr
	}
	if currentErr == nil {
		baseHash = current.BundleHash
		if err := authorizeVersionTransition(now, current.Bundle, bundle, opts); err != nil {
			return VerifiedBundle{}, err
		}
	}

	record := diskBundleRecord{
		Version:    recordVersion,
		VerifiedAt: now,
		BundleHash: bundleHash,
		BaseHash:   baseHash,
		Bundle:     bundle,
	}
	recordBytes, err := json.Marshal(record)
	if err != nil {
		return VerifiedBundle{}, fmt.Errorf("conductor apply cache: marshal bundle record: %w", err)
	}
	configName := bundleHash + configExt
	recordName := bundleHash + recordExt
	configPath := filepath.Join(c.configsDir, configName)
	if err := durableWrite(filepath.Join(c.bundlesDir, recordName), recordBytes); err != nil {
		return VerifiedBundle{}, err
	}
	if err := durableWrite(configPath, []byte(bundle.Payload.ConfigYAML)); err != nil {
		return VerifiedBundle{}, err
	}
	return VerifiedBundle{
		Bundle:     bundle,
		BundleHash: bundleHash,
		VerifiedAt: now,
		ConfigPath: configPath,
	}, nil
}

func (c *Cache) activate(verified VerifiedBundle) error {
	if c == nil {
		return ErrCacheRequired
	}
	if err := validateHash(verified.BundleHash); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	record, err := readBundleRecord(filepath.Join(c.bundlesDir, verified.BundleHash+recordExt))
	if err != nil {
		return err
	}
	if record.Bundle.BundleID != verified.Bundle.BundleID ||
		record.Bundle.Version != verified.Bundle.Version ||
		record.Bundle.PolicyHash != verified.Bundle.PolicyHash {
		return fmt.Errorf("%w: staged bundle does not match activation request", ErrInvalidActiveRecord)
	}
	current, currentErr := c.readActiveLocked()
	if currentErr != nil && !errors.Is(currentErr, ErrNoValidBundle) {
		return currentErr
	}
	if currentErr == nil && !strings.EqualFold(record.BaseHash, current.BundleHash) {
		return fmt.Errorf("%w: active bundle changed since staging", ErrInvalidActiveRecord)
	}
	if errors.Is(currentErr, ErrNoValidBundle) && record.BaseHash != "" {
		return fmt.Errorf("%w: active bundle removed since staging", ErrInvalidActiveRecord)
	}
	configName := verified.BundleHash + configExt
	configPath := filepath.Join(c.configsDir, configName)
	if err := validateRegularFile(configPath, conductor.MaxConfigYAMLBytes); err != nil {
		return err
	}
	active := activeRecord{
		Version:       recordVersion,
		ActivatedAt:   c.now().UTC(),
		BundleHash:    verified.BundleHash,
		BundleID:      verified.Bundle.BundleID,
		BundleVersion: verified.Bundle.Version,
		PolicyHash:    verified.Bundle.PolicyHash,
		ConfigFile:    filepath.ToSlash(filepath.Join(configsDirName, configName)),
	}
	activeBytes, err := json.Marshal(active)
	if err != nil {
		return fmt.Errorf("conductor apply cache: marshal active record: %w", err)
	}
	if err := durableWrite(filepath.Join(c.dir, activeRecordName), activeBytes); err != nil {
		return err
	}
	return nil
}

func (c *Cache) Active() (VerifiedBundle, error) {
	if c == nil {
		return VerifiedBundle{}, ErrCacheRequired
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readActiveLocked()
}

func (c *Cache) readActiveLocked() (VerifiedBundle, error) {
	activePath := filepath.Join(c.dir, activeRecordName)
	active, err := readActiveRecord(activePath)
	if err != nil {
		return VerifiedBundle{}, err
	}
	bundleRecord, err := readBundleRecord(filepath.Join(c.bundlesDir, active.BundleHash+recordExt))
	if err != nil {
		return VerifiedBundle{}, err
	}
	if bundleRecord.BundleHash != active.BundleHash ||
		bundleRecord.Bundle.BundleID != active.BundleID ||
		bundleRecord.Bundle.Version != active.BundleVersion ||
		bundleRecord.Bundle.PolicyHash != active.PolicyHash {
		return VerifiedBundle{}, fmt.Errorf("%w: active pointer does not match bundle record", ErrInvalidActiveRecord)
	}
	configPath := filepath.Join(c.dir, filepath.FromSlash(active.ConfigFile))
	if err := validateContainedPath(c.dir, configPath); err != nil {
		return VerifiedBundle{}, err
	}
	if err := validateRegularFile(configPath, conductor.MaxConfigYAMLBytes); err != nil {
		return VerifiedBundle{}, err
	}
	return VerifiedBundle{
		Bundle:     bundleRecord.Bundle,
		BundleHash: active.BundleHash,
		VerifiedAt: bundleRecord.VerifiedAt,
		ConfigPath: configPath,
	}, nil
}

func verifyBundle(now time.Time, bundle conductor.PolicyBundle, opts verifyOptions) error {
	if err := bundle.ValidateAtTime(now); err != nil {
		return err
	}
	if err := bundle.VerifySignaturesAt(now, opts.Resolver); err != nil {
		return err
	}
	if err := bundle.ValidateForFollower(opts.Identity.OrgID, opts.Identity.FleetID, opts.Identity.InstanceID, opts.Identity.Labels); err != nil {
		return err
	}
	if strings.TrimSpace(opts.LocalVersion) != "" {
		if err := rules.CheckMinPipelock(bundle.MinPipelockVersion, opts.LocalVersion); err != nil {
			return fmt.Errorf("%w: %w", ErrUnsupportedMinVersion, err)
		}
	}
	return nil
}

func authorizeVersionTransition(now time.Time, current, next conductor.PolicyBundle, opts verifyOptions) error {
	if next.Version > current.Version {
		currentHash, err := current.CanonicalHash()
		if err != nil {
			return err
		}
		if strings.EqualFold(next.PreviousBundleHash, currentHash) {
			return nil
		}
		return fmt.Errorf("%w: previous_bundle_hash does not match active bundle", conductor.ErrInvalidRollback)
	}
	if current.BundleID == next.BundleID && current.Version == next.Version {
		currentHash, err := current.CanonicalHash()
		if err != nil {
			return err
		}
		nextHash, err := next.CanonicalHash()
		if err != nil {
			return err
		}
		if strings.EqualFold(currentHash, nextHash) {
			return nil
		}
	}
	if !opts.AllowRollback || opts.Rollback == nil {
		return ErrRollbackRequired
	}
	auth := *opts.Rollback
	if err := auth.ValidateAtTime(now); err != nil {
		return err
	}
	if err := auth.VerifySignaturesAt(now, opts.Resolver); err != nil {
		return err
	}
	if auth.OrgID != opts.Identity.OrgID || auth.FleetID != opts.Identity.FleetID {
		return fmt.Errorf("%w: org_id/fleet_id", conductor.ErrAudienceMismatch)
	}
	if !auth.Audience.Matches(opts.Identity.InstanceID, opts.Identity.Labels) {
		return fmt.Errorf("%w: instance_id=%q", conductor.ErrAudienceMismatch, opts.Identity.InstanceID)
	}
	if auth.CurrentBundleID != current.BundleID ||
		auth.CurrentVersion != current.Version ||
		auth.TargetBundleID != next.BundleID ||
		auth.TargetVersion != next.Version {
		return fmt.Errorf("%w: authorization does not match active and target bundles", conductor.ErrInvalidRollback)
	}
	return nil
}

func (c *Cache) nowUTC(opts verifyOptions) time.Time {
	if opts.Now != nil {
		return opts.Now().UTC()
	}
	if c.now != nil {
		return c.now().UTC()
	}
	return time.Now().UTC()
}

func readActiveRecord(path string) (activeRecord, error) {
	var active activeRecord
	if err := readJSONFile(path, conductor.MaxConfigYAMLBytes, &active); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return activeRecord{}, ErrNoValidBundle
		}
		return activeRecord{}, err
	}
	if active.Version != recordVersion {
		return activeRecord{}, fmt.Errorf("%w: version=%d", ErrInvalidActiveRecord, active.Version)
	}
	if active.ActivatedAt.IsZero() ||
		strings.TrimSpace(active.BundleID) == "" ||
		active.BundleVersion == 0 ||
		strings.TrimSpace(active.PolicyHash) == "" ||
		strings.TrimSpace(active.ConfigFile) == "" {
		return activeRecord{}, fmt.Errorf("%w: missing metadata", ErrInvalidActiveRecord)
	}
	if err := validateHash(active.BundleHash); err != nil {
		return activeRecord{}, fmt.Errorf("%w: %w", ErrInvalidActiveRecord, err)
	}
	if filepath.IsAbs(active.ConfigFile) || strings.Contains(active.ConfigFile, `\`) {
		return activeRecord{}, fmt.Errorf("%w: invalid config_file", ErrInvalidActiveRecord)
	}
	wantConfigFile := filepath.ToSlash(filepath.Join(configsDirName, active.BundleHash+configExt))
	if active.ConfigFile != wantConfigFile {
		return activeRecord{}, fmt.Errorf("%w: config_file=%q want %q", ErrInvalidActiveRecord, active.ConfigFile, wantConfigFile)
	}
	return active, nil
}

func readBundleRecord(path string) (diskBundleRecord, error) {
	var record diskBundleRecord
	if err := readJSONFile(path, conductor.MaxConfigYAMLBytes*2, &record); err != nil {
		return diskBundleRecord{}, err
	}
	if record.Version != recordVersion {
		return diskBundleRecord{}, fmt.Errorf("%w: bundle record version=%d", ErrInvalidActiveRecord, record.Version)
	}
	if record.VerifiedAt.IsZero() {
		return diskBundleRecord{}, fmt.Errorf("%w: missing verified_at", ErrInvalidActiveRecord)
	}
	if err := validateHash(record.BundleHash); err != nil {
		return diskBundleRecord{}, fmt.Errorf("%w: %w", ErrInvalidActiveRecord, err)
	}
	if record.BaseHash != "" {
		if err := validateHash(record.BaseHash); err != nil {
			return diskBundleRecord{}, fmt.Errorf("%w: %w", ErrInvalidActiveRecord, err)
		}
	}
	hash, err := record.Bundle.CanonicalHash()
	if err != nil {
		return diskBundleRecord{}, err
	}
	if !strings.EqualFold(hash, record.BundleHash) {
		return diskBundleRecord{}, fmt.Errorf("%w: bundle hash mismatch", ErrInvalidActiveRecord)
	}
	if err := record.Bundle.Validate(); err != nil {
		return diskBundleRecord{}, err
	}
	return record, nil
}

func readJSONFile(path string, maxBytes int, dst any) error {
	if err := validateRegularFile(path, maxBytes); err != nil {
		return err
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	decoder := json.NewDecoder(io.LimitReader(f, int64(maxBytes)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("%w: decode JSON record: %w", ErrInvalidActiveRecord, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON document", ErrInvalidActiveRecord)
	}
	return nil
}

func validateRegularFile(path string, maxBytes int) error {
	info, err := os.Lstat(filepath.Clean(path))
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s must not be a symlink", ErrInvalidActiveRecord, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInvalidActiveRecord, path)
	}
	if info.Size() > int64(maxBytes) {
		return fmt.Errorf("%w: file_bytes=%d cap=%d", conductor.ErrPayloadTooLarge, info.Size(), maxBytes)
	}
	return nil
}

func validateHash(hash string) error {
	if !hashPattern.MatchString(hash) {
		return fmt.Errorf("%w: expected 64 hex chars", conductor.ErrInvalidHash)
	}
	return nil
}

func ensurePrivateDirs(dir string) (string, string, string, error) {
	root, err := ensurePrivateDir(dir)
	if err != nil {
		return "", "", "", err
	}
	bundlesDir := filepath.Join(root, bundlesDirName)
	configsDir := filepath.Join(root, configsDirName)
	for _, subdir := range []*string{&bundlesDir, &configsDir} {
		resolved, err := ensurePrivateDir(*subdir)
		if err != nil {
			return "", "", "", err
		}
		if err := validateContainedPath(root, resolved); err != nil {
			return "", "", "", err
		}
		*subdir = resolved
	}
	return root, bundlesDir, configsDir, nil
}

func ensurePrivateDir(dir string) (string, error) {
	clean := filepath.Clean(dir)
	abs, err := filepath.Abs(clean)
	if err != nil {
		return "", fmt.Errorf("conductor apply cache: absolute dir %s: %w", dir, err)
	}
	if err := rejectSymlinkAncestors(abs); err != nil {
		return "", err
	}
	if err := os.MkdirAll(clean, dirMode); err != nil {
		return "", fmt.Errorf("conductor apply cache: create dir %s: %w", dir, err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("conductor apply cache: stat dir %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("conductor apply cache: dir %s must not be a symlink", dir)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("conductor apply cache: %s is not a directory", dir)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("conductor apply cache: resolve dir %s: %w", dir, err)
	}
	if info.Mode().Perm() != dirMode {
		if err := os.Chmod(resolved, dirMode); err != nil {
			return "", fmt.Errorf("conductor apply cache: chmod dir %s: %w", resolved, err)
		}
	}
	return resolved, nil
}

func rejectSymlinkAncestors(abs string) error {
	dir := filepath.Dir(abs)
	parents := make([]string, 0, 8)
	for {
		parents = append(parents, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	for i := len(parents) - 1; i >= 0; i-- {
		info, err := os.Lstat(parents[i])
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return fmt.Errorf("conductor apply cache: stat dir ancestor %s: %w", parents[i], err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("conductor apply cache: dir ancestor %s must not be a symlink", parents[i])
		}
		if !info.IsDir() {
			return fmt.Errorf("conductor apply cache: dir ancestor %s is not a directory", parents[i])
		}
	}
	return nil
}

func validateContainedPath(root, path string) error {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("conductor apply cache: resolve path %s: %w", path, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("conductor apply cache: path %s escapes root %s", path, root)
	}
	return nil
}

func durableWrite(path string, data []byte) error {
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("conductor apply cache: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("conductor apply cache: write temp: %w", err)
	}
	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("conductor apply cache: chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("conductor apply cache: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("conductor apply cache: close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("conductor apply cache: rename temp: %w", err)
	}
	cleanup = false
	return fsyncDir(dir)
}

func fsyncDir(dir string) error {
	f, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return fmt.Errorf("conductor apply cache: open dir for fsync %s: %w", dir, err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
			return nil
		}
		return fmt.Errorf("conductor apply cache: fsync dir %s: %w", dir, err)
	}
	return nil
}

func sweepStaleTemps(dir string) error {
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return fmt.Errorf("conductor apply cache: scan stale temps in %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("conductor apply cache: remove stale temp %s: %w", entry.Name(), err)
		}
	}
	return nil
}
