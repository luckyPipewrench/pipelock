//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package applycache

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// storeValidActive stores one signed bundle and returns the cache plus the
// activated bundle hash. The on-disk state is a valid active pointer + bundle
// record + config file, ready to be tampered with.
func storeValidActive(t *testing.T) (*Cache, string) {
	t.Helper()
	key := newTestKey(t)
	cache := openTestCache(t)
	bundle := signedTestBundle(t, key, "bundle-1", 1, "")
	verified, err := cache.storeVerified(bundle, testVerifyOptions(key))
	if err != nil {
		t.Fatalf("storeVerified() error = %v", err)
	}
	return cache, verified.BundleHash
}

func activePath(c *Cache) string { return filepath.Join(c.dir, activeRecordName) }

func readActiveJSON(t *testing.T, c *Cache) activeRecord {
	t.Helper()
	data, err := os.ReadFile(activePath(c))
	if err != nil {
		t.Fatalf("read active.json: %v", err)
	}
	var rec activeRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("unmarshal active.json: %v", err)
	}
	return rec
}

func writeActiveJSON(t *testing.T, c *Cache, rec activeRecord) {
	t.Helper()
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal active.json: %v", err)
	}
	if err := os.WriteFile(activePath(c), data, 0o600); err != nil {
		t.Fatalf("write active.json: %v", err)
	}
}

// TestActiveRecordRejectsTampering proves the active pointer's at-rest
// integrity checks reject every shape of corruption an attacker with cache
// write access (or bit-rot) could produce. These checks are the security
// mechanism behind last-known-good: if they pass tampered state, the whole
// signed-bundle guarantee collapses.
func TestActiveRecordRejectsTampering(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(rec *activeRecord, validHash string)
	}{
		{"wrong_version", func(r *activeRecord, _ string) { r.Version = 999 }},
		{"missing_bundle_id", func(r *activeRecord, _ string) { r.BundleID = "" }},
		{"zero_bundle_version", func(r *activeRecord, _ string) { r.BundleVersion = 0 }},
		{"missing_policy_hash", func(r *activeRecord, _ string) { r.PolicyHash = "" }},
		{"missing_config_file", func(r *activeRecord, _ string) { r.ConfigFile = "" }},
		{"non_hex_bundle_hash", func(r *activeRecord, _ string) { r.BundleHash = strings.Repeat("z", 64) }},
		{"absolute_config_file", func(r *activeRecord, _ string) { r.ConfigFile = "/etc/passwd" }},
		{"backslash_config_file", func(r *activeRecord, _ string) { r.ConfigFile = `configs\evil.yaml` }},
		{"traversal_config_file", func(r *activeRecord, _ string) { r.ConfigFile = "configs/../../etc/passwd" }},
		{"config_file_hash_mismatch", func(r *activeRecord, _ string) {
			r.ConfigFile = filepath.ToSlash(filepath.Join(configsDirName, strings.Repeat("a", 64)+configExt))
		}},
		{"pointer_bundle_id_mismatch", func(r *activeRecord, _ string) { r.BundleID = "different-bundle" }},
		{"pointer_version_mismatch", func(r *activeRecord, _ string) { r.BundleVersion = 42 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache, hash := storeValidActive(t)
			rec := readActiveJSON(t, cache)
			tc.mutate(&rec, hash)
			writeActiveJSON(t, cache, rec)
			if _, err := cache.Active(); !errors.Is(err, ErrInvalidActiveRecord) {
				t.Fatalf("Active() after %s = %v, want ErrInvalidActiveRecord", tc.name, err)
			}
		})
	}
}

func TestActiveRecordMissingPointer(t *testing.T) {
	cache := openTestCache(t)
	if _, err := cache.Active(); !errors.Is(err, ErrNoValidBundle) {
		t.Fatalf("Active() with no pointer = %v, want ErrNoValidBundle", err)
	}
}

func TestActiveRecordRejectsTrailingJSON(t *testing.T) {
	cache, _ := storeValidActive(t)
	data, err := os.ReadFile(activePath(cache))
	if err != nil {
		t.Fatalf("read active.json: %v", err)
	}
	if err := os.WriteFile(activePath(cache), append(data, []byte("\n{}")...), 0o600); err != nil {
		t.Fatalf("write active.json: %v", err)
	}
	if _, err := cache.Active(); !errors.Is(err, ErrInvalidActiveRecord) {
		t.Fatalf("Active() with trailing JSON = %v, want ErrInvalidActiveRecord", err)
	}
}

func TestActiveRecordRejectsMalformedJSON(t *testing.T) {
	cache, _ := storeValidActive(t)
	if err := os.WriteFile(activePath(cache), []byte(`{"version":`), 0o600); err != nil {
		t.Fatalf("write active.json: %v", err)
	}
	if _, err := cache.Active(); !errors.Is(err, ErrInvalidActiveRecord) {
		t.Fatalf("Active() with malformed JSON = %v, want ErrInvalidActiveRecord", err)
	}
}

// TestBundleRecordRejectsTampering proves the staged bundle record is bound to
// its content hash: flipping the cached config or metadata is detected.
func TestBundleRecordRejectsTampering(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(rec *diskBundleRecord)
	}{
		{"content_hash_mismatch", func(r *diskBundleRecord) {
			r.Bundle.Payload.ConfigYAML += "\n# tampered\n"
		}},
		{"wrong_record_version", func(r *diskBundleRecord) { r.Version = 999 }},
		{"missing_verified_at", func(r *diskBundleRecord) { r.VerifiedAt = time.Time{} }},
		{"non_hex_stored_hash", func(r *diskBundleRecord) { r.BundleHash = strings.Repeat("z", 64) }},
		{"non_hex_base_hash", func(r *diskBundleRecord) { r.BaseHash = strings.Repeat("z", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache, hash := storeValidActive(t)
			recPath := filepath.Join(cache.bundlesDir, hash+recordExt)
			data, err := os.ReadFile(filepath.Clean(recPath))
			if err != nil {
				t.Fatalf("read bundle record: %v", err)
			}
			var rec diskBundleRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				t.Fatalf("unmarshal bundle record: %v", err)
			}
			tc.mutate(&rec)
			out, err := json.Marshal(rec)
			if err != nil {
				t.Fatalf("marshal bundle record: %v", err)
			}
			if err := os.WriteFile(recPath, out, 0o600); err != nil {
				t.Fatalf("write bundle record: %v", err)
			}
			if _, err := cache.Active(); err == nil {
				t.Fatalf("Active() after %s = nil, want rejection", tc.name)
			}
		})
	}
}

// TestActivateRejectsStaleStagedBase proves activation is compare-and-swapped
// against the active bundle observed at stage time. Without this, concurrent
// apply paths could reload one bundle and activate another older staged bundle.
func TestActivateRejectsStaleStagedBase(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	opts := testVerifyOptions(key)

	v1 := signedTestBundle(t, key, "bundle-1", 1, "")
	if _, err := cache.storeVerified(v1, opts); err != nil {
		t.Fatalf("storeVerified(v1): %v", err)
	}
	v1Hash, err := v1.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(v1): %v", err)
	}

	v2 := signedTestBundle(t, key, "bundle-2", 2, v1Hash)
	stagedV2, err := cache.stageVerified(v2, opts)
	if err != nil {
		t.Fatalf("stageVerified(v2): %v", err)
	}

	v3 := signedTestBundle(t, key, "bundle-3", 3, v1Hash)
	if _, err := cache.storeVerified(v3, opts); err != nil {
		t.Fatalf("storeVerified(v3): %v", err)
	}
	if err := cache.activate(stagedV2); !errors.Is(err, ErrInvalidActiveRecord) {
		t.Fatalf("activate(stale v2) = %v, want ErrInvalidActiveRecord", err)
	}
	active, err := cache.Active()
	if err != nil {
		t.Fatalf("Active(): %v", err)
	}
	if active.Bundle.BundleID != "bundle-3" {
		t.Fatalf("active bundle = %q, want bundle-3", active.Bundle.BundleID)
	}
}

// TestActiveRejectsSymlinkConfig proves the config file is read with a symlink
// guard: an attacker can't repoint the active config at an arbitrary file.
func TestActiveRejectsSymlinkConfig(t *testing.T) {
	cache, hash := storeValidActive(t)
	configPath := filepath.Join(cache.configsDir, hash+configExt)
	if err := os.Remove(configPath); err != nil {
		t.Fatalf("remove config: %v", err)
	}
	target := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(target, []byte("mode: monitor\n"), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Symlink(target, configPath); err != nil {
		t.Fatalf("symlink config: %v", err)
	}
	if _, err := cache.Active(); !errors.Is(err, ErrInvalidActiveRecord) {
		t.Fatalf("Active() with symlink config = %v, want ErrInvalidActiveRecord", err)
	}
}

// TestActivateRejectsMismatchedStagedBundle proves Activate refuses to point
// the active record at a staged bundle whose identity disagrees with the
// caller's verified bundle, even when the hash file exists.
func TestActivateRejectsMismatchedStagedBundle(t *testing.T) {
	cache, hash := storeValidActive(t)
	mismatched := VerifiedBundle{
		BundleHash: hash,
		Bundle: conductor.PolicyBundle{
			BundleID:   "attacker-bundle",
			Version:    7,
			PolicyHash: strings.Repeat("b", 64),
		},
	}
	if err := cache.activate(mismatched); !errors.Is(err, ErrInvalidActiveRecord) {
		t.Fatalf("activate(mismatched) = %v, want ErrInvalidActiveRecord", err)
	}
}

func TestActivateRejectsNonHexHash(t *testing.T) {
	cache := openTestCache(t)
	if err := cache.activate(VerifiedBundle{BundleHash: "not-a-hash"}); !errors.Is(err, conductor.ErrInvalidHash) {
		t.Fatalf("activate(bad hash) = %v, want ErrInvalidHash", err)
	}
}

// TestRollbackAuthorizationMismatches drives every post-signature rejection
// branch in authorizeVersionTransition: a validly signed authorization is
// still refused when its window, audience, or bundle targeting does not match
// the local state.
func TestRollbackAuthorizationMismatches(t *testing.T) {
	policyKey := newTestKey(t)
	rk1 := newPurposeKey(t, "rollback-1", signing.PurposePolicyBundleRollback)
	rk2 := newPurposeKey(t, "rollback-2", signing.PurposePolicyBundleRollback)

	cases := []struct {
		name   string
		mutate func(auth *conductor.RollbackAuthorization)
		want   error
	}{
		{
			name:   "expired",
			mutate: func(a *conductor.RollbackAuthorization) { a.ExpiresAt = testNow.Add(-time.Hour) },
			want:   nil, // ValidateAtTime returns a window error; assert non-nil + not activated
		},
		{
			name: "wrong_audience",
			mutate: func(a *conductor.RollbackAuthorization) {
				a.Audience = conductor.Audience{InstanceIDs: []string{"other"}}
			},
			want: conductor.ErrAudienceMismatch,
		},
		{
			name: "wrong_current_target",
			mutate: func(a *conductor.RollbackAuthorization) {
				a.CurrentVersion = 9
				a.TargetVersion = 8
				a.CurrentBundleID = "ghost"
			},
			want: conductor.ErrInvalidRollback,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache := openTestCache(t)
			v1 := signedTestBundle(t, policyKey, "bundle-1", 1, "")
			if _, err := cache.storeVerified(v1, testVerifyOptions(policyKey, rk1, rk2)); err != nil {
				t.Fatalf("storeVerified(v1): %v", err)
			}
			v1Hash, err := v1.CanonicalHash()
			if err != nil {
				t.Fatalf("CanonicalHash(v1): %v", err)
			}
			v2 := signedTestBundle(t, policyKey, "bundle-2", 2, v1Hash)
			if _, err := cache.storeVerified(v2, testVerifyOptions(policyKey, rk1, rk2)); err != nil {
				t.Fatalf("storeVerified(v2): %v", err)
			}

			auth := mutatedRollbackAuth(t, rk1, rk2, v2, v1, tc.mutate)
			opts := testVerifyOptions(policyKey, rk1, rk2)
			opts.AllowRollback = true
			opts.Rollback = &auth

			_, err = cache.storeVerified(v1, opts)
			if err == nil {
				t.Fatalf("storeVerified(%s) = nil, want rejection", tc.name)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("storeVerified(%s) = %v, want %v", tc.name, err, tc.want)
			}
			// The active bundle must remain v2 — a rejected rollback never activates.
			active, activeErr := cache.Active()
			if activeErr != nil {
				t.Fatalf("Active(): %v", activeErr)
			}
			if active.Bundle.Version != 2 {
				t.Fatalf("active version = %d, want 2 (rejected rollback must not activate)", active.Bundle.Version)
			}
		})
	}
}

// mutatedRollbackAuth builds a rollback authorization for current->target,
// applies mutate, then signs so the signature is valid over the mutated
// content (exercising the post-signature authorization checks).
func mutatedRollbackAuth(t *testing.T, key1, key2 testKey, current, target conductor.PolicyBundle, mutate func(*conductor.RollbackAuthorization)) conductor.RollbackAuthorization {
	t.Helper()
	auth := conductor.RollbackAuthorization{
		SchemaVersion:   conductor.SchemaVersion,
		AuthorizationID: "rollback-1",
		OrgID:           "org-1",
		FleetID:         "fleet-1",
		Audience:        conductor.Audience{InstanceIDs: []string{"instance-1"}},
		CurrentBundleID: current.BundleID,
		CurrentVersion:  current.Version,
		TargetBundleID:  target.BundleID,
		TargetVersion:   target.Version,
		Counter:         1,
		Reason:          "operator rollback",
		CreatedAt:       testNow.Add(-time.Minute),
		ExpiresAt:       testNow.Add(time.Hour),
	}
	mutate(&auth)
	auth.Signatures = []conductor.SignatureProof{
		signProof(t, key1, auth.SignablePreimage),
		signProof(t, key2, auth.SignablePreimage),
	}
	return auth
}

// TestStoreVerifiedIdempotentReapply proves re-storing the exact active
// bundle (same id/version/canonical hash) is accepted as a no-op rather than
// being treated as a rollback. This is the steady-state path when a follower
// re-fetches the bundle it already runs.
func TestStoreVerifiedIdempotentReapply(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	bundle := signedTestBundle(t, key, "bundle-1", 1, "")
	if _, err := cache.storeVerified(bundle, testVerifyOptions(key)); err != nil {
		t.Fatalf("storeVerified(first): %v", err)
	}
	if _, err := cache.storeVerified(bundle, testVerifyOptions(key)); err != nil {
		t.Fatalf("storeVerified(idempotent re-apply): %v, want success", err)
	}
	active, err := cache.Active()
	if err != nil {
		t.Fatalf("Active(): %v", err)
	}
	if active.Bundle.Version != 1 {
		t.Fatalf("active version = %d, want 1", active.Bundle.Version)
	}
}

// TestActivateRejectsMissingConfig proves Activate fails closed when the
// staged config file disappeared between staging and activation, rather than
// pointing the active record at a non-existent config.
func TestActivateRejectsMissingConfig(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	bundle := signedTestBundle(t, key, "bundle-1", 1, "")
	verified, err := cache.stageVerified(bundle, testVerifyOptions(key))
	if err != nil {
		t.Fatalf("stageVerified(): %v", err)
	}
	if err := os.Remove(verified.ConfigPath); err != nil {
		t.Fatalf("remove staged config: %v", err)
	}
	if err := cache.activate(verified); err == nil {
		t.Fatal("activate() with missing config = nil, want failure")
	}
	if _, err := cache.Active(); !errors.Is(err, ErrNoValidBundle) {
		t.Fatalf("Active() after failed activate = %v, want ErrNoValidBundle", err)
	}
}

func TestValidateHashUnit(t *testing.T) {
	cases := []struct {
		name string
		hash string
		ok   bool
	}{
		{"valid_lower", strings.Repeat("a", 64), true},
		{"valid_upper", strings.Repeat("F", 64), true},
		{"valid_mixed", strings.Repeat("aF09", 16), true},
		{"too_short", strings.Repeat("a", 63), false},
		{"too_long", strings.Repeat("a", 65), false},
		{"non_hex", strings.Repeat("g", 64), false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHash(tc.hash)
			if tc.ok && err != nil {
				t.Fatalf("validateHash(%q) = %v, want nil", tc.name, err)
			}
			if !tc.ok && !errors.Is(err, conductor.ErrInvalidHash) {
				t.Fatalf("validateHash(%q) = %v, want ErrInvalidHash", tc.name, err)
			}
		})
	}
}

func TestValidateContainedPathUnit(t *testing.T) {
	root := t.TempDir()
	if err := validateContainedPath(root, filepath.Join(root, "configs", "x.yaml")); err != nil {
		t.Fatalf("contained path rejected: %v", err)
	}
	if err := validateContainedPath(root, filepath.Join(root, "..", "escape")); err == nil {
		t.Fatal("parent-escape path accepted")
	}
	if err := validateContainedPath(root, "/etc/passwd"); err == nil {
		t.Fatal("absolute escape path accepted")
	}
}

func TestValidateRegularFileUnit(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write regular: %v", err)
	}
	if err := validateRegularFile(regular, 1024); err != nil {
		t.Fatalf("regular file rejected: %v", err)
	}
	if err := validateRegularFile(regular, 2); !errors.Is(err, conductor.ErrPayloadTooLarge) {
		t.Fatalf("oversize file = %v, want ErrPayloadTooLarge", err)
	}
	if err := validateRegularFile(filepath.Join(dir, "missing"), 1024); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file = %v, want ErrNotExist", err)
	}
	if err := validateRegularFile(dir, 1024); !errors.Is(err, ErrInvalidActiveRecord) {
		t.Fatalf("directory = %v, want ErrInvalidActiveRecord", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := validateRegularFile(link, 1024); !errors.Is(err, ErrInvalidActiveRecord) {
		t.Fatalf("symlink = %v, want ErrInvalidActiveRecord", err)
	}
}

func TestNilCacheMethodsFailClosed(t *testing.T) {
	var cache *Cache
	if _, err := cache.stageVerified(conductor.PolicyBundle{}, verifyOptions{}); !errors.Is(err, ErrCacheRequired) {
		t.Fatalf("stageVerified(nil cache) = %v, want ErrCacheRequired", err)
	}
	if err := cache.activate(VerifiedBundle{}); !errors.Is(err, ErrCacheRequired) {
		t.Fatalf("activate(nil cache) = %v, want ErrCacheRequired", err)
	}
	if _, err := cache.Active(); !errors.Is(err, ErrCacheRequired) {
		t.Fatalf("Active(nil cache) = %v, want ErrCacheRequired", err)
	}
}

func TestNowUTCDefaults(t *testing.T) {
	cache := &Cache{now: func() time.Time { return testNow }}
	if got := cache.nowUTC(verifyOptions{}); !got.Equal(testNow) {
		t.Fatalf("nowUTC(cache clock) = %s, want %s", got, testNow)
	}
	if got := (&Cache{}).nowUTC(verifyOptions{}); got.IsZero() {
		t.Fatal("nowUTC(default clock) returned zero time")
	}
}

func TestOpenRejectsEmptyDir(t *testing.T) {
	if _, err := Open(Config{Dir: "  "}); !errors.Is(err, ErrCacheRequired) {
		t.Fatalf("Open(blank dir) = %v, want ErrCacheRequired", err)
	}
}

func TestOpenRejectsFileAndSymlinkAncestor(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "cache-file")
	if err := os.WriteFile(filePath, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("write file path: %v", err)
	}
	if _, err := Open(Config{Dir: filePath}); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("Open(file path) = %v, want not-directory error", err)
	}

	realParent := filepath.Join(dir, "real")
	if err := os.Mkdir(realParent, 0o750); err != nil {
		t.Fatalf("mkdir real parent: %v", err)
	}
	linkParent := filepath.Join(dir, "link")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatalf("symlink parent: %v", err)
	}
	if _, err := Open(Config{Dir: filepath.Join(linkParent, "cache")}); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("Open(symlink ancestor) = %v, want symlink rejection", err)
	}
}

func TestDurableHelpersRejectBadPathsAndSweepTemps(t *testing.T) {
	dir := t.TempDir()
	if err := durableWrite(filepath.Join(dir, "missing", "record.json"), []byte("{}")); err == nil {
		t.Fatal("durableWrite(missing parent) = nil, want error")
	}
	if err := fsyncDir(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("fsyncDir(missing) = nil, want error")
	}
	if err := sweepStaleTemps(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("sweepStaleTemps(missing) = nil, want error")
	}

	tmpFile := filepath.Join(dir, ".tmp-stale")
	keepFile := filepath.Join(dir, "keep")
	tmpDir := filepath.Join(dir, ".tmp-dir")
	if err := os.WriteFile(tmpFile, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale temp: %v", err)
	}
	if err := os.WriteFile(keepFile, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write keep file: %v", err)
	}
	if err := os.Mkdir(tmpDir, 0o750); err != nil {
		t.Fatalf("mkdir temp dir: %v", err)
	}
	if err := sweepStaleTemps(dir); err != nil {
		t.Fatalf("sweepStaleTemps(): %v", err)
	}
	if _, err := os.Stat(tmpFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale temp stat = %v, want removed", err)
	}
	if _, err := os.Stat(keepFile); err != nil {
		t.Fatalf("keep file stat = %v, want present", err)
	}
	if _, err := os.Stat(tmpDir); err != nil {
		t.Fatalf("temp dir stat = %v, want present", err)
	}
}

func TestStageVerifiedFailsClosedWhenCacheDirsMissing(t *testing.T) {
	key := newTestKey(t)
	bundle := signedTestBundle(t, key, "bundle-1", 1, "")
	opts := testVerifyOptions(key)
	root := t.TempDir()

	missingBundles := &Cache{
		dir:        root,
		bundlesDir: filepath.Join(root, "missing-bundles"),
		configsDir: t.TempDir(),
		now:        func() time.Time { return testNow },
	}
	if _, err := missingBundles.stageVerified(bundle, opts); err == nil {
		t.Fatal("stageVerified(missing bundles dir) = nil, want error")
	}

	bundlesDir := filepath.Join(root, "bundles")
	if err := os.Mkdir(bundlesDir, 0o750); err != nil {
		t.Fatalf("mkdir bundles dir: %v", err)
	}
	missingConfigs := &Cache{
		dir:        root,
		bundlesDir: bundlesDir,
		configsDir: filepath.Join(root, "missing-configs"),
		now:        func() time.Time { return testNow },
	}
	if _, err := missingConfigs.stageVerified(bundle, opts); err == nil {
		t.Fatal("stageVerified(missing configs dir) = nil, want error")
	}
}

func TestUnsupportedMinVersionRejected(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	bundle := signedTestBundle(t, key, "bundle-1", 1, "")
	// Re-sign with a min version the local build cannot satisfy.
	bundle.MinPipelockVersion = "999.0.0"
	bundle.Signatures = []conductor.SignatureProof{signProof(t, key, bundle.SignablePreimage)}
	opts := testVerifyOptions(key)
	opts.LocalVersion = "1.2.3"
	if _, err := cache.storeVerified(bundle, opts); !errors.Is(err, ErrUnsupportedMinVersion) {
		t.Fatalf("storeVerified(min version) = %v, want ErrUnsupportedMinVersion", err)
	}
}
