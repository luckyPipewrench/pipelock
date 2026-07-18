// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestRecordVersionInitializesStateAndNeverLowersFloor(t *testing.T) {
	state := &FreshnessState{}
	RecordVersion(state, TierCommunity, "bundle", 9)
	RecordVersion(state, TierCommunity, "bundle", 4)
	if got := state.HighestSeen["community:bundle"]; got != 9 {
		t.Fatalf("rollback floor = %d, want 9", got)
	}
}

func TestFreshnessStateRejectsUnsafeAndMalformedFiles(t *testing.T) {
	tests := []struct {
		name string
		path func(string) string
		body string
		mode os.FileMode
		want string
	}{
		{
			name: "primary has unsafe permissions",
			path: func(dir string) string { return filepath.Join(dir, freshnessFilename) },
			body: `{"highest_seen":{}}`,
			mode: 0o644,
			want: "load freshness state",
		},
		{
			name: "secondary has unsafe permissions",
			path: freshnessSecondaryPath,
			body: `{"highest_seen":{}}`,
			mode: 0o644,
			want: "load freshness secondary state",
		},
		{
			name: "context has duplicate key",
			path: freshnessContextPath,
			body: `{"context":"one","context":"two"}`,
			mode: 0o600,
			want: "parse freshness context",
		},
		{
			name: "context has wrong type",
			path: freshnessContextPath,
			body: `{"context":1}`,
			mode: 0o600,
			want: "parse freshness context",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := tc.path(dir)
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.body), tc.mode); err != nil {
				t.Fatal(err)
			}
			if tc.mode == 0o644 {
				if err := os.Chmod(path, 0o666); err != nil { // #nosec G302 -- deliberately unsafe fixture.
					t.Fatal(err)
				}
			}
			_, err := LoadFreshnessState(dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadFreshnessState() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestReadFreshnessContextRejectsFilesystemObject(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(freshnessContextPath(dir), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := readFreshnessContext(dir); err == nil || !strings.Contains(err.Error(), "read freshness context") {
		t.Fatalf("readFreshnessContext() error = %v, want read failure", err)
	}
}

func TestSaveFreshnessStateReportsEachDurabilityFailure(t *testing.T) {
	state := &FreshnessState{HighestSeen: map[string]uint64{"community:bundle": 8}}

	t.Run("primary directory creation", func(t *testing.T) {
		rulesPath := filepath.Join(t.TempDir(), "rules")
		if err := os.WriteFile(rulesPath, []byte("occupied"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := SaveFreshnessState(rulesPath, state); err == nil {
			t.Fatal("SaveFreshnessState() accepted non-directory rules path")
		}
	})

	t.Run("secondary directory creation", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".pipelock-state"), []byte("occupied"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := SaveFreshnessState(dir, state)
		if err == nil || !strings.Contains(err.Error(), "create freshness state dir") {
			t.Fatalf("SaveFreshnessState() error = %v, want secondary directory failure", err)
		}
	})

	t.Run("context destination is directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(freshnessContextPath(dir), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := SaveFreshnessState(dir, state); err == nil {
			t.Fatal("SaveFreshnessState() accepted directory as context file")
		}
	})
}

func TestWriteFreshnessStateRejectsOversizedSnapshot(t *testing.T) {
	state := &FreshnessState{HighestSeen: make(map[string]uint64)}
	for i := 0; i < 45000; i++ {
		state.HighestSeen[fmt.Sprintf("community:bundle-%08d", i)] = uint64(i + 1)
	}
	err := writeFreshnessStateFile(filepath.Join(t.TempDir(), freshnessFilename), t.TempDir(), state)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("writeFreshnessStateFile() error = %v, want size rejection", err)
	}
}

func TestInstalledFreshnessContextFailsClosedOnFilesystemAndBundleTrustErrors(t *testing.T) {
	t.Run("rules path is file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rules")
		if err := os.WriteFile(path, []byte("occupied"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := installedFreshnessContextPresent(path); err == nil || !strings.Contains(err.Error(), "read rules directory") {
			t.Fatalf("installedFreshnessContextPresent() error = %v", err)
		}
	})

	t.Run("bundle path is directory", func(t *testing.T) {
		dir := t.TempDir()
		bundleDir := filepath.Join(dir, "bundle")
		if err := os.MkdirAll(filepath.Join(bundleDir, bundleFilename), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundleDir, lockFilename), []byte("lock"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := installedFreshnessContextPresent(dir); err == nil || !strings.Contains(err.Error(), "read bundle") {
			t.Fatalf("installedFreshnessContextPresent() error = %v", err)
		}
	})

	t.Run("bundle is malformed", func(t *testing.T) {
		dir := t.TempDir()
		bundleDir := filepath.Join(dir, "bundle")
		if err := os.MkdirAll(bundleDir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundleDir, lockFilename), []byte("lock"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundleDir, bundleFilename), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := installedFreshnessContextPresent(dir); err == nil || !strings.Contains(err.Error(), "parse bundle") {
			t.Fatalf("installedFreshnessContextPresent() error = %v", err)
		}
	})
}

func TestResetFreshnessStateFailsClosedOnMalformedInstalledBundle(t *testing.T) {
	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, lockFilename), []byte("lock"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, bundleFilename), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ResetFreshnessStateFromInstalledBundles(dir); err == nil || !strings.Contains(err.Error(), "parse bundle") {
		t.Fatalf("ResetFreshnessStateFromInstalledBundles() error = %v", err)
	}
}

func TestWithFreshnessLockPropagatesOpenAndCallbackFailures(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing", "rules")
	if err := WithFreshnessLock(missing, func() error { return nil }); err == nil || !strings.Contains(err.Error(), "freshness lock") {
		t.Fatalf("WithFreshnessLock() open error = %v", err)
	}

	sentinel := fmt.Errorf("callback refused")
	if err := WithFreshnessLock(t.TempDir(), func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("WithFreshnessLock() callback error = %v, want sentinel", err)
	}
}

func TestLoadBundlesRejectsRollbackAndAllowsExplicitStaleMode(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	setupKeyring(t, pub)

	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "community-pack")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}

	bundle := testBundleV2("community-pack", TierCommunity, 10, []Rule{
		testDLPRule("secret", confidenceHigh, StatusStable),
	})
	bundle.KeyID = KeyFingerprint(pub)
	writeSignedBundle(t, bundleDir, bundle, pub, priv)
	first := LoadBundles(dir, LoadOptions{MinConfidence: confidenceLow, PipelockVersion: testPipelockVersion})
	if len(first.Errors) != 0 || len(first.Loaded) != 1 {
		t.Fatalf("initial load = errors %v, loaded %v", first.Errors, first.Loaded)
	}

	rollback := testBundleV2("community-pack", TierCommunity, 4, bundle.Rules)
	rollback.KeyID = KeyFingerprint(pub)
	writeSignedBundle(t, bundleDir, rollback, pub, priv)
	rejected := LoadBundles(dir, LoadOptions{MinConfidence: confidenceLow, PipelockVersion: testPipelockVersion})
	if len(rejected.Errors) != 1 || !strings.Contains(rejected.Errors[0].Reason, "rollback") {
		t.Fatalf("rollback load errors = %v, want rollback rejection", rejected.Errors)
	}
	if len(rejected.Loaded) != 0 {
		t.Fatalf("rollback loaded bundles = %v, want none", rejected.Loaded)
	}

	stale := testBundleV2("community-pack", TierCommunity, 11, bundle.Rules)
	stale.KeyID = KeyFingerprint(pub)
	stale.ExpiresAt = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	writeSignedBundle(t, bundleDir, stale, pub, priv)
	allowed := LoadBundles(dir, LoadOptions{
		MinConfidence:   confidenceLow,
		PipelockVersion: testPipelockVersion,
		AllowStale:      true,
	})
	if len(allowed.Errors) != 0 || len(allowed.Loaded) != 1 || len(allowed.Warnings) == 0 {
		t.Fatalf("stale load = errors %v, loaded %v, warnings %v", allowed.Errors, allowed.Loaded, allowed.Warnings)
	}
}

func TestMergeIntoConfigPreservesPolicyWhenFreshnessStateIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, freshnessFilename), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Rules.RulesDir = dir
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:   "previously accepted",
		Regex:  "accepted-[0-9]+",
		Bundle: "community-pack",
	})
	beforeDLP := append([]config.DLPPattern(nil), cfg.DLP.Patterns...)
	beforeResponse := append([]config.ResponseScanPattern(nil), cfg.ResponseScanning.Patterns...)

	result := MergeIntoConfig(cfg, testPipelockVersion)
	if len(result.Errors) != 1 || !result.Degraded {
		t.Fatalf("MergeIntoConfig() result = %+v, want degraded state error", result)
	}
	if !reflect.DeepEqual(cfg.DLP.Patterns, beforeDLP) || !reflect.DeepEqual(cfg.ResponseScanning.Patterns, beforeResponse) {
		t.Fatal("load failure changed previously accepted policy")
	}
}

func TestRestoreCompiledStandardPatternsPreservesOverridesAndOrder(t *testing.T) {
	type pattern struct {
		name     string
		compiled bool
	}
	defaults := []pattern{
		{name: "core", compiled: true},
		{name: "standard", compiled: true},
		{name: "other", compiled: true},
	}
	current := []pattern{
		{name: "standard"},
		{name: "custom"},
		{name: "other", compiled: true},
	}
	got := restoreCompiledStandardPatterns(
		current,
		defaults,
		func(p pattern) string { return p.name },
		func(p pattern) bool { return p.compiled },
		map[string]bool{"standard": true},
	)
	want := []pattern{
		{name: "other", compiled: true},
		{name: "standard"},
		{name: "custom"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("restored patterns = %#v, want %#v", got, want)
	}
}

func TestBuildTierKeyMappingKeepsFirstBinding(t *testing.T) {
	mapping := buildTierKeyMapping([]config.TrustedKey{
		{Tier: TierCommunity, PublicKey: "first"},
		{Tier: "", PublicKey: "ignored"},
		{Tier: TierCommunity, PublicKey: "second"},
	})
	if len(mapping) != 1 || mapping[TierCommunity] != "first" {
		t.Fatalf("tier mapping = %#v, want first binding only", mapping)
	}
}

func TestBundleMetadataValidationFailsClosed(t *testing.T) {
	if err := CheckRequiredFeatures([]string{"Invalid-Feature"}); err == nil || !strings.Contains(err.Error(), "invalid feature name") {
		t.Fatalf("CheckRequiredFeatures() error = %v", err)
	}
	if _, err := ParseBundle([]byte(strings.Repeat("x", MaxBundleFileSize+1))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("ParseBundle() error = %v, want size rejection", err)
	}

	tests := []struct {
		name   string
		mutate func(*Bundle)
		want   string
	}{
		{
			name: "missing published time",
			mutate: func(b *Bundle) {
				b.PublishedAt = ""
			},
			want: "published_at must not be empty",
		},
		{
			name: "missing expiration",
			mutate: func(b *Bundle) {
				b.ExpiresAt = ""
			},
			want: "expires_at must not be empty",
		},
		{
			name: "invalid expiration",
			mutate: func(b *Bundle) {
				b.ExpiresAt = "tomorrow"
			},
			want: "expires_at",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle := testBundleV2("metadata-pack", TierCommunity, 1, nil)
			tc.mutate(bundle)
			if err := bundle.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVersionHelpersRejectMalformedIdentifiers(t *testing.T) {
	if isHexString("abc!") {
		t.Fatal("isHexString() accepted non-hex character")
	}
	tests := []struct {
		a    string
		b    string
		want int
	}{
		{a: "1.2", b: "1.10", want: -1},
		{a: "2", b: "1", want: 1},
		{a: "1", b: "alpha", want: -1},
		{a: "alpha", b: "1", want: 1},
		{a: "beta", b: "alpha", want: 1},
	}
	for _, tc := range tests {
		if got := comparePrerelease(tc.a, tc.b); got != tc.want {
			t.Fatalf("comparePrerelease(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestTrustReadersReportMissingAndMalformedArtifacts(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "missing")
	if _, err := VerifyBundleSignature(missingDir, nil); err == nil || !strings.Contains(err.Error(), "reading bundle") {
		t.Fatalf("VerifyBundleSignature() error = %v", err)
	}
	if err := VerifyIntegrity(missingDir, true, "", "", nil); err == nil || !strings.Contains(err.Error(), "reading bundle") {
		t.Fatalf("VerifyIntegrity(unsigned) error = %v", err)
	}
	if err := VerifyIntegrity(missingDir, false, "", "", nil); err == nil || !strings.Contains(err.Error(), "reading bundle") {
		t.Fatalf("VerifyIntegrity(signed) error = %v", err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, bundleFilename), []byte("bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyIntegrityBytes([]byte("bundle"), dir, false, "", "", nil); err == nil || !strings.Contains(err.Error(), "loading signature") {
		t.Fatalf("VerifyIntegrityBytes() error = %v", err)
	}

	lockPath := filepath.Join(dir, lockFilename)
	if err := os.WriteFile(lockPath, []byte("installed_version: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLockFile(lockPath); err == nil || !strings.Contains(err.Error(), "parse lock file") {
		t.Fatalf("ReadLockFile() error = %v", err)
	}
}
