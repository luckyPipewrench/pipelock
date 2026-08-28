// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	domrules "github.com/luckyPipewrench/pipelock/internal/rules"
)

func TestRulesInstallRemoteRejectsPersistedRollbacks(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	fingerprint := hex.EncodeToString(pub)
	setRulesKeyringHexForTest(t, fingerprint)

	current := []byte(v2InstallBundleYAML("2026.08.0", 10, fingerprint))
	currentSignature := signInstallBundle(current, priv)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			_, _ = w.Write(currentSignature)
			return
		}
		_, _ = w.Write(current)
	}))
	defer server.Close()
	originalClient := httpsOnlyClient
	httpsOnlyClient = server.Client()
	httpsOnlyClient.CheckRedirect = originalClient.CheckRedirect
	t.Cleanup(func() { httpsOnlyClient = originalClient })

	tests := []struct {
		name      string
		candidate func() []byte
		update    bool
		want      string
	}{
		{
			name: "older monotonic version",
			candidate: func() []byte {
				return []byte(v2InstallBundleYAML("2026.07.0", 4, fingerprint))
			},
			want: "version rollback",
		},
		{
			name: "forced update cannot lower monotonic floor",
			candidate: func() []byte {
				return []byte(v2InstallBundleYAML("2026.07.0", 4, fingerprint))
			},
			update: true,
			want:   "version rollback",
		},
		{
			name: "older bundle format",
			candidate: func() []byte {
				return []byte(v1InstallBundleYAML("2026.07.0"))
			},
			want: "format rollback",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			current = []byte(v2InstallBundleYAML("2026.08.0", 10, fingerprint))
			currentSignature = signInstallBundle(current, priv)
			_ = installRemoteForFreshnessTest(t, rulesDir, server.URL+testBundlePath, "")
			installed := append([]byte(nil), current...)

			current = tc.candidate()
			currentSignature = signInstallBundle(current, priv)
			var err error
			if tc.update {
				err = updateRemoteForFreshnessTest(t, rulesDir)
			} else {
				err = installRemoteForFreshnessTest(t, rulesDir, server.URL+testBundlePath, tc.want)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("install error = %v, want %q", err, tc.want)
			}
			assertInstalledBundleBytes(t, rulesDir, testBundleName, installed)
			state, loadErr := domrules.LoadFreshnessState(rulesDir)
			if loadErr != nil {
				t.Fatalf("load freshness state: %v", loadErr)
			}
			if got := state.HighestSeen["community:"+testBundleName]; got != 10 {
				t.Fatalf("highest seen = %d, want 10", got)
			}
			if got := state.FormatFloor[testBundleName]; got != 2 {
				t.Fatalf("format floor = %d, want 2", got)
			}
		})
	}
}

func updateRemoteForFreshnessTest(t *testing.T, rulesDir string) error {
	t.Helper()
	cmd := testRootCmd()
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"rules", "update", testBundleName, "--force", "--rules-dir", rulesDir})
	return cmd.Execute()
}

func TestStageRemoteBundleWithFreshnessRejectsVersionRollbackBeforeStaging(t *testing.T) {
	rulesDir := t.TempDir()
	name := "community-rules"
	original := []byte("newer installed bytes")
	writeInstalledBundleForFreshnessTest(t, rulesDir, name, original)
	if err := domrules.SaveFreshnessState(rulesDir, &domrules.FreshnessState{
		HighestSeen: map[string]uint64{"community:" + name: 10},
		FormatFloor: map[string]int{name: 2},
	}); err != nil {
		t.Fatalf("save freshness state: %v", err)
	}

	bundle, lock := remoteFreshnessCandidate(name, 2, 4)
	err := stageRemoteBundleWithFreshness(rulesDir, bundle, []byte("older candidate bytes"), []byte("signature"), lock, false)
	if err == nil || !strings.Contains(err.Error(), "version rollback") {
		t.Fatalf("stageRemoteBundleWithFreshness error = %v, want version rollback", err)
	}
	assertInstalledBundleBytes(t, rulesDir, name, original)
	state, err := domrules.LoadFreshnessState(rulesDir)
	if err != nil {
		t.Fatalf("load freshness state: %v", err)
	}
	if got := state.HighestSeen["community:"+name]; got != 10 {
		t.Fatalf("highest seen = %d, want 10", got)
	}
}

func TestStageRemoteBundleWithFreshnessRejectsFormatRollbackBeforeStaging(t *testing.T) {
	rulesDir := t.TempDir()
	name := "community-rules"
	original := []byte("v2 installed bytes")
	writeInstalledBundleForFreshnessTest(t, rulesDir, name, original)
	if err := domrules.SaveFreshnessState(rulesDir, &domrules.FreshnessState{
		HighestSeen: map[string]uint64{"community:" + name: 10},
		FormatFloor: map[string]int{name: 2},
	}); err != nil {
		t.Fatalf("save freshness state: %v", err)
	}

	bundle, lock := remoteFreshnessCandidate(name, 1, 0)
	err := stageRemoteBundleWithFreshness(rulesDir, bundle, []byte("v1 candidate bytes"), []byte("signature"), lock, false)
	if err == nil || !strings.Contains(err.Error(), "format rollback") {
		t.Fatalf("stageRemoteBundleWithFreshness error = %v, want format rollback", err)
	}
	assertInstalledBundleBytes(t, rulesDir, name, original)
}

func TestStageRemoteBundleWithFreshnessFirstInstallIsTrustOnFirstUse(t *testing.T) {
	rulesDir := t.TempDir()
	name := "community-rules"
	bundle, lock := remoteFreshnessCandidate(name, 2, 4)
	data := []byte("first accepted candidate")

	if err := stageRemoteBundleWithFreshness(rulesDir, bundle, data, []byte("signature"), lock, true); err != nil {
		t.Fatalf("stageRemoteBundleWithFreshness: %v", err)
	}
	assertInstalledBundleBytes(t, rulesDir, name, data)
	state, err := domrules.LoadFreshnessState(rulesDir)
	if err != nil {
		t.Fatalf("load freshness state: %v", err)
	}
	if got := state.HighestSeen["community:"+name]; got != 4 {
		t.Fatalf("highest seen = %d, want 4", got)
	}
	if got := state.FormatFloor[name]; got != 2 {
		t.Fatalf("format floor = %d, want 2", got)
	}
}

func TestStageRemoteBundleWithFreshnessRejectsExistingInstallAndV2Metadata(t *testing.T) {
	t.Run("existing install", func(t *testing.T) {
		rulesDir := t.TempDir()
		bundle, lock := remoteFreshnessCandidate("community-rules", 1, 0)
		bundle.Version = lock.InstalledVersion
		data := []byte("same candidate")
		if err := stageRemoteBundleWithFreshness(rulesDir, bundle, data, nil, lock, true); err != nil {
			t.Fatalf("first stage: %v", err)
		}
		err := stageRemoteBundleWithFreshness(rulesDir, bundle, data, nil, lock, true)
		if err == nil || !strings.Contains(err.Error(), "already installed") {
			t.Fatalf("second stage error = %v, want already installed", err)
		}
	})

	tests := []struct {
		name   string
		mutate func(*domrules.Bundle)
		want   string
	}{
		{
			name: "key binding",
			mutate: func(bundle *domrules.Bundle) {
				bundle.KeyID = "different-signer"
			},
			want: "key_id",
		},
		{
			name: "required feature",
			mutate: func(bundle *domrules.Bundle) {
				bundle.RequiredFeatures = []string{"unknown_feature"}
			},
			want: "requires unknown feature",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle, lock := remoteFreshnessCandidate("community-rules", 2, 1)
			tc.mutate(bundle)
			err := stageRemoteBundleWithFreshness(t.TempDir(), bundle, []byte("candidate"), []byte("signature"), lock, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("stage error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestStageBundleFreshnessRejectsCorruptPersistedState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage func(string, *domrules.Bundle, *domrules.LockFile) error
	}{
		{
			name: "local",
			stage: func(rulesDir string, bundle *domrules.Bundle, lock *domrules.LockFile) error {
				return stageLocalBundleWithFormatFloor(rulesDir, bundle, []byte("candidate"), lock)
			},
		},
		{
			name: "remote",
			stage: func(rulesDir string, bundle *domrules.Bundle, lock *domrules.LockFile) error {
				return stageRemoteBundleWithFreshness(rulesDir, bundle, []byte("candidate"), nil, lock, false)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rulesDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(rulesDir, ".freshness.json"), []byte("not json"), 0o600); err != nil {
				t.Fatalf("write corrupt state: %v", err)
			}
			bundle, lock := remoteFreshnessCandidate("community-rules", 1, 0)
			err := tc.stage(rulesDir, bundle, lock)
			if err == nil || !strings.Contains(err.Error(), "loading rules freshness state") {
				t.Fatalf("stage error = %v, want freshness load failure", err)
			}
		})
	}
}

func TestStageLocalBundleWithFormatFloorRejectsV1AfterV2(t *testing.T) {
	rulesDir := t.TempDir()
	name := "third-party-rules"
	original := []byte("v2 installed bytes")
	writeInstalledBundleForFreshnessTest(t, rulesDir, name, original)
	if err := domrules.SaveFreshnessState(rulesDir, &domrules.FreshnessState{
		HighestSeen: map[string]uint64{"community:" + name: 8},
		FormatFloor: map[string]int{name: 2},
	}); err != nil {
		t.Fatalf("save freshness state: %v", err)
	}

	bundle, lock := remoteFreshnessCandidate(name, 1, 0)
	lock.Unsigned = true
	err := stageLocalBundleWithFormatFloor(rulesDir, bundle, []byte("v1 local candidate"), lock)
	if err == nil || !strings.Contains(err.Error(), "format rollback") {
		t.Fatalf("stageLocalBundleWithFormatFloor error = %v, want format rollback", err)
	}
	assertInstalledBundleBytes(t, rulesDir, name, original)
}

func TestInstallLocalRejectsUnsignedV2WithoutRecordingFloor(t *testing.T) {
	rulesDir := t.TempDir()
	sourceDir := t.TempDir()
	bundle := []byte(v2InstallBundleYAML("2026.08.0", 1, "unsigned-test-key"))
	if err := os.WriteFile(filepath.Join(sourceDir, "bundle.yaml"), bundle, 0o600); err != nil {
		t.Fatalf("write local bundle: %v", err)
	}

	err := installLocal(&strings.Builder{}, rulesDir, sourceDir, true, true)
	if err == nil || !strings.Contains(err.Error(), "must be signed and installed from HTTPS") {
		t.Fatalf("installLocal error = %v, want signed HTTPS requirement", err)
	}
	if _, statErr := os.Stat(filepath.Join(rulesDir, ".freshness.json")); !os.IsNotExist(statErr) {
		t.Fatalf("freshness state exists after rejected unsigned v2 install: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(rulesDir, testBundleName)); !os.IsNotExist(statErr) {
		t.Fatalf("bundle directory exists after rejected unsigned v2 install: %v", statErr)
	}
}

func remoteFreshnessCandidate(name string, format int, monotonic uint64) (*domrules.Bundle, *domrules.LockFile) {
	const signer = "test-signer"
	return &domrules.Bundle{
			FormatVersion:    format,
			Name:             name,
			Tier:             domrules.TierCommunity,
			MonotonicVersion: monotonic,
			PublishedAt:      "2026-08-27T00:00:00Z",
			ExpiresAt:        "2030-01-01T00:00:00Z",
			KeyID:            signer,
		}, &domrules.LockFile{
			InstalledVersion:  "2026.08.0",
			InstalledAt:       "2026-08-27T00:00:00Z",
			Source:            "https://rules.example/bundle.yaml",
			LastCheck:         "2026-08-27T00:00:00Z",
			BundleSHA256:      "candidate-digest",
			SignerFingerprint: signer,
		}
}

func writeInstalledBundleForFreshnessTest(t *testing.T, rulesDir, name string, data []byte) {
	t.Helper()
	dir := filepath.Join(rulesDir, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create installed bundle dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.yaml"), data, 0o600); err != nil {
		t.Fatalf("write installed bundle: %v", err)
	}
}

func assertInstalledBundleBytes(t *testing.T, rulesDir, name string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Clean(filepath.Join(rulesDir, name, "bundle.yaml"))) // #nosec G304 -- test path is below t.TempDir
	if err != nil {
		t.Fatalf("read installed bundle: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("installed bundle = %q, want %q", got, want)
	}
}

func installRemoteForFreshnessTest(t *testing.T, rulesDir, source, wantErr string) error {
	t.Helper()
	cmd := testRootCmd()
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"rules", "install", "--source", source, "--rules-dir", rulesDir})
	err := cmd.Execute()
	if wantErr == "" && err != nil {
		t.Fatalf("install remote bundle: %v", err)
	}
	return err
}

func signInstallBundle(data []byte, privateKey ed25519.PrivateKey) []byte {
	encoded := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, data))
	return []byte(encoded + "\n")
}

func v2InstallBundleYAML(version string, monotonic uint64, fingerprint string) string {
	return fmt.Sprintf(`format_version: 2
name: test-bundle
version: %q
author: test
description: Test bundle
min_pipelock: "1.0.0"
tier: community
monotonic_version: %d
published_at: "2026-08-27T00:00:00Z"
expires_at: "2030-01-01T00:00:00Z"
key_id: %q
rules: []
`, version, monotonic, fingerprint)
}

func v1InstallBundleYAML(version string) string {
	return fmt.Sprintf(`format_version: 1
name: test-bundle
version: %q
author: test
description: Test bundle
min_pipelock: "1.0.0"
rules: []
`, version)
}
