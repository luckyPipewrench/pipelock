// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/commitmentkey"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestNewServerLoadsConfiguredCommitmentKeyring(t *testing.T) {
	dir := t.TempDir()
	keyringPath := filepath.Join(dir, "commitment-keyring.json")
	want, err := commitmentkey.Initialize(keyringPath, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	cfgPath := writeCommitmentRuntimeConfig(t, dir)
	server, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer server.cleanup()
	if server.commitmentKeyring == nil || server.commitmentKeyring.ActiveID != want.ActiveID {
		t.Fatalf("runtime keyring = %+v, want active %q", server.commitmentKeyring, want.ActiveID)
	}
}

func TestNewServerFailsClosedOnConfiguredCommitmentKeyringErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACLs do not use Unix permission bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "commitment-keyring.json")
	if _, err := commitmentkey.Initialize(path, time.Now()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	unsafeMode := os.FileMode(0o600)
	unsafeMode |= 0o044
	if err := os.Chmod(path, unsafeMode); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	cfgPath := writeCommitmentRuntimeConfig(t, dir)
	if _, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}}); err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
		t.Fatalf("NewServer error = %v, want unsafe-permission refusal", err)
	}
}

func TestNewServerFailsClosedOnCommitmentKeyringCorruption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "commitment-keyring.json")
	if _, err := commitmentkey.Initialize(path, time.Now()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	corruptCommitmentKeyringMaterial(t, path)
	cfgPath := writeCommitmentRuntimeConfig(t, dir)
	if _, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}}); err == nil || !strings.Contains(err.Error(), "content check") {
		t.Fatalf("NewServer corruption error = %v, want content-check refusal", err)
	}
}

func TestReloadPreservesStartupCommitmentKeyring(t *testing.T) {
	for _, test := range []struct {
		name        string
		mutate      func(*config.Config, string)
		wantWarning bool
	}{
		{
			name: "replacement path",
			mutate: func(cfg *config.Config, dir string) {
				cfg.EvidenceProvenance.CommitmentKeyringPath = filepath.Join(dir, "replacement.json")
			},
			wantWarning: true,
		},
		{
			name: "cleared path",
			mutate: func(cfg *config.Config, _ string) {
				cfg.EvidenceProvenance.CommitmentKeyringPath = ""
			},
			wantWarning: true,
		},
		{
			name: "unrelated reload",
			mutate: func(cfg *config.Config, _ string) {
				explain := true
				cfg.ExplainBlocks = &explain
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "commitment-keyring.json")
			want, err := commitmentkey.Initialize(path, time.Now())
			if err != nil {
				t.Fatalf("Initialize: %v", err)
			}
			stderr := &syncBuffer{}
			server, err := NewServer(ServerOpts{ConfigFile: writeCommitmentRuntimeConfig(t, dir), Stdout: &syncBuffer{}, Stderr: stderr})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			defer server.cleanup()
			updated := server.proxy.CurrentConfig().Clone()
			test.mutate(updated, dir)
			if err := server.Reload(updated); err != nil {
				t.Fatalf("Reload: %v", err)
			}
			if got := server.proxy.CurrentConfig().EvidenceProvenance.CommitmentKeyringPath; got != path {
				t.Fatalf("reload published path %q, want startup path %q", got, path)
			}
			if server.commitmentKeyring == nil || server.commitmentKeyring.ActiveID != want.ActiveID {
				t.Fatalf("reload keyring = %+v, want startup active %q", server.commitmentKeyring, want.ActiveID)
			}
			if test.wantWarning && !stderr.contains("keyring is loaded at startup") {
				t.Fatalf("stderr missing restart-only warning: %s", stderr.String())
			}
		})
	}
}

func writeCommitmentRuntimeConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "pipelock.yaml")
	body := "mode: balanced\nevidence_provenance:\n  commitment_keyring_path: commitment-keyring.json\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func corruptCommitmentKeyringMaterial(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var keyring map[string]any
	if err := json.Unmarshal(raw, &keyring); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	keys, ok := keyring["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatalf("keys = %#v, want first key", keyring["keys"])
	}
	entry, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatalf("keys[0] = %#v, want key entry", keys[0])
	}
	material, ok := entry["key"].(string)
	if !ok || material == "" {
		t.Fatalf("keys[0].key = %#v, want encoded key material", entry["key"])
	}
	if material[0] == 'A' {
		entry["key"] = "B" + material[1:]
	} else {
		entry["key"] = "A" + material[1:]
	}
	data, err := json.MarshalIndent(keyring, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
