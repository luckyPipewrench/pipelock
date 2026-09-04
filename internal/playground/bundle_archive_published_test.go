// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

func TestArchiveRunForPublishedReplay_SealsAndVerifiesDelegatedRun(t *testing.T) {
	runDir, _, root := buildDelegatedRunDir(t)

	bundle, err := playground.ArchiveRunForPublishedReplay(runDir, root)
	if err != nil {
		t.Fatalf("ArchiveRunForPublishedReplay: %v", err)
	}
	artifacts, err := playground.ExtractRunArtifactsFromBundle(bundle)
	if err != nil {
		t.Fatalf("ExtractRunArtifactsFromBundle: %v", err)
	}
	if len(artifacts.ReplayArchiveAuthorization) == 0 {
		t.Fatal("published replay omitted its root authorization")
	}
	report, err := playground.VerifyArchivedReplayArtifacts(artifacts, fmt.Sprintf("%x", root.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatalf("VerifyArchivedReplayArtifacts: %v", err)
	}
	if !report.OK {
		t.Fatalf("published replay did not verify: %s", report.FailureSummary())
	}
}

func TestArchiveRunForPublishedReplay_RefusesUnreadableOrInvalidInputs(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, runDir string)
		want   string
	}{
		{
			name: "missing manifest",
			mutate: func(t *testing.T, runDir string) {
				t.Helper()
				if err := os.Remove(filepath.Join(runDir, "launch-manifest.json")); err != nil {
					t.Fatal(err)
				}
			},
			want: "read artifact launch-manifest.json",
		},
		{
			name: "malformed manifest",
			mutate: func(t *testing.T, runDir string) {
				t.Helper()
				path := filepath.Join(runDir, "launch-manifest.json")
				if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "launch-manifest.json",
		},
		{
			name: "unreadable delegation",
			mutate: func(t *testing.T, runDir string) {
				t.Helper()
				path := filepath.Join(runDir, "orchestrator-delegation.json")
				makeUnreadable(t, path)
			},
			want: "read artifact orchestrator-delegation.json",
		},
		{
			name: "malformed delegation",
			mutate: func(t *testing.T, runDir string) {
				t.Helper()
				path := filepath.Join(runDir, "orchestrator-delegation.json")
				if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "orchestrator-delegation.json",
		},
		{
			name: "missing required archive artifact",
			mutate: func(t *testing.T, runDir string) {
				t.Helper()
				if err := os.Remove(filepath.Join(runDir, "witness.json")); err != nil {
					t.Fatal(err)
				}
			},
			want: "read artifact witness.json",
		},
		{
			name: "invalid sealed witness",
			mutate: func(t *testing.T, runDir string) {
				t.Helper()
				path := filepath.Join(runDir, "witness.json")
				if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "verify published replay",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runDir, _, root := buildDelegatedRunDir(t)
			tc.mutate(t, runDir)

			_, err := playground.ArchiveRunForPublishedReplay(runDir, root)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ArchiveRunForPublishedReplay error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestArchiveRunForPublishedReplay_RejectsInvalidRoot(t *testing.T) {
	runDir, _, _ := buildDelegatedRunDir(t)
	_, err := playground.ArchiveRunForPublishedReplay(runDir, ed25519.PrivateKey("short"))
	if err == nil || !strings.Contains(err.Error(), "archive authorization root key") {
		t.Fatalf("invalid root error = %v, want root-key refusal", err)
	}
}

func TestSignReplayArchiveAuthorization_RejectsMalformedDelegation(t *testing.T) {
	_, root := testGenKey(t)
	_, err := playground.SignReplayArchiveAuthorization(root, playground.LaunchManifest{}, []byte("{"))
	if err == nil || !strings.Contains(err.Error(), "orchestrator-delegation.json") {
		t.Fatalf("malformed delegation error = %v, want delegation parse refusal", err)
	}
}

func TestVerifyArchivedReplay_RefusesMalformedOrUnreadableAuthorization(t *testing.T) {
	t.Run("malformed authorization", func(t *testing.T) {
		dir, pub, _ := buildDelegatedRunDir(t)
		path := filepath.Join(dir, "replay-archive-authorization.json")
		if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		report, err := playground.VerifyArchivedReplay(dir, pub)
		if err != nil {
			t.Fatal(err)
		}
		if report.OK || !strings.Contains(report.FailureSummary(), "invalid replay archive authorization") {
			t.Fatalf("malformed authorization report = %+v", report)
		}
	})

	t.Run("authorization is directory", func(t *testing.T) {
		dir, pub, _ := buildDelegatedRunDir(t)
		path := filepath.Join(dir, "replay-archive-authorization.json")
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatal(err)
		}
		_, err := playground.VerifyArchivedReplay(dir, pub)
		if err == nil || !strings.Contains(err.Error(), "cannot read replay-archive-authorization.json") {
			t.Fatalf("directory authorization error = %v", err)
		}
	})
}
