// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// archiveReplayEnv points the publisher at a sealed run and a root key file, and
// skips when they are absent. That skip is deliberate and cannot be engineered
// away: resolveOrchestratorRoot refuses any key that does not derive the
// PUBLISHED identity, because a broker signing under another root would produce
// bundles that fail every shipped verifier. A generated test key is therefore
// rejected before the command does anything, so this end-to-end path can only
// run where the real root and a real sealed run are present.
//
// It is an extra layer rather than the coverage. The publisher's logic --
// kit-flag validation, build-before-publish ordering, and all-or-nothing
// rollback -- is exercised hermetically against buildArchiveVerifyKits and
// publishArchiveArtifacts in TestArchiveReplayOutputHelpersFailClosed, which
// runs everywhere including a clean CI checkout.
func archiveReplayEnv(t *testing.T) (runDir, keyFile string) {
	t.Helper()
	runDir = "/tmp/kit-verify/pipelock-live-verify-windows/app/run"
	if _, err := os.Stat(filepath.Join(runDir, "launch-manifest.json")); err != nil {
		t.Skipf("sealed run directory not present: %v", err)
	}
	keyFile = "/home/josh/.config/pipelock/playground-demo-signing-v2.key"
	if _, err := os.Stat(keyFile); err != nil {
		t.Skipf("published root key not present: %v", err)
	}
	return runDir, keyFile
}

func runArchiveCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newArchiveReplayCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// The publisher writes a bundle and all three kits in one invocation, because a
// kit built from a different bundle than the one shipped is a silent mismatch a
// visitor would only find offline.
func TestArchiveReplayCmd_WritesBundleAndKits(t *testing.T) {
	runDir, keyFile := archiveReplayEnv(t)
	for _, v := range []string{"/tmp/pg-verifiers/pipelock-verifier-linux", "/tmp/pg-verifiers/pipelock-verifier-macos", "/tmp/pg-verifiers/pipelock-verifier-windows.exe"} {
		if _, err := os.Stat(v); err != nil {
			t.Skipf("verifier binary not present: %v", err)
		}
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "replay-bundle.tar.gz")
	kits := filepath.Join(dir, "kits")

	out, err := runArchiveCmd(t,
		"--run-dir", runDir, "--orchestrator-key-file", keyFile, "--output", bundle,
		"--kit-output-dir", kits,
		"--linux-verifier", "/tmp/pg-verifiers/pipelock-verifier-linux",
		"--macos-verifier", "/tmp/pg-verifiers/pipelock-verifier-macos",
		"--windows-verifier", "/tmp/pg-verifiers/pipelock-verifier-windows.exe",
	)
	if err != nil {
		t.Fatalf("archive-replay: %v (%s)", err, out)
	}
	if fi, statErr := os.Stat(bundle); statErr != nil || fi.Size() == 0 {
		t.Fatalf("bundle not written: %v", statErr)
	}
	entries, err := os.ReadDir(kits)
	if err != nil {
		t.Fatalf("read kit dir: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("wrote %d kits, want 3", len(entries))
	}
}

// Every refusal below protects an operator from a half-published artifact set.
func TestArchiveReplayCmd_Refusals(t *testing.T) {
	runDir, keyFile := archiveReplayEnv(t)

	t.Run("verifier_without_kit_dir", func(t *testing.T) {
		out, err := runArchiveCmd(t,
			"--run-dir", runDir, "--orchestrator-key-file", keyFile,
			"--output", filepath.Join(t.TempDir(), "b.tar.gz"),
			"--linux-verifier", "/tmp/pg-verifiers/pipelock-verifier-linux",
		)
		if err == nil || !strings.Contains(err.Error()+out, "kit-output-dir is required") {
			t.Fatalf("error = %v (%s), want the kit-output-dir refusal", err, out)
		}
	})

	t.Run("kit_dir_without_every_verifier", func(t *testing.T) {
		out, err := runArchiveCmd(t,
			"--run-dir", runDir, "--orchestrator-key-file", keyFile,
			"--output", filepath.Join(t.TempDir(), "b.tar.gz"),
			"--kit-output-dir", filepath.Join(t.TempDir(), "kits"),
		)
		if err == nil || !strings.Contains(err.Error()+out, "requires --linux-verifier") {
			t.Fatalf("error = %v (%s), want the all-three-verifiers refusal", err, out)
		}
	})

	// Refusing to overwrite keeps a failed republish from destroying the artifact
	// currently serving visitors.
	t.Run("existing_output_is_not_overwritten", func(t *testing.T) {
		dir := t.TempDir()
		existing := filepath.Join(dir, "already-there.tar.gz")
		if err := os.WriteFile(existing, []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := runArchiveCmd(t, "--run-dir", runDir, "--orchestrator-key-file", keyFile, "--output", existing)
		if err == nil || !strings.Contains(err.Error()+out, "create output") {
			t.Fatalf("error = %v (%s), want a refusal to overwrite", err, out)
		}
		if data, readErr := os.ReadFile(filepath.Clean(existing)); readErr != nil || string(data) != "original" {
			t.Fatal("the existing artifact was modified")
		}
	})

	t.Run("missing_run_directory", func(t *testing.T) {
		out, err := runArchiveCmd(t,
			"--run-dir", filepath.Join(t.TempDir(), "absent"), "--orchestrator-key-file", keyFile,
			"--output", filepath.Join(t.TempDir(), "b.tar.gz"),
		)
		if err == nil {
			t.Fatalf("a missing run directory must be refused (%s)", out)
		}
	})

	t.Run("missing_root_key", func(t *testing.T) {
		out, err := runArchiveCmd(t,
			"--run-dir", runDir, "--orchestrator-key-file", filepath.Join(t.TempDir(), "absent.key"),
			"--output", filepath.Join(t.TempDir(), "b.tar.gz"),
		)
		if err == nil {
			t.Fatalf("an unreadable root key must be refused (%s)", out)
		}
	})
}

func TestArchiveReplayOutputHelpersFailClosed(t *testing.T) {
	t.Run("kit output path must be new directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "already-a-file")
		if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
			t.Fatal(err)
		}
		f := &archiveReplayFlags{
			output:          filepath.Join(t.TempDir(), "bundle.tar.gz"),
			kitOutputDir:    path,
			linuxVerifier:   "unused",
			macOSVerifier:   "unused",
			windowsVerifier: "unused",
		}
		kits := []archiveKit{{name: "kit.zip", data: []byte("kit")}}
		if err := publishArchiveArtifacts(f, []byte("bundle"), kits); err == nil || !strings.Contains(err.Error(), "create kit output directory") {
			t.Fatalf("existing output file error = %v, want directory creation refusal", err)
		}
	})

	// A build failure must not reach the filesystem at all, because the build
	// runs before anything is published.
	t.Run("kit build stops before any output", func(t *testing.T) {
		kitDir := filepath.Join(t.TempDir(), "kits")
		f := &archiveReplayFlags{
			kitOutputDir:    kitDir,
			linuxVerifier:   filepath.Join(t.TempDir(), "missing-linux"),
			macOSVerifier:   filepath.Join(t.TempDir(), "missing-macos"),
			windowsVerifier: filepath.Join(t.TempDir(), "missing-windows"),
		}
		kits, err := buildArchiveVerifyKits(f, nil)
		if err == nil || !strings.Contains(err.Error(), "build linux verification kit") {
			t.Fatalf("missing verifier error = %v, want kit-build failure", err)
		}
		if kits != nil {
			t.Fatalf("a failed build returned kits: %v", kits)
		}
		if _, statErr := os.Stat(kitDir); !os.IsNotExist(statErr) {
			t.Fatalf("a failed kit build created the output directory: %v", statErr)
		}
	})

	// The finding this covers: a later write failure used to leave the bundle and
	// any earlier kits on disk, so a visitor could download a bundle whose kits
	// never arrived. Publication is now all-or-nothing.
	t.Run("a failed kit write removes every artifact this run created", func(t *testing.T) {
		dir := t.TempDir()
		bundlePath := filepath.Join(dir, "replay-bundle.tar.gz")
		kitDir := filepath.Join(dir, "kits")
		f := &archiveReplayFlags{output: bundlePath, kitOutputDir: kitDir}

		// The second kit collides with the first by name, so its O_EXCL create
		// fails after the bundle and the first kit are already written.
		kits := []archiveKit{
			{name: "same-name.zip", data: []byte("first")},
			{name: "same-name.zip", data: []byte("second")},
		}
		err := publishArchiveArtifacts(f, []byte("bundle"), kits)
		if err == nil || !strings.Contains(err.Error(), "create output") {
			t.Fatalf("error = %v, want the duplicate-name create refusal", err)
		}
		if _, statErr := os.Stat(bundlePath); !os.IsNotExist(statErr) {
			t.Fatal("the bundle survived a failed publication")
		}
		if _, statErr := os.Stat(filepath.Join(kitDir, "same-name.zip")); !os.IsNotExist(statErr) {
			t.Fatal("the first kit survived a failed publication")
		}
		if _, statErr := os.Stat(kitDir); !os.IsNotExist(statErr) {
			t.Fatal("the kit directory survived a failed publication")
		}
	})

	// Rollback must never touch an artifact it did not create. A pre-existing
	// output is refused before anything is written, so nothing is removed.
	t.Run("rollback never removes a pre-existing artifact", func(t *testing.T) {
		dir := t.TempDir()
		bundlePath := filepath.Join(dir, "replay-bundle.tar.gz")
		if err := os.WriteFile(bundlePath, []byte("serving-visitors"), 0o600); err != nil {
			t.Fatal(err)
		}
		f := &archiveReplayFlags{output: bundlePath, kitOutputDir: filepath.Join(dir, "kits")}
		kits := []archiveKit{{name: "kit.zip", data: []byte("kit")}}
		if err := publishArchiveArtifacts(f, []byte("bundle"), kits); err == nil {
			t.Fatal("publishing over an existing artifact must be refused")
		}
		data, err := os.ReadFile(filepath.Clean(bundlePath))
		if err != nil || string(data) != "serving-visitors" {
			t.Fatalf("the pre-existing artifact was removed or modified: %q, %v", data, err)
		}
	})

	t.Run("archive file writes exact bytes and never replaces directory", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "replay.tar.gz")
		want := []byte("replay-bytes")
		if err := writeNewArchiveFile(path, want); err != nil {
			t.Fatalf("writeNewArchiveFile: %v", err)
		}
		got, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read output: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("output = %q, want %q", got, want)
		}
		if err := writeNewArchiveFile(dir, want); err == nil || !strings.Contains(err.Error(), "create output") {
			t.Fatalf("directory output error = %v, want create-output refusal", err)
		}
	})
}
