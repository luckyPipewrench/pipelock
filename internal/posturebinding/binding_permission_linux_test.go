//go:build linux

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posturebinding

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const (
	unreadableCaseEnv = "PIPELOCK_POSTUREBINDING_UNREADABLE_CASE"
	unreadablePathEnv = "PIPELOCK_POSTUREBINDING_UNREADABLE_PATH"
	unreadableKeyEnv  = "PIPELOCK_POSTUREBINDING_UNREADABLE_KEY"
)

func TestLoadFileUnreadableFile(t *testing.T) {
	testUnreadableProof(t, "file")
}

func TestLoadFileUnreadableParent(t *testing.T) {
	testUnreadableProof(t, "parent")
}

func testUnreadableProof(t *testing.T, wantCase string) {
	t.Helper()
	if childCase := os.Getenv(unreadableCaseEnv); childCase != "" {
		if childCase != wantCase {
			t.Fatalf("child case = %q, want %q", childCase, wantCase)
		}
		assertUnreadableProof(t, os.Getenv(unreadablePathEnv), os.Getenv(unreadableKeyEnv))
		return
	}

	path, keyHex, cleanup := makeUnreadableProof(t, wantCase)
	t.Cleanup(cleanup)
	if os.Geteuid() == 0 {
		testName := "^TestLoadFileUnreadableFile$"
		if wantCase == "parent" {
			testName = "^TestLoadFileUnreadableParent$"
		}
		// #nosec G204,G702 -- this only re-executes the current test binary with a fixed test name.
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run="+testName, "-test.v")
		cmd.Env = append(os.Environ(), unreadableCaseEnv+"="+wantCase, unreadablePathEnv+"="+path, unreadableKeyEnv+"="+keyHex)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("unprivileged child: %v\n%s", err, output)
		}
		return
	}
	assertUnreadableProof(t, path, keyHex)
}

func makeUnreadableProof(t *testing.T, wantCase string) (string, string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pipelock-posturebinding-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	cleanup := func() {
		if wantCase == "parent" {
			// #nosec G302 -- restore a private test directory before test cleanup.
			_ = os.Chmod(filepath.Join(dir, "denied"), 0o700)
		}
		_ = os.Chmod(filepath.Join(dir, "proof.json"), 0o600)
		_ = os.RemoveAll(dir)
	}
	// #nosec G302 -- the unprivileged child must traverse this isolated test directory.
	if err := os.Chmod(dir, 0o755); err != nil {
		cleanup()
		t.Fatalf("Chmod temp dir: %v", err)
	}
	capsule, data := mintContainmentCapsule(t)
	path := filepath.Join(dir, "proof.json")
	if wantCase == "parent" {
		denied := filepath.Join(dir, "denied")
		if err := os.Mkdir(denied, 0o700); err != nil {
			cleanup()
			t.Fatalf("Mkdir denied parent: %v", err)
		}
		path = filepath.Join(denied, "proof.json")
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		cleanup()
		t.Fatalf("WriteFile: %v", err)
	}
	if wantCase == "parent" {
		if err := os.Chmod(filepath.Dir(path), 0o000); err != nil {
			cleanup()
			t.Fatalf("Chmod parent: %v", err)
		}
	} else if err := os.Chmod(path, 0o000); err != nil {
		cleanup()
		t.Fatalf("Chmod proof: %v", err)
	}
	return path, capsule.SignerKeyID, cleanup
}

func assertUnreadableProof(t *testing.T, path, keyHex string) {
	t.Helper()
	result, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile(%q): %v", path, err)
	}
	requireAvailability(t, result, AvailabilityUnreadable)
	if !errors.Is(result.Cause, os.ErrPermission) {
		t.Fatalf("unreadable cause = %v, want permission denial", result.Cause)
	}

	t.Setenv(RuntimeProofEnv, path)
	var warning bytes.Buffer
	binding, err := LoadRuntimeForReceipts(RuntimeReceiptOptions{ReceiptSigningEnabled: true, Stderr: &warning})
	if err != nil {
		t.Fatalf("ordinary receipt policy: %v", err)
	}
	if binding.Availability != AvailabilityUnreadable {
		t.Fatalf("ordinary receipt availability = %q, want %q", binding.Availability, AvailabilityUnreadable)
	}
	message := warning.String()
	for _, want := range []string{path, "containment user", "grant this runtime user read access"} {
		if !strings.Contains(message, want) {
			t.Fatalf("warning %q does not contain %q", message, want)
		}
	}
	if !strings.Contains(message, "owner ") || !strings.Contains(message, "group ") {
		t.Fatalf("file warning %q does not name the proof owner and group", message)
	}

	pinnedKey, decodeErr := hex.DecodeString(keyHex)
	if decodeErr != nil {
		t.Fatalf("decode pinned signer key: %v", decodeErr)
	}
	_, err = LoadRuntimeForReceipts(RuntimeReceiptOptions{
		ReceiptSigningEnabled:      true,
		RequireContainmentEvidence: true,
		PinnedPostureSignerKey:     pinnedKey,
		Stderr:                     &warning,
	})
	if err == nil || !strings.Contains(err.Error(), "containment evidence is required") || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("required receipt policy error = %v, want unreadable containment requirement", err)
	}
}
