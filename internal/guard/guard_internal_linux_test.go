// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestApply_RefusesABIBelowFloor(t *testing.T) {
	prepared := &PreparedManifest{complete: true}
	record, err := prepared.apply(func() (int, error) { return MinimumABI - 1, nil })
	if !errors.Is(err, ErrABITooOld) {
		t.Fatalf("err = %v, want ErrABITooOld", err)
	}
	if record.Enforced() || record.State != EnforcementRefused {
		t.Fatalf("record = %+v, want refused and unenforced", record)
	}
	if record.ObservedABI == nil || *record.ObservedABI != MinimumABI-1 {
		t.Fatalf("observed ABI = %v, want %d", record.ObservedABI, MinimumABI-1)
	}
}

func TestPrepare_RechecksFloorOnResolvedTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}

	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles:  []config.GuardProfile{{Name: "agent", Manifests: []string{"m"}}},
		Manifests: []config.GuardManifest{{Name: "m", ReadOnlyDirectories: []string{alias}}},
	}
	explainFloor := func(path string, access config.GuardAccess) (config.GuardFloorDecision, error) {
		decision := config.GuardFloorDecision{Access: access, Path: path}
		if filepath.Clean(path) == target {
			decision.Refused = true
			decision.Reason = "test resolved target is refused"
		}
		return decision, nil
	}

	grants, err := planManifestsWithFloor(cfg, "agent", explainFloor)
	if err != nil {
		t.Fatalf("plan manifests: %v", err)
	}
	prepared, err := prepareGrants(grants, os.Getuid(), explainFloor)
	if err != nil {
		t.Fatalf("prepare grants: %v", err)
	}
	defer func() { _ = prepared.Close() }()

	if prepared.complete {
		t.Fatal("resolved floor refusal reported a complete manifest")
	}
	if len(prepared.outcomes) != 1 || prepared.outcomes[0].State != StateRefused {
		t.Fatalf("outcomes = %+v, want one refused outcome", prepared.outcomes)
	}
	if !strings.Contains(prepared.outcomes[0].Reason, "resolved target") {
		t.Fatalf("reason = %q, want resolved target refusal", prepared.outcomes[0].Reason)
	}
}

func TestCreateLeaf_ExistingLeafIsGranted(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o750); err != nil {
		t.Fatal(err)
	}

	fd, stateResult, reason := createLeaf(state, os.Getuid())
	if fd < 0 {
		t.Fatalf("create leaf failed: %s", reason)
	}
	defer func() { _ = unix.Close(fd) }()
	if stateResult != StateGranted {
		t.Fatalf("state = %q, want %q when mkdirat observes an existing leaf", stateResult, StateGranted)
	}
}

func TestPreparedManifestCloseIsIdempotentAndReleasesDescriptors(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles:  []config.GuardProfile{{Name: "agent", Manifests: []string{"m"}}},
		Manifests: []config.GuardManifest{{Name: "m", ReadWriteDirectories: []string{state}}},
	}
	prepared, err := Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(prepared.rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(prepared.rules))
	}
	fd := prepared.rules[0].fd
	if err := prepared.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("closed descriptor F_GETFD error = %v, want EBADF", err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
