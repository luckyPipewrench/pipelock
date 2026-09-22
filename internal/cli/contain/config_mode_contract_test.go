// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/session"
)

// The admin CLI (internal/cli/session, checkConfigPerms) refuses a config file
// carrying any group bit, any world bit, or owner-execute, because that file
// holds the admin API token. It masks with 0o177. The installer writes the same
// file, so the two must agree: installing a mode the CLI rejects makes every
// shipped admin command fail against the shipped config, which is what happened
// with 0o640 ("restrict to 0o600 before using it as an admin API source").
//
// This asserts the installer side against the CLI's mask. If the CLI's rule
// changes, this test should be updated in the same commit as that change.
func TestConfigSecretModeSatisfiesAdminCLI(t *testing.T) {
	if modeConfigSecret&session.ConfigPermRejectMask != 0 {
		t.Errorf("modeConfigSecret = %#o carries bits the admin CLI rejects (mask %#o); "+
			"shipped admin commands would refuse the shipped config",
			modeConfigSecret, session.ConfigPermRejectMask)
	}
	if modeConfigSecret&0o400 == 0 {
		t.Errorf("modeConfigSecret = %#o is not owner-readable; the proxy could not read its own config", modeConfigSecret)
	}
}

// An install that upgrades over a config written by an older version must
// tighten it. Promotion cannot: it returns early with no --config, and again
// when the staged bytes match what is already installed, so the long-running
// installs that most need the repair are exactly the ones promotion skips.
func TestRepairManagedConfigMode_TightensExistingLooseConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not preserve Unix permission bits, so the loose-mode seed and the mask assertion cannot hold there")
	}
	var out bytes.Buffer
	env := &installEnv{
		configDir:      t.TempDir(),
		out:            &out,
		repairLeafMode: setLeafModeNoFollow,
	}

	dst := managedPipelockConfigPath(env)
	if err := os.WriteFile(dst, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("seed existing config: %v", err)
	}
	// Chmod explicitly: os.WriteFile applies the umask, so seeding a loose mode
	// through the create call alone can silently land at 0o600 and the test then
	// asserts nothing.
	if err := os.Chmod(dst, 0o640); err != nil {
		t.Fatalf("seed existing config mode: %v", err)
	}
	if info, err := os.Stat(dst); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("seed did not take: mode=%v err=%v", info.Mode().Perm(), err)
	}

	applied, err := stepRepairManagedConfigMode().apply(context.Background(), env)
	if err != nil {
		t.Fatalf("repair step: %v", err)
	}
	if !applied {
		t.Error("repair step reported no change for a 0640 config")
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat repaired config: %v", err)
	}
	if got := info.Mode().Perm(); got&session.ConfigPermRejectMask != 0 {
		t.Errorf("config left at %#o, which the admin CLI rejects", got)
	}

	applied, err = stepRepairManagedConfigMode().apply(context.Background(), env)
	if err != nil {
		t.Fatalf("repair step second run: %v", err)
	}
	if applied {
		t.Error("repair step reported a change on an already-correct config")
	}
}

// The repair step runs on every install, including the first, where promotion
// owns creating the file. Absence is not a failure and must not be reported as
// a change.
func TestRepairManagedConfigMode_NoConfigYet(t *testing.T) {
	var out bytes.Buffer
	env := &installEnv{configDir: t.TempDir(), out: &out, repairLeafMode: setLeafModeNoFollow}

	applied, err := stepRepairManagedConfigMode().apply(context.Background(), env)
	if err != nil {
		t.Fatalf("repair step with no config: %v", err)
	}
	if applied {
		t.Error("repair step reported a change when no config exists")
	}
}

// A chmod that fails must surface. Swallowing it would leave the config at a
// mode the admin CLI refuses while install reported success, which is the
// failure direction this whole change exists to remove.
func TestRepairManagedConfigMode_ChmodFailureSurfaces(t *testing.T) {
	var out bytes.Buffer
	dir := t.TempDir()
	env := &installEnv{
		configDir: dir,
		out:       &out,
		repairLeafMode: func(string, os.FileMode, bool) (os.FileMode, bool, error) {
			return 0, false, errors.New("read-only filesystem")
		},
	}
	dst := managedPipelockConfigPath(env)
	if err := os.WriteFile(dst, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(dst, 0o640); err != nil {
		t.Fatalf("seed mode: %v", err)
	}

	applied, err := stepRepairManagedConfigMode().apply(context.Background(), env)
	if err == nil {
		t.Fatal("chmod failure did not surface as an error")
	}
	if applied {
		t.Error("failed chmod reported as an applied change")
	}
	if !strings.Contains(err.Error(), "read-only filesystem") {
		t.Errorf("error lost its cause: %v", err)
	}
}

// A symlinked leaf must be refused outright. The managed config lives in a
// directory the proxy account owns, so that account can replace the file
// between a check and a chmod; a path-resolving repair would then point root's
// privileged mode change at whatever the link names (CWE-59).
func TestRepairManagedConfigMode_RefusesSymlinkedLeaf(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics and Unix modes differ on Windows")
	}
	var out bytes.Buffer
	dir := t.TempDir()
	env := &installEnv{configDir: dir, out: &out, repairLeafMode: setLeafModeNoFollow}

	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("do not touch\n"), 0o600); err != nil {
		t.Fatalf("seed victim: %v", err)
	}
	if err := os.Chmod(victim, 0o644); err != nil {
		t.Fatalf("seed victim mode: %v", err)
	}
	if err := os.Symlink(victim, managedPipelockConfigPath(env)); err != nil {
		t.Fatalf("seed symlink: %v", err)
	}

	applied, err := stepRepairManagedConfigMode().apply(context.Background(), env)
	if err == nil {
		t.Fatal("symlinked config was accepted; a privileged chmod could be redirected")
	}
	if applied {
		t.Error("symlinked config reported as repaired")
	}
	info, statErr := os.Stat(victim)
	if statErr != nil {
		t.Fatalf("stat victim: %v", statErr)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("victim mode changed to %#o; the repair followed the symlink", got)
	}
}

// Rollback must put back the mode the repair found. Without an undo handler a
// later step's failure leaves the config tightened and the install half applied.
func TestRepairManagedConfigMode_UndoRestoresPreviousMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not preserve Unix permission bits")
	}
	var out bytes.Buffer
	env := &installEnv{configDir: t.TempDir(), out: &out, repairLeafMode: setLeafModeNoFollow}
	dst := managedPipelockConfigPath(env)
	if err := os.WriteFile(dst, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(dst, 0o640); err != nil {
		t.Fatalf("seed mode: %v", err)
	}

	s := stepRepairManagedConfigMode()
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("undo left mode %#o, want the 0640 it found", got)
	}
}

// undo must be safe to call when apply changed nothing. The step runner calls
// undo against partial state, so a no-op apply followed by a rollback must not
// touch a file this step never modified.
func TestRepairManagedConfigMode_UndoWithoutApplyIsNoOp(t *testing.T) {
	var out bytes.Buffer
	env := &installEnv{configDir: t.TempDir(), out: &out, repairLeafMode: setLeafModeNoFollow}
	if err := stepRepairManagedConfigMode().undo(context.Background(), env); err != nil {
		t.Errorf("undo without apply: %v", err)
	}
}

// A rollback that cannot restore the mode must surface, not report success: the
// file is left tightened and the operator needs to know.
func TestRepairManagedConfigMode_UndoFailureSurfaces(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not preserve Unix permission bits")
	}
	var out bytes.Buffer
	calls := 0
	env := &installEnv{
		configDir: t.TempDir(),
		out:       &out,
		repairLeafMode: func(path string, mode os.FileMode, _ bool) (os.FileMode, bool, error) {
			calls++
			if calls == 1 {
				return 0o640, true, nil
			}
			return 0, false, errors.New("read-only filesystem")
		},
	}
	s := stepRepairManagedConfigMode()
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("apply: %v", err)
	}
	err := s.undo(context.Background(), env)
	if err == nil {
		t.Fatal("undo failure did not surface")
	}
	if !strings.Contains(err.Error(), "read-only filesystem") {
		t.Errorf("error lost its cause: %v", err)
	}
}

// 0400 already satisfies the admin CLI: no group, world or owner-execute bit.
// Rewriting it to 0600 would GRANT owner write access to a file that was
// stricter, so the repair must leave it alone. Tightening that loosens is worse
// than not running at all.
func TestRepairManagedConfigMode_LeavesStricterModeAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not preserve Unix permission bits")
	}
	var out bytes.Buffer
	env := &installEnv{configDir: t.TempDir(), out: &out, repairLeafMode: setLeafModeNoFollow}
	dst := managedPipelockConfigPath(env)
	if err := os.WriteFile(dst, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(dst, 0o400); err != nil {
		t.Fatalf("seed mode: %v", err)
	}

	applied, err := stepRepairManagedConfigMode().apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied {
		t.Error("repair reported a change on a 0400 config the admin CLI already accepts")
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o400 {
		t.Errorf("mode changed to %#o; the repair loosened a stricter config", got)
	}
}

// A directory or device at the managed path means the leaf is not the config
// install wrote. The open succeeds, so only the regular-file check stands
// between a privileged mode change and an unintended target.
func TestRepairManagedConfigMode_RefusesNonRegularLeaf(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file-type semantics")
	}
	var out bytes.Buffer
	env := &installEnv{configDir: t.TempDir(), out: &out, repairLeafMode: setLeafModeNoFollow}
	if err := os.Mkdir(managedPipelockConfigPath(env), 0o750); err != nil {
		t.Fatalf("seed directory: %v", err)
	}

	applied, err := stepRepairManagedConfigMode().apply(context.Background(), env)
	if err == nil {
		t.Fatal("a directory at the managed config path was accepted")
	}
	if applied {
		t.Error("directory reported as repaired")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Errorf("error does not name the cause: %v", err)
	}
}
