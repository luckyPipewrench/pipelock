// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"errors"
	"os"
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
	var out bytes.Buffer
	env := &installEnv{
		configDir: t.TempDir(),
		out:       &out,
		stat:      os.Stat,
		chmod:     os.Chmod,
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
	env := &installEnv{configDir: t.TempDir(), out: &out, stat: os.Stat, chmod: os.Chmod}

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
		stat:      os.Stat,
		chmod:     func(string, os.FileMode) error { return errors.New("read-only filesystem") },
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
