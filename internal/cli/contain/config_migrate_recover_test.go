// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestEnsureSigningKey_RecoversExistingKeyInsteadOfGenerating proves that when
// the dedicated dest has no key but the operator's configured key exists
// elsewhere, the migration COPIES the existing key (preserving signer_key)
// rather than generating a fresh one that would orphan the receipt chain.
func TestEnsureSigningKey_RecoversExistingKeyInsteadOfGenerating(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	ctx := &configMigrationContext{env: env}

	recoverSrc := filepath.Join(env.configDir, "old", "operator-signing.key")
	mustWriteSigningKey(t, recoverSrc)
	existing, err := signing.LoadPrivateKeyFile(recoverSrc)
	if err != nil {
		t.Fatalf("load existing key: %v", err)
	}

	dest := filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
	if err := ensureFlightRecorderSigningKeyWithRecovery(ctx, dest, recoverSrc); err != nil {
		t.Fatalf("ensure with recovery: %v", err)
	}

	got, err := signing.LoadPrivateKeyFile(dest)
	if err != nil {
		t.Fatalf("load dest key: %v", err)
	}
	if !existing.Equal(got) {
		t.Fatal("dest key does not match recovered key - the chain would be orphaned")
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat dest: %v", err)
	}
	if info.Mode().Perm() != modePinSecret {
		t.Errorf("dest mode = %s, want %s", info.Mode().Perm(), modePinSecret)
	}
}

// TestEnsureSigningKey_GeneratesWhenNoExistingKey confirms that when neither
// dest nor a recoverable source exists, a fresh key IS generated (the legit
// first-time path).
func TestEnsureSigningKey_GeneratesWhenNoExistingKey(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	ctx := &configMigrationContext{env: env}

	dest := filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
	missing := filepath.Join(env.configDir, "old", "does-not-exist.key")
	if err := ensureFlightRecorderSigningKeyWithRecovery(ctx, dest, missing); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := signing.LoadPrivateKeyFile(dest); err != nil {
		t.Fatalf("generated key invalid: %v", err)
	}
	if len(ctx.artifacts) == 0 {
		t.Fatal("expected a generated-key artifact")
	}
}

// TestEnsureSigningKey_DoesNotRecoverNonKeyFile confirms a non-key file at the
// recovery source is NOT adopted (it would fail to load at runtime); a fresh
// key is generated instead.
func TestEnsureSigningKey_DoesNotRecoverNonKeyFile(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	ctx := &configMigrationContext{env: env}

	recoverSrc := filepath.Join(env.configDir, "old", "garbage")
	mustWriteFile(t, recoverSrc, "not a signing key")

	dest := filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
	if err := ensureFlightRecorderSigningKeyWithRecovery(ctx, dest, recoverSrc); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	// A valid (freshly generated) key must be present, NOT the garbage bytes.
	if _, err := signing.LoadPrivateKeyFile(dest); err != nil {
		t.Fatalf("dest must hold a valid key after non-key recovery source: %v", err)
	}
}

func TestResolveExistingKeyPath_Variants(t *testing.T) {
	home := t.TempDir()
	configDir := filepath.Join(home, ".config", "pipelock")
	ctx := &configMigrationContext{operatorHome: home, configDir: configDir}

	if got := ctx.resolveExistingKeyPath(""); got != "" {
		t.Errorf("empty -> %q, want \"\"", got)
	}
	if got := ctx.resolveExistingKeyPath(`""`); got != "" {
		t.Errorf("quoted-empty -> %q, want \"\"", got)
	}
	if got := ctx.resolveExistingKeyPath("~"); got != filepath.Clean(home) {
		t.Errorf("~ -> %q, want %q", got, home)
	}
	if got := ctx.resolveExistingKeyPath("~/keys/k.key"); got != filepath.Join(home, "keys", "k.key") {
		t.Errorf("~/keys/k.key -> %q", got)
	}
	if got := ctx.resolveExistingKeyPath("~bob/x"); got != "" {
		t.Errorf("~bob/x -> %q, want \"\" (other-user home unresolved)", got)
	}
	if got := ctx.resolveExistingKeyPath("rel/k.key"); got != filepath.Join(configDir, "rel", "k.key") {
		t.Errorf("relative -> %q, want under configDir", got)
	}
	if got := ctx.resolveExistingKeyPath("/abs/k.key"); got != filepath.Clean("/abs/k.key") {
		t.Errorf("abs -> %q", got)
	}

	// No operator home: ~ paths are unresolvable.
	ctx.operatorHome = ""
	if got := ctx.resolveExistingKeyPath("~/k"); got != "" {
		t.Errorf("~ with empty home -> %q, want \"\"", got)
	}
}

func TestRecoverExistingSigningKey_NonRegularSourceNotRecovered(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	ctx := &configMigrationContext{env: env}
	srcDir := filepath.Join(env.configDir, "old", "as-dir")
	if err := os.MkdirAll(srcDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dest := filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
	recovered, err := recoverExistingSigningKey(ctx, srcDir, dest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if recovered {
		t.Fatal("a directory source must not be recovered")
	}
}

// TestMigratePipelockConfigForContain_RecoversExistingKeyAtDest is the realistic
// re-install case: the dedicated dest already holds the operator's key from a
// prior install, and the configured source is now missing. Migration must KEEP
// the existing dest key (stable signer_key), not regenerate.
func TestMigratePipelockConfigForContain_RecoversExistingKeyAtDest(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	home := t.TempDir()
	origLookup := env.lookupUser
	env.lookupUser = func(name string) (*user.User, error) {
		if name == containInstallOperatorUser {
			return &user.User{Uid: "1000", Gid: "1000", Username: name, HomeDir: home}, nil
		}
		return origLookup(name)
	}
	configDir := filepath.Join(home, ".config", "pipelock")
	dest := filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
	mustWriteSigningKey(t, dest)
	before, err := signing.LoadPrivateKeyFile(dest)
	if err != nil {
		t.Fatalf("load pre-existing dest key: %v", err)
	}

	missingKey := filepath.Join(home, ".pipelock", "agents", "official", "id_ed25519")
	out, _, err := migratePipelockConfigForContain(env, filepath.Join(configDir, "pipelock.yaml"), []byte(`
flight_recorder:
  signing_key_path: `+missingKey+`
`))
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !strings.Contains(string(out), "signing_key_path: "+dest) {
		t.Fatalf("config not repointed to dest:\n%s", out)
	}
	after, err := signing.LoadPrivateKeyFile(dest)
	if err != nil {
		t.Fatalf("load dest key after migrate: %v", err)
	}
	if !before.Equal(after) {
		t.Fatal("dest signing key was regenerated - the receipt chain would orphan")
	}
}

// TestRecoverExistingSigningKey_RejectsSymlinkSource confirms a symlinked
// recovery source is rejected (refusing to copy as root), matching the
// existing copy-path hardening.
func TestRecoverExistingSigningKey_RejectsSymlinkSource(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	ctx := &configMigrationContext{env: env}

	realKey := filepath.Join(env.configDir, "old", "real.key")
	mustWriteSigningKey(t, realKey)
	link := filepath.Join(env.configDir, "old", "link.key")
	if err := os.Symlink(realKey, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	dest := filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
	recovered, err := recoverExistingSigningKey(ctx, link, dest)
	if err == nil {
		t.Fatal("expected symlink recovery source to be rejected")
	}
	if recovered {
		t.Fatal("symlink source must not be reported as recovered")
	}
}
