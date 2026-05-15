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

func TestMigratePipelockConfigForContain_RewritesHomePaths(t *testing.T) {
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
	mustWriteFile(t, filepath.Join(configDir, "license.token"), "pipelock_lic_v1_test\n")
	mustWriteFile(t, filepath.Join(home, ".pipelock", "ca.pem"), "CA\n")
	mustWriteFile(t, filepath.Join(home, ".pipelock", "ca-key.pem"), "KEY\n")
	mustWriteSigningKey(t, filepath.Join(home, ".pipelock", "agents", "pipelock-official", "id_ed25519"))
	mustWriteFile(t, filepath.Join(home, ".local", "share", "pipelock", "learn-salt"), "SALT\n")
	mustWriteFile(t, filepath.Join(configDir, "integrity", "manifest.json"), "{}\n")
	mustWriteFile(t, filepath.Join(configDir, "roster.json"), "{}\n")
	mustWriteFile(t, filepath.Join(configDir, "recorder", "existing.jsonl"), "{}\n")
	mustWriteFile(t, filepath.Join(home, ".local", "share", "pipelock", "captures", "local", "cap.jsonl"), "{}\n")
	mustWriteFile(t, filepath.Join(home, ".config", "pipelock", "baselines", "profile.json"), "{}\n")
	mustWriteFile(t, filepath.Join(home, ".pipelock", "contracts", "production", "active", "active.json"), "{}\n")

	data := []byte(`
mode: balanced
license_file: ` + filepath.Join(configDir, "license.token") + `
mcp_tool_policy:
  redirect_profiles:
    fetch-proxy:
      exec: ["` + filepath.Join(home, ".local", "bin", "pipelock") + `", "internal-redirect", "fetch-proxy"]
logging:
  output: file
  file: ` + filepath.Join(home, ".local", "share", "pipelock", "audit.log") + `
flight_recorder:
  enabled: true
  dir: ` + filepath.Join(configDir, "recorder") + `
  signing_key_path: ` + filepath.Join(home, ".pipelock", "agents", "pipelock-official", "id_ed25519") + `
learn:
  enabled: true
  capture_dir: ` + filepath.Join(home, ".local", "share", "pipelock", "captures", "local") + `
  privacy:
    salt_source: file:` + filepath.Join(home, ".local", "share", "pipelock", "learn-salt") + `
mcp_binary_integrity:
  enabled: true
  manifest_path: ` + filepath.Join(configDir, "integrity", "manifest.json") + `
behavioral_baseline:
  enabled: true
  profile_dir: ` + filepath.Join(configDir, "baselines") + `
tls_interception:
  enabled: true
learn_lock:
  enabled: true
  store_dir: ` + filepath.Join(home, ".pipelock", "contracts", "production", "active") + `
  roster_path: ` + filepath.Join(configDir, "roster.json") + `
`)

	out, artifacts, err := migratePipelockConfigForContain(env, filepath.Join(configDir, "pipelock.yaml"), data)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	text := string(out)
	for _, forbidden := range []string{
		filepath.Join(home, ".config", "pipelock"),
		filepath.Join(home, ".pipelock"),
		filepath.Join(home, ".local", "share", "pipelock"),
		filepath.Join(home, ".local", "bin", "pipelock"),
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("migrated config still contains %s:\n%s", forbidden, text)
		}
	}
	for _, want := range []string{
		"license_file: " + filepath.Join(env.configDir, "license.token"),
		"ca_cert: " + filepath.Join(env.configDir, "tls", "ca.pem"),
		"ca_key: " + filepath.Join(env.configDir, "tls", "ca-key.pem"),
		"signing_key_path: " + filepath.Join(env.configDir, "keys", "flight-recorder-signing.key"),
		"salt_source: file:" + filepath.Join(env.configDir, "learn-privacy-salt"),
		"manifest_path: " + filepath.Join(env.configDir, "integrity", "manifest.json"),
		"roster_path: " + filepath.Join(env.configDir, "roster.json"),
		"file: " + filepath.Join(env.dataDir, "logs", "audit.log"),
		"dir: " + filepath.Join(env.dataDir, "recorder"),
		"capture_dir: " + filepath.Join(env.dataDir, "captures", "local"),
		"profile_dir: " + filepath.Join(env.dataDir, "baselines"),
		"store_dir: " + filepath.Join(env.dataDir, "contracts", "active"),
		env.pipelockTarget,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("migrated config missing %q:\n%s", want, text)
		}
	}
	for _, p := range []string{
		filepath.Join(env.configDir, "license.token"),
		filepath.Join(env.configDir, "tls", "ca.pem"),
		filepath.Join(env.configDir, "tls", "ca-key.pem"),
		filepath.Join(env.configDir, "keys", "flight-recorder-signing.key"),
		filepath.Join(env.configDir, "learn-privacy-salt"),
		filepath.Join(env.configDir, "integrity", "manifest.json"),
		filepath.Join(env.configDir, "roster.json"),
		filepath.Join(env.dataDir, "recorder", "existing.jsonl"),
		filepath.Join(env.dataDir, "captures", "local", "cap.jsonl"),
		filepath.Join(env.dataDir, "baselines", "profile.json"),
		filepath.Join(env.dataDir, "contracts", "active", "active.json"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected migrated artifact %s: %v", p, err)
		}
	}
	for _, p := range []string{
		filepath.Join(env.configDir, "learn-privacy-salt"),
		filepath.Join(env.configDir, "tls", "ca-key.pem"),
		filepath.Join(env.configDir, "keys", "flight-recorder-signing.key"),
	} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if got := info.Mode().Perm(); got != modePinSecret {
			t.Fatalf("%s mode = %s, want %s", p, got, modePinSecret)
		}
	}
	if len(artifacts) == 0 {
		t.Fatal("expected tracked migrated artifacts")
	}
}

func TestMigratePipelockConfigForContain_EmptyMappingIsNoOp(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	home := t.TempDir()
	origLookup := env.lookupUser
	env.lookupUser = func(name string) (*user.User, error) {
		if name == containInstallOperatorUser {
			return &user.User{Uid: "1000", Gid: "1000", Username: name, HomeDir: home}, nil
		}
		return origLookup(name)
	}
	out, artifacts, err := migratePipelockConfigForContain(env, filepath.Join(home, ".config", "pipelock", "pipelock.yaml"), []byte("{}\n"))
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("expected no artifacts, got %+v", artifacts)
	}
	if strings.TrimSpace(string(out)) != "{}" {
		t.Fatalf("output: %q", out)
	}
}

func TestMigratePipelockConfigForContainRejectsInvalidDocuments(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "invalid yaml", body: ":\n", want: "parse pipelock config"},
		{name: "multi document", body: "{}\n---\n{}\n", want: "single YAML document"},
		{name: "non mapping", body: "[]\n", want: "YAML mapping"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := migratePipelockConfigForContain(env, filepath.Join(t.TempDir(), "pipelock.yaml"), []byte(tc.body))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err: %v, want %q", err, tc.want)
			}
		})
	}
}

func TestMigratePipelockConfigForContain_RejectsSymlinkSource(t *testing.T) {
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
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(configDir, "real.token")
	mustWriteFile(t, target, "token\n")
	link := filepath.Join(configDir, "license.token")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, _, err := migratePipelockConfigForContain(env, filepath.Join(configDir, "pipelock.yaml"), []byte("license_file: "+link+"\n"))
	if err == nil {
		t.Fatal("expected symlink rejection")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err: %v", err)
	}
}

func TestMigratePipelockConfigForContain_RejectsSymlinkParent(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	home := t.TempDir()
	origLookup := env.lookupUser
	env.lookupUser = func(name string) (*user.User, error) {
		if name == containInstallOperatorUser {
			return &user.User{Uid: "1000", Gid: "1000", Username: name, HomeDir: home}, nil
		}
		return origLookup(name)
	}
	realConfigDir := filepath.Join(home, "real-config")
	mustWriteFile(t, filepath.Join(realConfigDir, "license.token"), "token\n")
	if err := os.Symlink(realConfigDir, filepath.Join(home, ".config")); err != nil {
		t.Fatalf("symlink parent: %v", err)
	}
	linkPath := filepath.Join(home, ".config", "license.token")
	_, _, err := migratePipelockConfigForContain(env, filepath.Join(home, "pipelock.yaml"), []byte("license_file: "+linkPath+"\n"))
	if err == nil {
		t.Fatal("expected symlink parent rejection")
	}
	if !strings.Contains(err.Error(), "symlink component") {
		t.Fatalf("err: %v", err)
	}
}

func TestMigratePipelockConfigForContain_GeneratesMissingFlightRecorderKey(t *testing.T) {
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
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	missingKey := filepath.Join(home, ".pipelock", "agents", "pipelock-official", "id_ed25519")
	out, artifacts, err := migratePipelockConfigForContain(env, filepath.Join(configDir, "pipelock.yaml"), []byte(`
flight_recorder:
  signing_key_path: "`+missingKey+`"
`))
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	dest := filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
	if !strings.Contains(string(out), dest) {
		t.Fatalf("rewritten config missing generated key path:\n%s", out)
	}
	if _, err := signing.LoadPrivateKeyFile(dest); err != nil {
		t.Fatalf("generated key invalid: %v", err)
	}
	if len(artifacts) == 0 {
		t.Fatal("expected generated key artifacts to be tracked")
	}
}

func TestCopyConfigDirCopiesNestedFiles(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	home := t.TempDir()
	src := filepath.Join(home, "rules")
	mustWriteFile(t, filepath.Join(src, "nested", "bundle.yaml"), "rules\n")
	ctx := &configMigrationContext{env: env, operatorHome: home}
	dest := filepath.Join(env.configDir, "rules")
	if err := copyConfigDir(ctx, src, dest); err != nil {
		t.Fatalf("copy dir: %v", err)
	}
	got, err := env.readFile(filepath.Join(dest, "nested", "bundle.yaml"))
	if err != nil {
		t.Fatalf("read copied: %v", err)
	}
	if string(got) != "rules\n" {
		t.Fatalf("copied content: %q", got)
	}
	if len(ctx.artifacts) == 0 {
		t.Fatal("expected copied artifacts to be tracked")
	}
}

func TestCopyConfigDirRejectsSymlinkChild(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	home := t.TempDir()
	src := filepath.Join(home, "rules")
	mustWriteFile(t, filepath.Join(src, "real.yaml"), "rules\n")
	if err := os.Symlink(filepath.Join(src, "real.yaml"), filepath.Join(src, "link.yaml")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	ctx := &configMigrationContext{env: env, operatorHome: home}
	err := copyConfigDir(ctx, src, filepath.Join(env.configDir, "rules"))
	if err == nil {
		t.Fatal("expected symlink child rejection")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err: %v", err)
	}
}

func TestEnsureMigratedDirRejectsSymlinkTarget(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.MkdirAll(target, 0o750); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	ctx := &configMigrationContext{env: env}
	err := ensureMigratedDir(ctx, link, modeDirPrivate)
	if err == nil {
		t.Fatal("expected symlink target rejection")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err: %v", err)
	}
}

func TestEnsureMigratedDirRejectsSymlinkParent(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	root := t.TempDir()
	realParent := filepath.Join(root, "real-parent")
	if err := os.MkdirAll(realParent, 0o750); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	linkParent := filepath.Join(root, "link-parent")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	ctx := &configMigrationContext{env: env}
	err := ensureMigratedDir(ctx, filepath.Join(linkParent, "child"), modeDirPrivate)
	if err == nil {
		t.Fatal("expected symlink parent rejection")
	}
	if !strings.Contains(err.Error(), "symlink parent") {
		t.Fatalf("err: %v", err)
	}
}

func TestCleanupMigratedConfigArtifactsRestoresFilesAndKeepsNonEmptyDirs(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	root := t.TempDir()
	filePath := filepath.Join(root, "migrated-token")
	if err := os.WriteFile(filePath, []byte("new"), 0o600); err != nil {
		t.Fatalf("write current: %v", err)
	}
	if err := os.WriteFile(filePath+".bak", []byte("old"), 0o600); err != nil {
		t.Fatalf("write backup: %v", err)
	}
	nonEmptyDir := filepath.Join(root, "dir")
	if err := os.MkdirAll(nonEmptyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nonEmptyDir, "kept"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write child: %v", err)
	}

	err := cleanupMigratedConfigArtifacts(env, []migratedConfigArtifact{
		{path: filePath},
		{path: nonEmptyDir, dir: true},
	})
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	got, err := env.readFile(filePath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(got) != "old" {
		t.Fatalf("restored file: got %q, want old", got)
	}
	if _, err := os.Stat(nonEmptyDir); err != nil {
		t.Fatalf("non-empty dir should remain: %v", err)
	}
}

func TestIsDirectoryNotEmpty(t *testing.T) {
	if isDirectoryNotEmpty(nil) {
		t.Fatal("nil must not report directory-not-empty")
	}
	if isDirectoryNotEmpty(os.ErrInvalid) {
		t.Fatal("unrelated errors must not report directory-not-empty")
	}
	if !isDirectoryNotEmpty(&os.PathError{Op: "remove", Path: "/tmp/x", Err: stringError("directory not empty")}) {
		t.Fatal("expected directory-not-empty message to match")
	}
}

type stringError string

func (e stringError) Error() string { return string(e) }

func TestMigratePipelockConfigForContain_SkipsIdenticalArtifactWrite(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	home := t.TempDir()
	origLookup := env.lookupUser
	env.lookupUser = func(name string) (*user.User, error) {
		if name == containInstallOperatorUser {
			return &user.User{Uid: "1000", Gid: "1000", Username: name, HomeDir: home}, nil
		}
		return origLookup(name)
	}
	src := filepath.Join(home, ".config", "pipelock", "license.token")
	dst := filepath.Join(env.configDir, "license.token")
	mustWriteFile(t, src, "same\n")
	mustWriteFile(t, dst, "same\n")

	_, artifacts, err := migratePipelockConfigForContain(env, filepath.Join(home, ".config", "pipelock", "pipelock.yaml"), []byte("license_file: "+src+"\n"))
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("expected no artifacts for identical migrated file, got %#v", artifacts)
	}
	if _, err := os.Stat(dst + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("expected no backup for identical migrated file, stat err=%v", err)
	}
}

func TestMigratePipelockConfigForContain_GeneratesMissingFlightRecorderSigningKey(t *testing.T) {
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
	missingKey := filepath.Join(home, ".pipelock", "agents", "pipelock-official", "id_ed25519")
	data := []byte(`
flight_recorder:
  enabled: true
  signing_key_path: ` + missingKey + `
`)

	out, artifacts, err := migratePipelockConfigForContain(env, filepath.Join(configDir, "pipelock.yaml"), data)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	dest := filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
	text := string(out)
	if strings.Contains(text, missingKey) {
		t.Fatalf("migrated config still references missing home key:\n%s", text)
	}
	if !strings.Contains(text, "signing_key_path: "+dest) {
		t.Fatalf("migrated config missing generated signing key path %q:\n%s", dest, text)
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat generated key: %v", err)
	}
	if got := info.Mode().Perm(); got != modePinSecret {
		t.Fatalf("generated key mode = %s, want %s", got, modePinSecret)
	}
	if _, err := signing.LoadPrivateKeyFile(dest); err != nil {
		t.Fatalf("load generated key: %v", err)
	}
	if len(artifacts) == 0 {
		t.Fatal("expected generated key artifact to be tracked")
	}
}

func mustWriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustWriteSigningKey(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, path); err != nil {
		t.Fatalf("write signing key %s: %v", path, err)
	}
}
