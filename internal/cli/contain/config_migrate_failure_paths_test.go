// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExistingSigningKeyFailuresStopMigration(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *installEnv, string)
		want  string
	}{
		{
			name: "symlink target",
			setup: func(t *testing.T, _ *installEnv, dest string) {
				t.Helper()
				targetKey := filepath.Join(t.TempDir(), "real.key")
				mustWriteSigningKey(t, targetKey)
				if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
					t.Fatalf("mkdir key dir: %v", err)
				}
				if err := os.Symlink(targetKey, dest); err != nil {
					t.Fatalf("symlink key: %v", err)
				}
			},
			want: "is a symlink",
		},
		{
			name: "directory target",
			setup: func(t *testing.T, _ *installEnv, dest string) {
				t.Helper()
				if err := os.MkdirAll(dest, 0o750); err != nil {
					t.Fatalf("mkdir key target: %v", err)
				}
			},
			want: "not a regular file",
		},
		{
			name: "chmod denied",
			setup: func(t *testing.T, env *installEnv, dest string) {
				t.Helper()
				mustWriteSigningKey(t, dest)
				env.chmod = func(string, os.FileMode) error { return os.ErrPermission }
			},
			want: "chmod",
		},
		{
			name: "invalid key",
			setup: func(t *testing.T, _ *installEnv, dest string) {
				t.Helper()
				mustWriteFile(t, dest, "not a private key\n")
			},
			want: "validate existing signing key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			dest := filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
			tc.setup(t, env, dest)
			ctx := &configMigrationContext{env: env}
			err := ensureFlightRecorderSigningKeyWithRecovery(ctx, dest, "")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}

	t.Run("stat denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		dest := filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
		env.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
		ctx := &configMigrationContext{env: env}
		err := ensureFlightRecorderSigningKeyWithRecovery(ctx, dest, "")
		if err == nil || !strings.Contains(err.Error(), "stat existing target") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("public sidecar write denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		dest := filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
		mustWriteSigningKey(t, dest)
		env.writeFile = func(string, []byte, os.FileMode) error { return os.ErrPermission }
		ctx := &configMigrationContext{env: env}
		err := ensureFlightRecorderSigningKeyWithRecovery(ctx, dest, "")
		if err == nil || !strings.Contains(err.Error(), "write public signing key") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestRecoverSigningKeyHardFailuresAreNotRegeneratedAway(t *testing.T) {
	t.Run("source stat denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		ctx := &configMigrationContext{env: env}
		env.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
		recovered, err := recoverExistingSigningKey(ctx, "/operator/key", "/managed/key")
		if err == nil || recovered || !strings.Contains(err.Error(), "stat recovery source") {
			t.Fatalf("recovered = %v, error = %v", recovered, err)
		}
	})

	t.Run("destination write denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		src := filepath.Join(t.TempDir(), "operator.key")
		mustWriteSigningKey(t, src)
		dest := filepath.Join(env.configDir, "keys", "flight-recorder-signing.key")
		env.writeFile = func(string, []byte, os.FileMode) error { return os.ErrPermission }
		ctx := &configMigrationContext{env: env}
		recovered, err := recoverExistingSigningKey(ctx, src, dest)
		if err == nil || recovered || !strings.Contains(err.Error(), "recover signing key") {
			t.Fatalf("recovered = %v, error = %v", recovered, err)
		}
	})
}

func TestBackupAndWriteIfChangedRejectsUnsafeExistingState(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		targetPath := filepath.Join(t.TempDir(), "real")
		mustWriteFile(t, targetPath, "old\n")
		target := filepath.Join(t.TempDir(), "target")
		if err := os.Symlink(targetPath, target); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		wrote, err := backupAndWriteIfChanged(env, target, []byte("new\n"), 0o600)
		if err == nil || wrote || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("wrote = %v, error = %v", wrote, err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		target := t.TempDir()
		wrote, err := backupAndWriteIfChanged(env, target, []byte("new\n"), 0o600)
		if err == nil || wrote || !strings.Contains(err.Error(), "is a directory") {
			t.Fatalf("wrote = %v, error = %v", wrote, err)
		}
	})

	t.Run("stat denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
		wrote, err := backupAndWriteIfChanged(env, "/managed/file", []byte("new\n"), 0o600)
		if err == nil || wrote || !strings.Contains(err.Error(), "stat existing") {
			t.Fatalf("wrote = %v, error = %v", wrote, err)
		}
	})

	t.Run("same contents chmod denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		target := filepath.Join(t.TempDir(), "target")
		mustWriteFile(t, target, "same\n")
		env.chmod = func(string, os.FileMode) error { return os.ErrPermission }
		wrote, err := backupAndWriteIfChanged(env, target, []byte("same\n"), 0o600)
		if err == nil || wrote || !strings.Contains(err.Error(), "chmod") {
			t.Fatalf("wrote = %v, error = %v", wrote, err)
		}
	})

	t.Run("read denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		target := filepath.Join(t.TempDir(), "target")
		mustWriteFile(t, target, "old\n")
		env.readFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
		wrote, err := backupAndWriteIfChanged(env, target, []byte("new\n"), 0o600)
		if err == nil || wrote || !strings.Contains(err.Error(), "read existing") {
			t.Fatalf("wrote = %v, error = %v", wrote, err)
		}
	})
}

func TestEnsureMigratedDirReportsFilesystemFailures(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *installEnv, string)
		want  string
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, _ *installEnv, path string) {
				t.Helper()
				if err := os.Symlink(t.TempDir(), path); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
			want: "is a symlink",
		},
		{
			name: "regular file",
			setup: func(t *testing.T, _ *installEnv, path string) {
				t.Helper()
				mustWriteFile(t, path, "occupied\n")
			},
			want: "not a directory",
		},
		{
			name: "existing chmod denied",
			setup: func(t *testing.T, env *installEnv, path string) {
				t.Helper()
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				env.chmod = func(string, os.FileMode) error { return os.ErrPermission }
			},
			want: "permission denied",
		},
		{
			name: "mkdir denied",
			setup: func(t *testing.T, env *installEnv, _ string) {
				t.Helper()
				env.mkdirAll = func(string, os.FileMode) error { return os.ErrPermission }
			},
			want: "mkdir",
		},
		{
			name: "new chmod denied",
			setup: func(t *testing.T, env *installEnv, _ string) {
				t.Helper()
				env.chmod = func(string, os.FileMode) error { return os.ErrPermission }
			},
			want: "chmod",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			path := filepath.Join(env.configDir, "keys")
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatalf("mkdir parent: %v", err)
			}
			tc.setup(t, env, path)
			ctx := &configMigrationContext{env: env}
			err := ensureMigratedDir(ctx, path, modeDirPrivate)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}

	t.Run("stat denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
		ctx := &configMigrationContext{env: env}
		err := ensureMigratedDir(ctx, filepath.Join(env.configDir, "keys"), modeDirPrivate)
		if err == nil || !strings.Contains(err.Error(), "stat") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestCopyConfigDirRejectsUntrustedSourceKinds(t *testing.T) {
	t.Run("stat denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
		ctx := &configMigrationContext{env: env}
		err := copyConfigDir(ctx, "/operator/rules", filepath.Join(env.dataDir, "rules"))
		if err == nil || !strings.Contains(err.Error(), "stat source") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		targetDir := t.TempDir()
		src := filepath.Join(t.TempDir(), "rules")
		if err := os.Symlink(targetDir, src); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		ctx := &configMigrationContext{env: env}
		err := copyConfigDir(ctx, src, filepath.Join(env.dataDir, "rules"))
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("regular file", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		src := filepath.Join(t.TempDir(), "rules")
		mustWriteFile(t, src, "not a directory\n")
		ctx := &configMigrationContext{env: env}
		err := copyConfigDir(ctx, src, filepath.Join(env.dataDir, "rules"))
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestCleanupMigrationIgnoresExpectedDirectoryStates(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.removeFile = func(path string) error {
		switch filepath.Base(path) {
		case "missing":
			return os.ErrNotExist
		case "occupied":
			return errors.New("directory not empty")
		default:
			return nil
		}
	}
	err := cleanupMigratedConfigArtifacts(env, []migratedConfigArtifact{
		{path: "/tmp/missing", dir: true},
		{path: "/tmp/occupied", dir: true},
	})
	if err != nil {
		t.Fatalf("cleanup expected states: %v", err)
	}
}
