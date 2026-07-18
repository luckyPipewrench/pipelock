// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialGuardFilesystemFailuresAbortActivation(t *testing.T) {
	t.Run("operator lookup", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.lookupUser = func(name string) (*user.User, error) {
			return nil, user.UnknownUserError(name)
		}
		applied, err := stepWriteCredentialGuard().apply(context.Background(), env)
		if err == nil || applied || !strings.Contains(err.Error(), "lookup operator user") {
			t.Fatalf("applied = %v, error = %v", applied, err)
		}
	})

	t.Run("parent mkdir", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.mkdirAll = func(string, os.FileMode) error { return os.ErrPermission }
		applied, err := stepWriteCredentialGuard().apply(context.Background(), env)
		if err == nil || applied || !strings.Contains(err.Error(), "mkdir") {
			t.Fatalf("applied = %v, error = %v", applied, err)
		}
	})

	t.Run("parent chmod", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.chmod = func(string, os.FileMode) error { return os.ErrPermission }
		applied, err := stepWriteCredentialGuard().apply(context.Background(), env)
		if err == nil || applied || !strings.Contains(err.Error(), "chmod") {
			t.Fatalf("applied = %v, error = %v", applied, err)
		}
	})

	t.Run("unchanged file chmod", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		operator, err := env.lookupUser(env.operatorUser)
		if err != nil {
			t.Fatalf("lookup operator: %v", err)
		}
		body := renderCredentialGuardScript(env.agentUserName, operator.HomeDir, env.bashPath)
		mustWriteFile(t, env.guardScriptPath, body)
		originalChmod := env.chmod
		env.chmod = func(path string, mode os.FileMode) error {
			if path == env.guardScriptPath {
				return os.ErrPermission
			}
			return originalChmod(path, mode)
		}
		applied, err := stepWriteCredentialGuard().apply(context.Background(), env)
		if err == nil || applied || !strings.Contains(err.Error(), "chmod") {
			t.Fatalf("applied = %v, error = %v", applied, err)
		}
	})

	t.Run("file write", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.writeFile = func(string, []byte, os.FileMode) error { return os.ErrPermission }
		applied, err := stepWriteCredentialGuard().apply(context.Background(), env)
		if err == nil || applied || !strings.Contains(err.Error(), "write") {
			t.Fatalf("applied = %v, error = %v", applied, err)
		}
	})
}

func TestCredentialGuardProcessFailuresRemainAppliedForRollback(t *testing.T) {
	tests := []struct {
		name      string
		failName  string
		failArg   string
		startFail bool
		want      string
	}{
		{name: "guard startup", failName: "guard", startFail: true, want: "permission denied"},
		{name: "daemon reload startup", failName: "systemctl", failArg: "daemon-reload", startFail: true, want: "daemon-reload"},
		{name: "daemon reload exit", failName: "systemctl", failArg: "daemon-reload", want: "exit 19"},
		{name: "enable startup", failName: "systemctl", failArg: "enable", startFail: true, want: "systemctl enable"},
		{name: "enable exit", failName: "systemctl", failArg: "enable", want: "exit 19"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
				matches := tc.failName == "guard" && name == env.guardScriptPath
				if tc.failName == "systemctl" && name == "systemctl" && len(args) > 0 && args[0] == tc.failArg {
					matches = true
				}
				if !matches {
					return "", 0, nil
				}
				if tc.startFail {
					return "", -1, os.ErrPermission
				}
				return "service manager rejected request", 19, nil
			}
			applied, err := stepWriteCredentialGuard().apply(context.Background(), env)
			if err == nil || !applied || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("applied = %v, error = %v, want containing %q", applied, err, tc.want)
			}
		})
	}
}

func TestCreateDirectoryFailuresDoNotReportSuccess(t *testing.T) {
	t.Run("existing chmod", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		path := filepath.Join(t.TempDir(), "existing")
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		env.chmod = func(string, os.FileMode) error { return os.ErrPermission }
		applied, err := stepCreateDir("test", func(*installEnv) string { return path }, modeDirPrivate).apply(context.Background(), env)
		if err == nil || applied || !strings.Contains(err.Error(), "chmod") {
			t.Fatalf("applied = %v, error = %v", applied, err)
		}
	})

	t.Run("stat denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
		applied, err := stepCreateDir("test", func(*installEnv) string { return "/managed/data" }, modeDirPrivate).apply(context.Background(), env)
		if err == nil || applied || !strings.Contains(err.Error(), "stat") {
			t.Fatalf("applied = %v, error = %v", applied, err)
		}
	})

	t.Run("mkdir denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		path := filepath.Join(t.TempDir(), "new")
		env.mkdirAll = func(string, os.FileMode) error { return os.ErrPermission }
		applied, err := stepCreateDir("test", func(*installEnv) string { return path }, modeDirPrivate).apply(context.Background(), env)
		if err == nil || applied || !strings.Contains(err.Error(), "mkdir") {
			t.Fatalf("applied = %v, error = %v", applied, err)
		}
	})

	t.Run("new chmod denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		path := filepath.Join(t.TempDir(), "new")
		env.chmod = func(string, os.FileMode) error { return os.ErrPermission }
		applied, err := stepCreateDir("test", func(*installEnv) string { return path }, modeDirPrivate).apply(context.Background(), env)
		if err == nil || applied || !strings.Contains(err.Error(), "chmod") {
			t.Fatalf("applied = %v, error = %v", applied, err)
		}
	})
}

func TestToolsListWriteFailuresPreservePolicyBoundary(t *testing.T) {
	t.Run("mkdir denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.mkdirAll = func(string, os.FileMode) error { return os.ErrPermission }
		err := writeToolsList(env, []toolsListEntry{{name: "tool", target: "/usr/bin/tool"}})
		if err == nil || !strings.Contains(err.Error(), "mkdir") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("chmod denied", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.chmod = func(string, os.FileMode) error { return os.ErrPermission }
		err := writeToolsList(env, []toolsListEntry{{name: "tool", target: "/usr/bin/tool"}})
		if err == nil || !strings.Contains(err.Error(), "chmod") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("step has no executable defaults", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
		applied, err := stepWriteToolsList().apply(context.Background(), env)
		if err == nil || applied || !strings.Contains(err.Error(), "no default agent tools") {
			t.Fatalf("applied = %v, error = %v", applied, err)
		}
	})
}

func TestWrapperInventoryRejectsIncompleteOrUnreadableInputs(t *testing.T) {
	validTools := "tool\t/usr/bin/tool\n"
	tests := []struct {
		name  string
		setup func(*installEnv)
		want  string
	}{
		{
			name: "parent mkdir",
			setup: func(env *installEnv) {
				env.mkdirAll = func(string, os.FileMode) error { return os.ErrPermission }
			},
			want: "mkdir",
		},
		{
			name: "parent chmod",
			setup: func(env *installEnv) {
				env.chmod = func(string, os.FileMode) error { return os.ErrPermission }
			},
			want: "chmod",
		},
		{
			name: "tools list unreadable",
			setup: func(env *installEnv) {
				env.readFile = func(path string) ([]byte, error) {
					if path == env.toolsListPath {
						return nil, os.ErrPermission
					}
					return os.ReadFile(filepath.Clean(path))
				}
			},
			want: "read tools.list",
		},
		{
			name: "inventory unreadable",
			setup: func(env *installEnv) {
				env.readFile = func(path string) ([]byte, error) {
					switch path {
					case env.toolsListPath:
						return []byte(validTools), nil
					case env.wrapperInvPath:
						return nil, os.ErrPermission
					default:
						return os.ReadFile(filepath.Clean(path))
					}
				}
			},
			want: "read wrapper inventory",
		},
		{
			name: "inventory malformed",
			setup: func(env *installEnv) {
				env.readFile = func(path string) ([]byte, error) {
					switch path {
					case env.toolsListPath:
						return []byte(validTools), nil
					case env.wrapperInvPath:
						return []byte("{"), nil
					default:
						return os.ReadFile(filepath.Clean(path))
					}
				}
			},
			want: "parse wrapper inventory",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			mustWriteFile(t, env.toolsListPath, validTools)
			tc.setup(env)
			applied, err := stepWriteWrapperInventory().apply(context.Background(), env)
			if err == nil || applied || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("applied = %v, error = %v, want containing %q", applied, err, tc.want)
			}
		})
	}
}

func TestRollbackPathRemovalContinuesPastAbsentBackup(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "managed")
	var removed []string
	env.removeFile = func(candidate string) error {
		removed = append(removed, candidate)
		if candidate == path {
			return os.ErrNotExist
		}
		return nil
	}
	err := actionRemovePath("managed file", func(*installEnv) string { return path }).undo(context.Background(), env)
	if err != nil {
		t.Fatalf("remove absent path: %v", err)
	}
	if len(removed) != 2 || removed[1] != path+".bak" {
		t.Fatalf("removed paths = %v, want path and backup", removed)
	}
}

func TestRollbackPathRemovalSurfacesPermissionFailure(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.removeFile = func(string) error { return os.ErrPermission }
	err := actionRemovePath("managed file", func(*installEnv) string { return "/managed/file" }).undo(context.Background(), env)
	if err == nil || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("error = %v, want permission failure", err)
	}
}
