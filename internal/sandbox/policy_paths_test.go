// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// protectedHomeNames mirrors the candidates secretDirs derives from HOME.
var protectedHomeNames = []string{
	".ssh",
	".aws",
	filepath.Join(".config", "pipelock"),
	".gnupg",
	".kube",
	".docker",
}

// newProtectedHome points HOME at a fresh directory holding every protected
// candidate, so the secret-directory checks run on every host instead of
// depending on what the developer or CI runner happens to have in HOME. It
// returns HOME with symlinks resolved, the form ValidatePolicy compares.
func newProtectedHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, name := range protectedHomeNames {
		mustMkdirAll(t, filepath.Join(home, name))
	}
	resolved, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatalf("resolve test HOME: %v", err)
	}
	return resolved
}

func mustMkdirAll(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	return dir
}

func mustWriteFile(t *testing.T, path string) string {
	t.Helper()
	mustMkdirAll(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func mustSymlink(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, target, err)
	}
	return link
}

// TestValidatePolicyRejectsAllowFilesInsideProtectedDirs exercises the file
// allowlist check with real files, so the rejection comes from the
// protected-directory comparison rather than from the path being missing.
func TestValidatePolicyRejectsAllowFilesInsideProtectedDirs(t *testing.T) {
	home := newProtectedHome(t)
	outside := t.TempDir()
	workspace := t.TempDir()

	tests := []struct {
		name string
		// apply adds the allow entry under test to a policy.
		apply func(t *testing.T, p *Policy)
		// wantLabel and wantProtected name the rejected list and the
		// protected directory; both empty means the policy must be accepted.
		wantLabel     string
		wantProtected string
	}{
		{
			name: "read file inside ssh",
			apply: func(t *testing.T, p *Policy) {
				p.AllowReadFiles = append(p.AllowReadFiles, mustWriteFile(t, filepath.Join(home, ".ssh", "id_vendor")))
			},
			wantLabel:     "allow_read_file",
			wantProtected: filepath.Join(home, ".ssh"),
		},
		{
			name: "write file inside aws",
			apply: func(t *testing.T, p *Policy) {
				p.AllowRWFiles = append(p.AllowRWFiles, mustWriteFile(t, filepath.Join(home, ".aws", "credentials")))
			},
			wantLabel:     "allow_write_file",
			wantProtected: filepath.Join(home, ".aws"),
		},
		{
			name: "read file nested inside pipelock config",
			apply: func(t *testing.T, p *Policy) {
				p.AllowReadFiles = append(p.AllowReadFiles, mustWriteFile(t, filepath.Join(home, ".config", "pipelock", "keys", "signing.key")))
			},
			wantLabel:     "allow_read_file",
			wantProtected: filepath.Join(home, ".config", "pipelock"),
		},
		{
			name: "read file through symlink into kube",
			apply: func(t *testing.T, p *Policy) {
				target := mustWriteFile(t, filepath.Join(home, ".kube", "config"))
				p.AllowReadFiles = append(p.AllowReadFiles, mustSymlink(t, target, filepath.Join(outside, "kubeconfig-link")))
			},
			wantLabel:     "allow_read_file",
			wantProtected: filepath.Join(home, ".kube"),
		},
		{
			name: "write file through symlink into docker",
			apply: func(t *testing.T, p *Policy) {
				target := mustWriteFile(t, filepath.Join(home, ".docker", "config.json"))
				p.AllowRWFiles = append(p.AllowRWFiles, mustSymlink(t, target, filepath.Join(outside, "docker-link")))
			},
			wantLabel:     "allow_write_file",
			wantProtected: filepath.Join(home, ".docker"),
		},
		{
			name: "read file in sibling sharing the protected prefix",
			apply: func(t *testing.T, p *Policy) {
				p.AllowReadFiles = append(p.AllowReadFiles, mustWriteFile(t, filepath.Join(home, ".ssh-notes", "readme.txt")))
			},
		},
		{
			name: "write file directly in home",
			apply: func(t *testing.T, p *Policy) {
				p.AllowRWFiles = append(p.AllowRWFiles, mustWriteFile(t, filepath.Join(home, ".vendorrc")))
			},
		},
		{
			name: "read file through symlink that stays outside protected dirs",
			apply: func(t *testing.T, p *Policy) {
				target := mustWriteFile(t, filepath.Join(outside, "real", "settings.json"))
				p.AllowReadFiles = append(p.AllowReadFiles, mustSymlink(t, target, filepath.Join(outside, "settings-link")))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Policy{Workspace: workspace, AllowRWDirs: []string{workspace}}
			tt.apply(t, &p)
			err := ValidatePolicy(p)
			if tt.wantLabel == "" {
				if err != nil {
					t.Fatalf("ValidatePolicy() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidatePolicy() = nil, want %s rejected inside %s", tt.wantLabel, tt.wantProtected)
			}
			want := fmt.Sprintf("is inside protected directory %q", tt.wantProtected)
			if !strings.Contains(err.Error(), "sandbox "+tt.wantLabel+" ") || !strings.Contains(err.Error(), want) {
				t.Fatalf("ValidatePolicy() = %v, want %s error containing %s", err, tt.wantLabel, want)
			}
		})
	}
}

// TestValidatePolicyRejectsAllowDirsCoveringProtectedDirs runs the directory
// checks against a controlled HOME so they never skip for lack of real
// secret directories on the host.
func TestValidatePolicyRejectsAllowDirsCoveringProtectedDirs(t *testing.T) {
	home := newProtectedHome(t)
	outside := t.TempDir()
	workspace := t.TempDir()

	tests := []struct {
		name      string
		apply     func(t *testing.T, p *Policy)
		wantLabel string
	}{
		{
			name: "read dir equal to home",
			apply: func(_ *testing.T, p *Policy) {
				p.AllowReadDirs = append(p.AllowReadDirs, home)
			},
			wantLabel: "allow_read",
		},
		{
			name: "write dir equal to gnupg",
			apply: func(_ *testing.T, p *Policy) {
				p.AllowRWDirs = append(p.AllowRWDirs, filepath.Join(home, ".gnupg"))
			},
			wantLabel: "allow_write",
		},
		{
			name: "read dir that is a parent of pipelock config",
			apply: func(_ *testing.T, p *Policy) {
				p.AllowReadDirs = append(p.AllowReadDirs, filepath.Join(home, ".config"))
			},
			wantLabel: "allow_read",
		},
		{
			name: "read dir through symlink to ssh",
			apply: func(t *testing.T, p *Policy) {
				p.AllowReadDirs = append(p.AllowReadDirs, mustSymlink(t, filepath.Join(home, ".ssh"), filepath.Join(outside, "ssh-link")))
			},
			wantLabel: "allow_read",
		},
		{
			name: "read dir in sibling sharing the protected prefix",
			apply: func(t *testing.T, p *Policy) {
				p.AllowReadDirs = append(p.AllowReadDirs, mustMkdirAll(t, filepath.Join(home, ".ssh-notes")))
			},
		},
		{
			name: "read dir whose name is a prefix of a protected dir",
			apply: func(t *testing.T, p *Policy) {
				p.AllowReadDirs = append(p.AllowReadDirs, mustMkdirAll(t, filepath.Join(home, ".dock")))
			},
		},
		{
			name: "write dir under home outside protected dirs",
			apply: func(t *testing.T, p *Policy) {
				p.AllowRWDirs = append(p.AllowRWDirs, mustMkdirAll(t, filepath.Join(home, "src", "project")))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Policy{Workspace: workspace, AllowRWDirs: []string{workspace}}
			tt.apply(t, &p)
			err := ValidatePolicy(p)
			if tt.wantLabel == "" {
				if err != nil {
					t.Fatalf("ValidatePolicy() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidatePolicy() = nil, want %s rejected", tt.wantLabel)
			}
			if !strings.Contains(err.Error(), "sandbox "+tt.wantLabel+" ") || !strings.Contains(err.Error(), "covers protected directory") {
				t.Fatalf("ValidatePolicy() = %v, want %s covers-protected error", err, tt.wantLabel)
			}
		})
	}
}

// TestResolvePolicyPathsRejectsUnusableAllowPaths pins the fail-closed
// resolution of every allow list: a grant must name an existing path of the
// right kind, because Landlock resolves the path when the rule is added.
func TestResolvePolicyPathsRejectsUnusableAllowPaths(t *testing.T) {
	base := t.TempDir()
	dir := mustMkdirAll(t, filepath.Join(base, "dir"))
	file := mustWriteFile(t, filepath.Join(base, "file"))
	missing := filepath.Join(base, "missing")
	underFile := filepath.Join(file, "child")
	dangling := mustSymlink(t, missing, filepath.Join(base, "dangling"))

	tests := []struct {
		name    string
		policy  Policy
		wantErr string
	}{
		{name: "all kinds valid", policy: Policy{
			Workspace: dir, AllowReadDirs: []string{dir}, AllowRWDirs: []string{dir},
			AllowReadFiles: []string{file}, AllowRWFiles: []string{file},
		}},
		{name: "workspace missing", policy: Policy{Workspace: missing}, wantErr: "sandbox workspace path does not exist"},
		{name: "workspace is a file", policy: Policy{Workspace: file}, wantErr: "sandbox workspace path is not a directory"},
		{name: "read dir is a file", policy: Policy{AllowReadDirs: []string{file}}, wantErr: "sandbox allow_read path is not a directory"},
		{name: "read dir is a dangling symlink", policy: Policy{AllowReadDirs: []string{dangling}}, wantErr: "sandbox allow_read path does not exist"},
		{name: "read dir below a file", policy: Policy{AllowReadDirs: []string{underFile}}, wantErr: "resolve sandbox allow_read path"},
		{name: "write dir missing", policy: Policy{AllowRWDirs: []string{missing}}, wantErr: "sandbox allow_write path does not exist"},
		{name: "write dir is a file", policy: Policy{AllowRWDirs: []string{file}}, wantErr: "sandbox allow_write path is not a directory"},
		{name: "read file is a dir", policy: Policy{AllowReadFiles: []string{dir}}, wantErr: "sandbox allow_read_file path is not a file"},
		{name: "write file is a dir", policy: Policy{AllowRWFiles: []string{dir}}, wantErr: "sandbox allow_write_file path is not a file"},
		{name: "write file missing", policy: Policy{AllowRWFiles: []string{missing}}, wantErr: "sandbox allow_write_file path does not exist"},
		{name: "valid entry does not mask a later bad one", policy: Policy{AllowReadDirs: []string{dir, file}}, wantErr: "sandbox allow_read path is not a directory"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolvePolicyPaths(tt.policy)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ResolvePolicyPaths() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ResolvePolicyPaths() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestValidatePolicyRejectsUnresolvablePathsWithoutSecretDirs proves path
// resolution still fails closed when HOME holds no protected directory, the
// case where the overlap checks have nothing to compare.
func TestValidatePolicyRejectsUnresolvablePathsWithoutSecretDirs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	workspace := t.TempDir()
	tests := []struct {
		name    string
		extra   string
		wantErr bool
	}{
		{name: "existing dir accepted", extra: mustMkdirAll(t, filepath.Join(t.TempDir(), "tool"))},
		{name: "missing dir rejected", extra: filepath.Join(workspace, "not-created"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePolicy(Policy{Workspace: workspace, AllowReadDirs: []string{tt.extra}})
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("ValidatePolicy() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "sandbox allow_read path does not exist") {
				t.Fatalf("ValidatePolicy() = %v, want missing allow_read rejected", err)
			}
		})
	}
}

// TestResolvePolicyPathsCanonicalizes checks the values a successful
// resolution hands to Landlock and to the overlap checks.
func TestResolvePolicyPathsCanonicalizes(t *testing.T) {
	base := t.TempDir()
	realDir := mustMkdirAll(t, filepath.Join(base, "real"))
	resolvedReal, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatalf("resolve fixture dir: %v", err)
	}
	link := mustSymlink(t, realDir, filepath.Join(base, "link"))
	missingDeny := filepath.Join(base, "gone", "..", "deny-missing")

	got, err := ResolvePolicyPaths(Policy{
		Workspace:     link,
		AllowReadDirs: []string{"/proc/self/", link},
		DenyReadDirs:  []string{link, missingDeny},
	})
	if err != nil {
		t.Fatalf("ResolvePolicyPaths() = %v", err)
	}

	checks := []struct {
		name string
		got  []string
		want []string
	}{
		{name: "workspace", got: []string{got.Workspace}, want: []string{resolvedReal}},
		{name: "allow_read", got: got.AllowReadDirs, want: []string{"/proc/self", resolvedReal}},
		// Deny entries are resolved when possible and kept, cleaned, when
		// not: a missing deny entry must never be dropped from the policy.
		{name: "deny_read", got: got.DenyReadDirs, want: []string{resolvedReal, filepath.Join(base, "deny-missing")}},
	}
	for _, c := range checks {
		if strings.Join(c.got, "\n") != strings.Join(c.want, "\n") {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}

	// The /proc/self shortcut applies to directory grants only.
	if _, err := ResolvePolicyPaths(Policy{AllowReadFiles: []string{"/proc/self"}}); err == nil || !strings.Contains(err.Error(), "allow_read_file") {
		t.Fatalf("ResolvePolicyPaths(/proc/self as file) = %v, want allow_read_file error", err)
	}
}
