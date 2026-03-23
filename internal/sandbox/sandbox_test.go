// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateWorkspace_RejectsHome(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	err := ValidateWorkspace(home)
	if err == nil {
		t.Error("expected error for HOME as workspace")
	}
}

func TestValidateWorkspace_RejectsRoot(t *testing.T) {
	err := ValidateWorkspace("/")
	if err == nil {
		t.Error("expected error for / as workspace")
	}
}

func TestValidateWorkspace_RejectsTmp(t *testing.T) {
	err := ValidateWorkspace("/tmp")
	if err == nil {
		t.Error("expected error for /tmp as workspace")
	}
}

func TestValidateWorkspace_RejectsBroadAncestors(t *testing.T) {
	for _, p := range []string{"/home", "/etc", "/usr", "/var"} {
		if _, err := os.Stat(p); err != nil {
			continue // skip if path doesn't exist on this system
		}
		err := ValidateWorkspace(p)
		if err == nil {
			t.Errorf("expected error for broad ancestor %s as workspace", p)
		}
	}
}

func TestValidateWorkspace_RejectsNonexistent(t *testing.T) {
	err := ValidateWorkspace("/nonexistent/path/that/should/not/exist")
	if err == nil {
		t.Error("expected error for nonexistent workspace")
	}
}

func TestValidateWorkspace_RejectsEmpty(t *testing.T) {
	err := ValidateWorkspace("")
	if err == nil {
		t.Error("expected error for empty workspace")
	}
}

func TestValidateWorkspace_RejectsFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "notadir-*")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	err = ValidateWorkspace(f.Name())
	if err == nil {
		t.Error("expected error for file as workspace")
	}
}

func TestValidateWorkspace_RejectsSymlinkToHome(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "sneaky")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}

	err := ValidateWorkspace(link)
	if err == nil {
		t.Error("expected error for symlink pointing to HOME")
	}
}

func TestValidateWorkspace_AcceptsValidDir(t *testing.T) {
	dir := t.TempDir()
	err := ValidateWorkspace(dir)
	if err != nil {
		t.Errorf("unexpected error for valid workspace: %v", err)
	}
}

func TestValidateWorkspace_AcceptsSubdirOfTmp(t *testing.T) {
	dir := t.TempDir() // creates /tmp/TestXXX which is a subdir of /tmp
	err := ValidateWorkspace(dir)
	if err != nil {
		t.Errorf("unexpected error for /tmp subdirectory: %v", err)
	}
}

func TestDefaultPolicy_HasRequiredPaths(t *testing.T) {
	dir := t.TempDir()
	p := DefaultPolicy(dir)

	if p.Workspace != dir {
		t.Errorf("workspace = %q, want %q", p.Workspace, dir)
	}

	// Check that critical paths are present.
	assertContains(t, "AllowReadDirs", p.AllowReadDirs, "/usr/")
	assertContains(t, "AllowReadFiles", p.AllowReadFiles, "/etc/resolv.conf")
	assertContains(t, "AllowReadFiles", p.AllowReadFiles, "/etc/passwd")
	assertContains(t, "AllowRWDirs", p.AllowRWDirs, dir)
	// /tmp/ is NOT in the default policy — child adds its sandbox dir dynamically.
	assertNotContains(t, "AllowRWDirs", p.AllowRWDirs, "/tmp/")
	assertContains(t, "AllowRWFiles", p.AllowRWFiles, "/dev/null")
}

func TestDefaultPolicy_DeniesSecretDirs(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)
	dir := t.TempDir()
	p := DefaultPolicy(dir)

	if len(p.DenyReadDirs) == 0 {
		t.Fatal("expected deny_read dirs, got empty")
	}
	// Verify at least one secret dir is in the deny list.
	protected := secretDirs()
	assertContains(t, "DenyReadDirs", p.DenyReadDirs, protected[0])
}

func TestResult_ActiveCount(t *testing.T) {
	r := Result{
		Layers: []LayerStatus{
			{Name: LayerLandlock, Active: true},
			{Name: LayerNetNS, Active: false, Reason: "unavailable"},
			{Name: LayerSeccomp, Active: true},
		},
	}
	if r.ActiveCount() != 2 {
		t.Errorf("ActiveCount = %d, want 2", r.ActiveCount())
	}
	if r.TotalCount() != 3 {
		t.Errorf("TotalCount = %d, want 3", r.TotalCount())
	}
	if r.IsFullyContained() {
		t.Error("should not be fully contained with one layer missing")
	}
}

func TestResult_FullyContained(t *testing.T) {
	r := Result{
		Layers: []LayerStatus{
			{Name: LayerLandlock, Active: true},
			{Name: LayerNetNS, Active: true},
			{Name: LayerSeccomp, Active: true},
		},
	}
	if !r.IsFullyContained() {
		t.Error("expected fully contained with all layers active")
	}
}

func TestDefaultPolicy_EmptyHOME(t *testing.T) {
	t.Setenv("HOME", "")
	dir := t.TempDir()
	p := DefaultPolicy(dir)

	// With empty HOME, DenyReadDirs should be empty (no secret dirs to deny).
	if len(p.DenyReadDirs) != 0 {
		t.Errorf("expected empty DenyReadDirs with no HOME, got %v", p.DenyReadDirs)
	}
}

func TestValidateWorkspace_RejectsSymlinkResolveError(t *testing.T) {
	// Create a symlink to a target that doesn't exist — EvalSymlinks will
	// return an error that is os.IsNotExist.
	dir := t.TempDir()
	link := filepath.Join(dir, "broken")
	if err := os.Symlink("/nonexistent/target", link); err != nil {
		t.Fatal(err)
	}
	err := ValidateWorkspace(link)
	if err == nil {
		t.Error("expected error for broken symlink workspace")
	}
}

func requireSecretDirs(t *testing.T) {
	t.Helper()
	if len(secretDirs()) == 0 {
		t.Skip("no secret dirs exist (CI env without ~/.ssh, ~/.aws, etc.)")
	}
}

func TestValidatePolicy_RejectsHomeOverlap(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)
	p := DefaultPolicy(t.TempDir())
	p.AllowReadDirs = append(p.AllowReadDirs, home)
	if err := ValidatePolicy(p); err == nil {
		t.Error("expected error for HOME in allow_read")
	}
}

func TestValidatePolicy_RejectsParentOfSecret(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)
	p := DefaultPolicy(t.TempDir())
	p.AllowReadDirs = append(p.AllowReadDirs, home+"/")
	if err := ValidatePolicy(p); err == nil {
		t.Error("expected error for HOME/ covering secret dirs")
	}
}

func TestValidatePolicy_RejectsWriteOverlap(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)
	p := DefaultPolicy(t.TempDir())
	p.AllowRWDirs = append(p.AllowRWDirs, home)
	if err := ValidatePolicy(p); err == nil {
		t.Error("expected error for HOME in allow_write")
	}
}

func TestValidatePolicy_AcceptsDefault(t *testing.T) {
	if err := ValidatePolicy(DefaultPolicy(t.TempDir())); err != nil {
		t.Errorf("default policy should pass: %v", err)
	}
}

func TestValidatePolicy_AcceptsNarrowPaths(t *testing.T) {
	p := DefaultPolicy(t.TempDir())
	p.AllowReadDirs = append(p.AllowReadDirs, "/opt/my-tool/")
	if err := ValidatePolicy(p); err != nil {
		t.Errorf("narrow path should pass: %v", err)
	}
}

func TestPathCovers(t *testing.T) {
	tests := []struct {
		allowed, protected string
		want               bool
	}{
		{"/home/user", "/home/user/.ssh", true},
		{"/home/user/", "/home/user/.ssh", true},
		{"/home/user", "/home/user", true},
		{"/usr", "/home/user/.ssh", false},
		{"/home/other", "/home/user/.ssh", false},
		{"/home/userfoo", "/home/user/.ssh", false},
	}
	for _, tt := range tests {
		t.Run(tt.allowed+"->"+tt.protected, func(t *testing.T) {
			if got := pathCovers(tt.allowed, tt.protected); got != tt.want {
				t.Errorf("pathCovers(%q, %q) = %v, want %v", tt.allowed, tt.protected, got, tt.want)
			}
		})
	}
}

func TestValidatePolicy_RejectsSymlinkToHome(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)
	// Create a symlink that points to HOME. Landlock would resolve this
	// and grant access to the real home directory.
	dir := t.TempDir()
	link := filepath.Join(dir, "home-link")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}

	p := DefaultPolicy(t.TempDir())
	p.AllowReadDirs = append(p.AllowReadDirs, link)
	if err := ValidatePolicy(p); err == nil {
		t.Error("expected error for symlink to HOME in allow_read")
	}
}

func TestValidatePolicy_RejectsSymlinkToHomeInWrite(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)
	dir := t.TempDir()
	link := filepath.Join(dir, "home-link-rw")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}

	p := DefaultPolicy(t.TempDir())
	p.AllowRWDirs = append(p.AllowRWDirs, link)
	if err := ValidatePolicy(p); err == nil {
		t.Error("expected error for symlink to HOME in allow_write")
	}
}

func TestValidatePolicy_RejectsFileInsideProtectedDir(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	requireSecretDirs(t)
	// Use the first existing protected dir for the test.
	protected := secretDirs()
	p := DefaultPolicy(t.TempDir())
	p.AllowReadFiles = append(p.AllowReadFiles, filepath.Join(protected[0], "test_file"))
	if err := ValidatePolicy(p); err == nil {
		t.Errorf("expected error for file inside protected directory %s", protected[0])
	}
}

func TestValidatePolicy_AcceptsFileOutsideProtectedDir(t *testing.T) {
	p := DefaultPolicy(t.TempDir())
	p.AllowReadFiles = append(p.AllowReadFiles, "/opt/app/config.json")
	if err := ValidatePolicy(p); err != nil {
		t.Errorf("file outside protected dirs should pass: %v", err)
	}
}

func TestDefaultPolicy_NoHostTmp(t *testing.T) {
	dir := t.TempDir()
	p := DefaultPolicy(dir)
	assertNotContains(t, "AllowRWDirs", p.AllowRWDirs, "/tmp/")
}

func TestDefaultPolicy_HasDevShm(t *testing.T) {
	dir := t.TempDir()
	p := DefaultPolicy(dir)
	assertContains(t, "AllowRWDirs", p.AllowRWDirs, "/dev/shm/")
}

func TestDefaultPolicy_HasBinDirs(t *testing.T) {
	dir := t.TempDir()
	p := DefaultPolicy(dir)
	assertContains(t, "AllowReadDirs", p.AllowReadDirs, "/bin/")
	assertContains(t, "AllowReadDirs", p.AllowReadDirs, "/sbin/")
}

func assertContains(t *testing.T, field string, slice []string, want string) {
	t.Helper()
	for _, s := range slice {
		if s == want {
			return
		}
	}
	t.Errorf("%s missing %q", field, want)
}

func assertNotContains(t *testing.T, field string, slice []string, unwanted string) {
	t.Helper()
	for _, s := range slice {
		if s == unwanted {
			t.Errorf("%s should not contain %q", field, unwanted)
			return
		}
	}
}
