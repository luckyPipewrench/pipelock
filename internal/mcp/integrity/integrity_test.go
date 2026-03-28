// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	testShellScript  = "#!/bin/sh\necho hello\n"
	testPythonScript = "#!/usr/bin/env python3\nprint('hello')\n"
	testPlainBinary  = "ELF-like-content-for-test"
	testAction       = "block"
	testActionWarn   = "warn"
	osWindows        = "windows"
	interpPython3    = "python3"
)

// hashOfString is a test helper that writes content to a temp file and returns
// the SHA-256 hash via hashFileByFD.
func hashOfString(t *testing.T, content string) string {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "hashme")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	h, err := hashFileByFD(tmp)
	if err != nil {
		t.Fatalf("hashing temp file: %v", err)
	}
	return h
}

// --- Manifest Tests ---

func TestLoadManifest_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	m := &Manifest{
		Version: ManifestVersion,
		Entries: map[string]string{
			"/usr/bin/node": "abc123",
		},
	}
	if err := SaveManifest(path, m); err != nil {
		t.Fatalf("saving manifest: %v", err)
	}

	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("loading manifest: %v", err)
	}

	if loaded.Version != ManifestVersion {
		t.Errorf("version = %d, want %d", loaded.Version, ManifestVersion)
	}
	if loaded.Entries["/usr/bin/node"] != "abc123" {
		t.Errorf("entry = %q, want %q", loaded.Entries["/usr/bin/node"], "abc123")
	}
}

func TestLoadManifest_BadVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	data := []byte(`{"version":999,"entries":{}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	_, err := LoadManifest(path)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
	if got := err.Error(); !contains(got, "unsupported manifest version") {
		t.Errorf("error = %q, want substring %q", got, "unsupported manifest version")
	}
}

func TestLoadManifest_NullEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	data := []byte(`{"version":1,"entries":null}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	_, err := LoadManifest(path)
	if err == nil {
		t.Fatal("expected error for null entries")
	}
}

func TestLoadManifest_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	if err := os.WriteFile(path, []byte("{not json}"), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	_, err := LoadManifest(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadManifest_NotFound(t *testing.T) {
	_, err := LoadManifest("/nonexistent/path/manifest.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSaveManifest_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	original := &Manifest{
		Version: ManifestVersion,
		Entries: map[string]string{
			"/usr/local/bin/bun": "deadbeef",
			"/usr/bin/python3":   "cafebabe",
		},
	}

	if err := SaveManifest(path, original); err != nil {
		t.Fatalf("saving: %v", err)
	}

	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	if len(loaded.Entries) != len(original.Entries) {
		t.Fatalf("entries count = %d, want %d", len(loaded.Entries), len(original.Entries))
	}
	for k, v := range original.Entries {
		if loaded.Entries[k] != v {
			t.Errorf("entry[%q] = %q, want %q", k, loaded.Entries[k], v)
		}
	}

	// Verify file permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file permission = %04o, want 0600", perm)
	}
}

func TestSaveManifest_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	m := &Manifest{Version: ManifestVersion, Entries: map[string]string{"/bin/sh": "aaa"}}
	if err := SaveManifest(path, m); err != nil {
		t.Fatalf("saving: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	// Should be valid JSON.
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("re-parsing JSON: %v", err)
	}

	// Should end with newline.
	if data[len(data)-1] != '\n' {
		t.Error("manifest file should end with newline")
	}
}

// --- hashFileByFD Tests ---

func TestHashFileByFD_Consistent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testfile")
	if err := os.WriteFile(path, []byte("deterministic content"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	h1, err := hashFileByFD(path)
	if err != nil {
		t.Fatalf("first hash: %v", err)
	}

	h2, err := hashFileByFD(path)
	if err != nil {
		t.Fatalf("second hash: %v", err)
	}

	if h1 != h2 {
		t.Errorf("hashes differ: %q vs %q", h1, h2)
	}

	// SHA-256 hex is 64 characters.
	if len(h1) != 64 {
		t.Errorf("hash length = %d, want 64", len(h1))
	}
}

func TestHashFileByFD_DifferentContent(t *testing.T) {
	dir := t.TempDir()

	f1 := filepath.Join(dir, "file1")
	f2 := filepath.Join(dir, "file2")
	if err := os.WriteFile(f1, []byte("content A"), 0o600); err != nil {
		t.Fatalf("writing f1: %v", err)
	}
	if err := os.WriteFile(f2, []byte("content B"), 0o600); err != nil {
		t.Fatalf("writing f2: %v", err)
	}

	h1, err := hashFileByFD(f1)
	if err != nil {
		t.Fatalf("hashing f1: %v", err)
	}

	h2, err := hashFileByFD(f2)
	if err != nil {
		t.Fatalf("hashing f2: %v", err)
	}

	if h1 == h2 {
		t.Error("different files should have different hashes")
	}
}

func TestHashFileByFD_NotFound(t *testing.T) {
	_, err := hashFileByFD("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// --- Shebang Tests ---

func TestDetectShebang_ShBang(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "test.sh")
	if err := os.WriteFile(script, []byte(testShellScript), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	interp := detectShebang(script)
	if interp != "/bin/sh" {
		t.Errorf("interpreter = %q, want %q", interp, "/bin/sh")
	}
}

func TestDetectShebang_EnvPython(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "test.py")
	if err := os.WriteFile(script, []byte(testPythonScript), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	interp := detectShebang(script)
	if interp != interpPython3 {
		t.Errorf("interpreter = %q, want %q", interp, interpPython3)
	}
}

func TestDetectShebang_NoBang(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "noshebang")
	if err := os.WriteFile(script, []byte(testPlainBinary), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	interp := detectShebang(script)
	if interp != "" {
		t.Errorf("interpreter = %q, want empty string", interp)
	}
}

func TestDetectShebang_EmptyShebang(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "empty.sh")
	if err := os.WriteFile(script, []byte("#!\n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	interp := detectShebang(script)
	if interp != "" {
		t.Errorf("interpreter = %q, want empty for bare #!", interp)
	}
}

func TestDetectShebang_NonexistentFile(t *testing.T) {
	interp := detectShebang("/nonexistent/file")
	if interp != "" {
		t.Errorf("interpreter = %q, want empty for missing file", interp)
	}
}

func TestDetectShebang_OverlongLine(t *testing.T) {
	// A shebang line exceeding maxShebangLen with no newline should be
	// treated as "no shebang" (safe default per Finding 2).
	dir := t.TempDir()
	script := filepath.Join(dir, "overlong")

	// Build a shebang line longer than maxShebangLen with no newline.
	content := "#!" + strings.Repeat("x", maxShebangLen+100)
	if err := os.WriteFile(script, []byte(content), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	interp := detectShebang(script)
	if interp != "" {
		t.Errorf("interpreter = %q, want empty for overlong shebang", interp)
	}
}

// --- isInsideDir Tests ---

func TestIsInsideDir_Inside(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "subdir", "binary")
	if err := os.MkdirAll(filepath.Dir(child), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(child, []byte("bin"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	if !isInsideDir(child, dir) {
		t.Error("expected child to be inside dir")
	}
}

func TestIsInsideDir_Outside(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	child := filepath.Join(dir2, "binary")
	if err := os.WriteFile(child, []byte("bin"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	if isInsideDir(child, dir1) {
		t.Error("expected child to be outside dir")
	}
}

func TestIsInsideDir_SameDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("data"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	if !isInsideDir(file, dir) {
		t.Error("file in same dir should be inside")
	}
}

// --- Verify Tests ---

func TestVerify_KnownBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "test-mcp")
	if err := os.WriteFile(bin, []byte(testPlainBinary), 0o600); err != nil {
		t.Fatalf("writing binary: %v", err)
	}

	hash := hashOfString(t, testPlainBinary)
	cfg := &Config{
		Enabled:   true,
		Action:    testAction,
		Manifests: map[string]string{bin: hash},
	}

	result, err := Verify([]string{bin}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !result.Verified {
		t.Errorf("expected Verified=true, got reason: %s", result.Reason)
	}
	if result.ActualHash != hash {
		t.Errorf("ActualHash = %q, want %q", result.ActualHash, hash)
	}
	if result.ResolvedPath != bin {
		t.Errorf("ResolvedPath = %q, want %q", result.ResolvedPath, bin)
	}
}

func TestVerify_TamperedBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tampered")
	if err := os.WriteFile(bin, []byte("original content"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	// Record the original hash, then tamper.
	origHash := hashOfString(t, "original content")

	// Now write different content to the binary.
	if err := os.WriteFile(bin, []byte("tampered content"), 0o600); err != nil {
		t.Fatalf("writing tampered: %v", err)
	}

	cfg := &Config{
		Enabled:   true,
		Action:    testAction,
		Manifests: map[string]string{bin: origHash},
	}

	result, err := Verify([]string{bin}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.Verified {
		t.Error("expected Verified=false for tampered binary")
	}
	if result.ExpectedHash != origHash {
		t.Errorf("ExpectedHash = %q, want %q", result.ExpectedHash, origHash)
	}
	if result.ActualHash == origHash {
		t.Error("ActualHash should differ from ExpectedHash")
	}
	if result.Reason == "" {
		t.Error("Reason should be non-empty for mismatch")
	}
}

func TestVerify_UnknownBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "unknown")
	if err := os.WriteFile(bin, []byte("some binary"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	// Manifest exists but does not include this binary.
	cfg := &Config{
		Enabled:   true,
		Action:    testAction,
		Manifests: map[string]string{"/some/other/binary": "deadbeef"},
	}

	result, err := Verify([]string{bin}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.Verified {
		t.Error("expected Verified=false for unknown binary (fail-closed)")
	}
	if !contains(result.Reason, "not found in manifest") {
		t.Errorf("Reason = %q, want 'not found in manifest'", result.Reason)
	}
}

func TestVerify_NilManifest(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.WriteFile(bin, []byte("content"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	// No manifest configured: fail-closed, not verified.
	cfg := &Config{
		Enabled:   true,
		Action:    testAction,
		Manifests: nil,
	}

	result, err := Verify([]string{bin}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.Verified {
		t.Error("expected Verified=false when no manifest (fail-closed)")
	}
	if !contains(result.Reason, "no manifest loaded") {
		t.Errorf("Reason = %q, want 'no manifest loaded'", result.Reason)
	}
}

func TestVerify_EmptyCommand(t *testing.T) {
	cfg := &Config{Enabled: true, Action: testAction}
	_, err := Verify([]string{}, cfg, "")
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}

func TestVerify_NonexistentBinary(t *testing.T) {
	cfg := &Config{Enabled: true, Action: testAction}
	_, err := Verify([]string{"/nonexistent/binary/path"}, cfg, "")
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}
}

func TestVerify_InterpreterWithScript(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("interpreter detection requires Unix PATH resolution")
	}

	// Find a real interpreter on the system.
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not in PATH")
	}
	resolvedSh, err := filepath.EvalSymlinks(shPath)
	if err != nil {
		t.Fatalf("resolving sh: %v", err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "test.sh")
	if err := os.WriteFile(script, []byte(testShellScript), 0o600); err != nil {
		t.Fatalf("writing script: %v", err)
	}

	shHash := hashOfString(t, readFileContent(t, resolvedSh))
	scriptHash := hashOfString(t, testShellScript)

	cfg := &Config{
		Enabled: true,
		Action:  testAction,
		Manifests: map[string]string{
			resolvedSh: shHash,
			script:     scriptHash,
		},
	}

	result, err := Verify([]string{"sh", script}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !result.IsInterpreter {
		t.Error("expected IsInterpreter=true for 'sh'")
	}
	if result.ScriptPath != script {
		t.Errorf("ScriptPath = %q, want %q", result.ScriptPath, script)
	}
	if !result.Verified {
		t.Errorf("expected Verified=true, got reason: %s", result.Reason)
	}
}

func TestVerify_ShebangDetection(t *testing.T) {
	dir := t.TempDir()

	// Create a script with a shebang pointing to /bin/sh.
	script := filepath.Join(dir, "myscript")
	if err := os.WriteFile(script, []byte(testShellScript), 0o600); err != nil {
		t.Fatalf("writing script: %v", err)
	}

	// Resolve /bin/sh for manifest.
	shPath := "/bin/sh"
	resolvedSh, err := filepath.EvalSymlinks(shPath)
	if err != nil {
		t.Skip("cannot resolve /bin/sh")
	}

	shHash, err := hashFileByFD(resolvedSh)
	if err != nil {
		t.Fatalf("hashing /bin/sh: %v", err)
	}

	scriptHash := hashOfString(t, testShellScript)

	cfg := &Config{
		Enabled: true,
		Action:  testAction,
		Manifests: map[string]string{
			resolvedSh: shHash,
			script:     scriptHash,
		},
	}

	result, err := Verify([]string{script}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !result.IsInterpreter {
		t.Error("expected shebang script detected as interpreter")
	}
	if result.ResolvedPath != resolvedSh {
		t.Errorf("ResolvedPath = %q, want shebang interpreter %q", result.ResolvedPath, resolvedSh)
	}
	if result.ScriptPath != script {
		t.Errorf("ScriptPath = %q, want %q", result.ScriptPath, script)
	}
}

func TestVerify_SymlinkResolution(t *testing.T) {
	dir := t.TempDir()

	// Create a real binary.
	realBin := filepath.Join(dir, "real-binary")
	if err := os.WriteFile(realBin, []byte(testPlainBinary), 0o600); err != nil {
		t.Fatalf("writing binary: %v", err)
	}

	// Create a symlink to it.
	link := filepath.Join(dir, "link-to-binary")
	if err := os.Symlink(realBin, link); err != nil {
		t.Fatalf("creating symlink: %v", err)
	}

	hash := hashOfString(t, testPlainBinary)
	cfg := &Config{
		Enabled:   true,
		Action:    testAction,
		Manifests: map[string]string{realBin: hash},
	}

	result, err := Verify([]string{link}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.ResolvedPath != realBin {
		t.Errorf("ResolvedPath = %q, want %q (should resolve symlink)", result.ResolvedPath, realBin)
	}
	if !result.Verified {
		t.Errorf("expected Verified=true, got reason: %s", result.Reason)
	}
}

func TestVerify_SuspiciousCWD(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "evil-binary")
	if err := os.WriteFile(bin, []byte(testPlainBinary), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	hash := hashOfString(t, testPlainBinary)
	cfg := &Config{
		Enabled:   true,
		Action:    testAction,
		Manifests: map[string]string{bin: hash},
	}

	// Agent working dir = same dir as binary.
	result, err := Verify([]string{bin}, cfg, dir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !result.Suspicious {
		t.Error("expected Suspicious=true when binary is in agent working dir")
	}
}

func TestVerify_SuspiciousCWD_Outside(t *testing.T) {
	dir := t.TempDir()
	agentDir := t.TempDir()
	bin := filepath.Join(dir, "safe-binary")
	if err := os.WriteFile(bin, []byte(testPlainBinary), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	hash := hashOfString(t, testPlainBinary)
	cfg := &Config{Enabled: true, Action: testAction, Manifests: map[string]string{bin: hash}}

	result, err := Verify([]string{bin}, cfg, agentDir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.Suspicious {
		t.Error("expected Suspicious=false when binary is outside agent working dir")
	}
}

func TestVerify_InterpreterTamperedScript(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("requires Unix")
	}

	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not in PATH")
	}
	resolvedSh, err := filepath.EvalSymlinks(shPath)
	if err != nil {
		t.Fatalf("resolving sh: %v", err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho evil"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	shHash, err := hashFileByFD(resolvedSh)
	if err != nil {
		t.Fatalf("hashing sh: %v", err)
	}

	// Manifest has the real script hash but we'll write different content.
	cfg := &Config{
		Enabled: true,
		Action:  testAction,
		Manifests: map[string]string{
			resolvedSh: shHash,
			script:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // wrong hash
		},
	}

	result, err := Verify([]string{"sh", script}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.Verified {
		t.Error("expected Verified=false for tampered script")
	}
	if !contains(result.Reason, "script hash mismatch") {
		t.Errorf("Reason = %q, want 'script hash mismatch'", result.Reason)
	}
}

// --- CheckSymlinkRace Tests ---

func TestCheckSymlinkRace_NoRace(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "stable")
	if err := os.WriteFile(bin, []byte("stable"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	resolved, err := resolveBinary(bin)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}

	if err := CheckSymlinkRace(bin, resolved); err != nil {
		t.Errorf("unexpected race error: %v", err)
	}
}

func TestCheckSymlinkRace_RaceDetected(t *testing.T) {
	dir := t.TempDir()

	realBin := filepath.Join(dir, "real")
	if err := os.WriteFile(realBin, []byte("real"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	evilBin := filepath.Join(dir, "evil")
	if err := os.WriteFile(evilBin, []byte("evil"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(realBin, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	originalResolved := realBin

	// Swap symlink to evil.
	_ = os.Remove(link)
	if err := os.Symlink(evilBin, link); err != nil {
		t.Fatalf("re-symlink: %v", err)
	}

	err := CheckSymlinkRace(link, originalResolved)
	if err == nil {
		t.Fatal("expected symlink race error")
	}
	if !contains(err.Error(), "symlink race detected") {
		t.Errorf("error = %q, want 'symlink race detected'", err.Error())
	}
}

func TestCheckSymlinkRace_BinaryRemoved(t *testing.T) {
	err := CheckSymlinkRace("/nonexistent/binary/removed", "/some/path")
	if err == nil {
		t.Fatal("expected error for removed binary")
	}
}

// --- ResolveAndHash Tests ---

func TestResolveAndHash_ValidBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.WriteFile(bin, []byte("content"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	resolved, hash, err := ResolveAndHash(bin)
	if err != nil {
		t.Fatalf("ResolveAndHash: %v", err)
	}

	if resolved != bin {
		t.Errorf("resolved = %q, want %q", resolved, bin)
	}
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
}

func TestResolveAndHash_Nonexistent(t *testing.T) {
	_, _, err := ResolveAndHash("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}
}

// --- resolveBinary Tests ---

func TestResolveBinary_AbsolutePath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "abs-bin")
	if err := os.WriteFile(bin, []byte("bin"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	resolved, err := resolveBinary(bin)
	if err != nil {
		t.Fatalf("resolveBinary: %v", err)
	}
	if resolved != bin {
		t.Errorf("resolved = %q, want %q", resolved, bin)
	}
}

func TestResolveBinary_LookPath(t *testing.T) {
	// "sh" should be findable via PATH on any Unix system.
	if runtime.GOOS == osWindows {
		t.Skip("requires Unix")
	}

	resolved, err := resolveBinary("sh")
	if err != nil {
		t.Fatalf("resolveBinary(sh): %v", err)
	}
	if resolved == "" {
		t.Error("resolved should not be empty")
	}
	if !filepath.IsAbs(resolved) {
		t.Errorf("resolved should be absolute, got %q", resolved)
	}
}

func TestResolveBinary_Nonexistent(t *testing.T) {
	_, err := resolveBinary("nonexistent-binary-xyzzy-12345")
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}
	// Should be an exec.ErrNotFound wrapped error.
	if !errors.Is(err, exec.ErrNotFound) {
		// On some systems, LookPath returns a different error. That's fine.
		if !contains(err.Error(), "LookPath") && !contains(err.Error(), "not found") {
			t.Errorf("unexpected error type: %v", err)
		}
	}
}

func TestResolveBinary_SymlinkChain(t *testing.T) {
	dir := t.TempDir()

	realBin := filepath.Join(dir, "real")
	if err := os.WriteFile(realBin, []byte("real"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	link1 := filepath.Join(dir, "link1")
	if err := os.Symlink(realBin, link1); err != nil {
		t.Fatalf("symlink1: %v", err)
	}

	link2 := filepath.Join(dir, "link2")
	if err := os.Symlink(link1, link2); err != nil {
		t.Fatalf("symlink2: %v", err)
	}

	resolved, err := resolveBinary(link2)
	if err != nil {
		t.Fatalf("resolveBinary: %v", err)
	}
	if resolved != realBin {
		t.Errorf("resolved = %q, want %q (should follow chain)", resolved, realBin)
	}
}

// --- Interpreter map tests ---

func TestInterpreterMap(t *testing.T) {
	expected := []string{
		"python", "python3", "node", "bun", "deno",
		"ruby", "perl", "bash", "sh", "dash",
	}
	for _, name := range expected {
		if !interpreters[name] {
			t.Errorf("interpreter %q should be in map", name)
		}
	}

	// Package runners should NOT be in the interpreters map.
	runners := []string{"npx", "bunx", "uvx", "pipx"}
	for _, name := range runners {
		if interpreters[name] {
			t.Errorf("package runner %q should not be in interpreters map", name)
		}
		if !packageRunners[name] {
			t.Errorf("package runner %q should be in packageRunners map", name)
		}
	}

	// Non-interpreters should not be in map.
	nonInterpreters := []string{"gcc", "ls", "cat", "grep"}
	for _, name := range nonInterpreters {
		if interpreters[name] {
			t.Errorf("non-interpreter %q should not be in map", name)
		}
	}
}

// --- Additional coverage tests ---

func TestVerify_ShebangEnvInterpreter(t *testing.T) {
	// Script with #!/usr/bin/env python3 -- the env unwrapping path.
	dir := t.TempDir()
	script := filepath.Join(dir, "envscript.py")
	if err := os.WriteFile(script, []byte(testPythonScript), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	// Verify detectShebang finds "python3" (not "/usr/bin/env").
	interp := detectShebang(script)
	if interp != interpPython3 {
		t.Errorf("shebang interpreter = %q, want %q", interp, interpPython3)
	}
}

func TestVerify_InterpreterNoScript(t *testing.T) {
	// Interpreter invoked with no script argument (e.g. "python3" alone).
	if runtime.GOOS == osWindows {
		t.Skip("requires Unix")
	}

	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not in PATH")
	}
	resolvedSh, err := filepath.EvalSymlinks(shPath)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}

	shHash, hashErr := hashFileByFD(resolvedSh)
	if hashErr != nil {
		t.Fatalf("hashing: %v", hashErr)
	}

	cfg := &Config{
		Enabled:   true,
		Action:    testAction,
		Manifests: map[string]string{resolvedSh: shHash},
	}

	// Only the interpreter, no script arg.
	result, err := Verify([]string{"sh"}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !result.IsInterpreter {
		t.Error("expected IsInterpreter=true")
	}
	// No script should be hashed.
	if result.ScriptPath != "" {
		t.Errorf("ScriptPath should be empty, got %q", result.ScriptPath)
	}
	if !result.Verified {
		t.Errorf("expected Verified=true, got reason: %s", result.Reason)
	}
}

func TestIsInsideDir_NonexistentDir(t *testing.T) {
	// When the dir doesn't exist, isInsideDir should return false.
	if isInsideDir("/some/file", "/nonexistent/dir/abc123") {
		t.Error("should return false for nonexistent dir")
	}
}

func TestIsInsideDir_NonexistentFile(t *testing.T) {
	dir := t.TempDir()
	if isInsideDir("/nonexistent/file/abc123", dir) {
		t.Error("should return false for nonexistent file")
	}
}

func TestVerify_ScriptNotInManifest(t *testing.T) {
	// Interpreter is in manifest but script is not.
	if runtime.GOOS == osWindows {
		t.Skip("requires Unix")
	}

	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not in PATH")
	}
	resolvedSh, err := filepath.EvalSymlinks(shPath)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	shHash, hashErr := hashFileByFD(resolvedSh)
	if hashErr != nil {
		t.Fatalf("hashing: %v", hashErr)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "mystery.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho mystery"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	cfg := &Config{
		Enabled: true,
		Action:  testAction,
		Manifests: map[string]string{
			resolvedSh: shHash,
			// script NOT in manifest
		},
	}

	result, err := Verify([]string{"sh", script}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.Verified {
		t.Error("expected Verified=false when script not in manifest")
	}
	if !contains(result.Reason, "not found in manifest") {
		t.Errorf("Reason = %q, want 'not found in manifest'", result.Reason)
	}
}

func TestHashScript_NonexistentScript(t *testing.T) {
	_, _, err := hashScript("/nonexistent/script.sh", "")
	if err == nil {
		t.Fatal("expected error for nonexistent script")
	}
}

func TestHashScript_WorkDir(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "myscript.sh")
	content := "#!/bin/sh\necho workdir\n"
	if err := os.WriteFile(script, []byte(content), 0o600); err != nil {
		t.Fatalf("writing script: %v", err)
	}

	// Relative path with workDir should resolve correctly.
	resolved, hash, err := hashScript("myscript.sh", dir)
	if err != nil {
		t.Fatalf("hashScript with workDir: %v", err)
	}
	if resolved != script {
		t.Errorf("resolved = %q, want %q", resolved, script)
	}
	expectedHash := hashOfString(t, content)
	if hash != expectedHash {
		t.Errorf("hash = %q, want %q", hash, expectedHash)
	}

	// Absolute path should ignore workDir.
	resolved2, hash2, err := hashScript(script, "/some/other/dir")
	if err != nil {
		t.Fatalf("hashScript with abs path: %v", err)
	}
	if resolved2 != script {
		t.Errorf("resolved = %q, want %q", resolved2, script)
	}
	if hash2 != expectedHash {
		t.Errorf("hash = %q, want %q", hash2, expectedHash)
	}
}

func TestVerify_RelativePath(t *testing.T) {
	// Test with a relative path containing a separator.
	dir := t.TempDir()
	subdir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(subdir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bin := filepath.Join(subdir, "mybin")
	if err := os.WriteFile(bin, []byte("relative"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	// Use relative path with separator.
	relPath := filepath.Join("sub", "mybin")

	// We need to be in the temp dir for the relative path to resolve.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	resolved, err := resolveBinary(relPath)
	if err != nil {
		t.Fatalf("resolveBinary: %v", err)
	}
	if resolved != bin {
		t.Errorf("resolved = %q, want %q", resolved, bin)
	}
}

func TestSaveManifest_BadPath(t *testing.T) {
	m := &Manifest{Version: ManifestVersion, Entries: map[string]string{}}
	err := SaveManifest("/nonexistent/dir/manifest.json", m)
	if err == nil {
		t.Fatal("expected error for bad path")
	}
}

func TestVerify_ShebangBinaryWithManifest(t *testing.T) {
	// A non-interpreter binary that has a shebang pointing to /bin/sh.
	// When the script is also in the manifest, both are verified.
	dir := t.TempDir()
	script := filepath.Join(dir, "myscript")
	if err := os.WriteFile(script, []byte(testShellScript), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	resolvedSh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("cannot resolve /bin/sh")
	}

	shHash, err := hashFileByFD(resolvedSh)
	if err != nil {
		t.Fatalf("hashing /bin/sh: %v", err)
	}
	scriptHash := hashOfString(t, testShellScript)

	// Manifest has both, but binary hash is WRONG (tampered interpreter).
	cfg := &Config{
		Enabled: true,
		Action:  testAction,
		Manifests: map[string]string{
			resolvedSh: "bad_hash_for_interpreter",
			script:     scriptHash,
		},
	}

	result, err := Verify([]string{script}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.Verified {
		t.Error("expected Verified=false for tampered shebang interpreter")
	}
	if !contains(result.Reason, "binary hash mismatch") {
		t.Errorf("Reason = %q, want 'binary hash mismatch'", result.Reason)
	}

	// Now with correct hashes.
	cfg.Manifests[resolvedSh] = shHash
	result, err = Verify([]string{script}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Verified {
		t.Errorf("expected Verified=true with correct hashes, got reason: %s", result.Reason)
	}

	// Verify the script's hash appears correctly.
	_ = shHash
}

func TestResolveAndHash_Symlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target-content"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	resolved, hash, err := ResolveAndHash(link)
	if err != nil {
		t.Fatalf("ResolveAndHash: %v", err)
	}
	if resolved != target {
		t.Errorf("resolved = %q, want %q", resolved, target)
	}
	expectedHash := hashOfString(t, "target-content")
	if hash != expectedHash {
		t.Errorf("hash = %q, want %q", hash, expectedHash)
	}
}

// --- Versioned interpreter and /usr/bin/env wrapper tests ---

func TestIsInterpreterName_ExactMatch(t *testing.T) {
	exact := []string{"python", "python3", "node", "bun", "deno", "ruby", "perl", "bash", "sh"}
	for _, name := range exact {
		if !isInterpreterName(name) {
			t.Errorf("isInterpreterName(%q) = false, want true", name)
		}
	}
}

func TestIsInterpreterName_VersionedPrefixMatch(t *testing.T) {
	versioned := []string{"python3.11", "python3.12", "node20", "ruby3.2", "perl5.38"}
	for _, name := range versioned {
		if !isInterpreterName(name) {
			t.Errorf("isInterpreterName(%q) = false, want true (versioned)", name)
		}
	}
}

func TestIsInterpreterName_NonInterpreter(t *testing.T) {
	nonInterp := []string{"gcc", "ls", "cat", "env", "grep", "make"}
	for _, name := range nonInterp {
		if isInterpreterName(name) {
			t.Errorf("isInterpreterName(%q) = true, want false", name)
		}
	}
}

func TestIsInterpreterName_PrefixFalsePositives(t *testing.T) {
	// Binaries that start with interpreter prefixes but are not interpreters.
	// The suffix must start with a digit or dot to be a versioned interpreter.
	falsePositives := []string{"shred", "sha256sum", "node_exporter", "python-config", "perldoc", "bunzip2"}
	for _, name := range falsePositives {
		if isInterpreterName(name) {
			t.Errorf("isInterpreterName(%q) = true, want false (not a versioned interpreter)", name)
		}
	}
}

func TestIsInterpreterName_PackageRunners(t *testing.T) {
	// Package runners should NOT match as interpreters.
	runners := []string{"npx", "bunx", "uvx", "pipx"}
	for _, name := range runners {
		if isInterpreterName(name) {
			t.Errorf("isInterpreterName(%q) = true, want false (package runner, not interpreter)", name)
		}
	}
}

func TestVerify_VersionedInterpreter(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("requires Unix")
	}

	dir := t.TempDir()

	// Create a fake "python3.11" binary in the temp dir.
	fakePython := filepath.Join(dir, "python3.11")
	pythonContent := "fake-python3.11-binary"
	if err := os.WriteFile(fakePython, []byte(pythonContent), 0o600); err != nil {
		t.Fatalf("writing fake python: %v", err)
	}

	script := filepath.Join(dir, "script.py")
	scriptContent := "print('hello')\n"
	if err := os.WriteFile(script, []byte(scriptContent), 0o600); err != nil {
		t.Fatalf("writing script: %v", err)
	}

	pythonHash := hashOfString(t, pythonContent)
	scriptHash := hashOfString(t, scriptContent)

	cfg := &Config{
		Enabled: true,
		Action:  testAction,
		Manifests: map[string]string{
			fakePython: pythonHash,
			script:     scriptHash,
		},
	}

	result, err := Verify([]string{fakePython, script}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !result.IsInterpreter {
		t.Error("expected IsInterpreter=true for python3.11")
	}
	if result.ScriptPath != script {
		t.Errorf("ScriptPath = %q, want %q", result.ScriptPath, script)
	}
	if !result.Verified {
		t.Errorf("expected Verified=true, got reason: %s", result.Reason)
	}
}

func TestVerify_EnvWrapper_Python(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("requires Unix")
	}

	// Find /usr/bin/env on the system.
	envPath, err := exec.LookPath("env")
	if err != nil {
		t.Skip("env not in PATH")
	}

	// Find a real interpreter (sh is most reliable).
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not in PATH")
	}
	resolvedSh, err := filepath.EvalSymlinks(shPath)
	if err != nil {
		t.Fatalf("resolving sh: %v", err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "test.sh")
	scriptContent := "#!/bin/sh\necho hello\n"
	if err := os.WriteFile(script, []byte(scriptContent), 0o600); err != nil {
		t.Fatalf("writing script: %v", err)
	}

	shHash, err := hashFileByFD(resolvedSh)
	if err != nil {
		t.Fatalf("hashing sh: %v", err)
	}
	scriptHash := hashOfString(t, scriptContent)

	cfg := &Config{
		Enabled: true,
		Action:  testAction,
		Manifests: map[string]string{
			resolvedSh: shHash,
			script:     scriptHash,
		},
	}

	// Invoke as: /usr/bin/env sh test.sh
	result, err := Verify([]string{envPath, "sh", script}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !result.IsInterpreter {
		t.Error("expected IsInterpreter=true for env-wrapped sh")
	}
	if result.ResolvedPath != resolvedSh {
		t.Errorf("ResolvedPath = %q, want %q (should resolve to actual interpreter)", result.ResolvedPath, resolvedSh)
	}
	if result.ScriptPath != script {
		t.Errorf("ScriptPath = %q, want %q", result.ScriptPath, script)
	}
	if !result.Verified {
		t.Errorf("expected Verified=true, got reason: %s", result.Reason)
	}
}

func TestVerify_EnvWrapper_NoScript(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("requires Unix")
	}

	envPath, err := exec.LookPath("env")
	if err != nil {
		t.Skip("env not in PATH")
	}

	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not in PATH")
	}
	resolvedSh, err := filepath.EvalSymlinks(shPath)
	if err != nil {
		t.Fatalf("resolving sh: %v", err)
	}

	shHash, err := hashFileByFD(resolvedSh)
	if err != nil {
		t.Fatalf("hashing sh: %v", err)
	}

	cfg := &Config{
		Enabled:   true,
		Action:    testAction,
		Manifests: map[string]string{resolvedSh: shHash},
	}

	// Invoke as: /usr/bin/env sh (no script argument)
	result, err := Verify([]string{envPath, "sh"}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !result.IsInterpreter {
		t.Error("expected IsInterpreter=true for env-wrapped sh")
	}
	if result.ScriptPath != "" {
		t.Errorf("ScriptPath should be empty, got %q", result.ScriptPath)
	}
	if !result.Verified {
		t.Errorf("expected Verified=true, got reason: %s", result.Reason)
	}
}

func TestVerify_Python312_VersionedInterpreter(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("requires Unix")
	}

	dir := t.TempDir()

	// Create a fake "python3.12" binary.
	fakePython := filepath.Join(dir, "python3.12")
	pythonContent := "fake-python3.12-binary"
	if err := os.WriteFile(fakePython, []byte(pythonContent), 0o600); err != nil {
		t.Fatalf("writing fake python: %v", err)
	}

	script := filepath.Join(dir, "app.py")
	scriptContent := "import sys\n"
	if err := os.WriteFile(script, []byte(scriptContent), 0o600); err != nil {
		t.Fatalf("writing script: %v", err)
	}

	pythonHash := hashOfString(t, pythonContent)
	scriptHash := hashOfString(t, scriptContent)

	cfg := &Config{
		Enabled: true,
		Action:  testAction,
		Manifests: map[string]string{
			fakePython: pythonHash,
			script:     scriptHash,
		},
	}

	result, err := Verify([]string{fakePython, script}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if !result.IsInterpreter {
		t.Error("expected IsInterpreter=true for python3.12")
	}
	if result.ScriptHash != scriptHash {
		t.Errorf("ScriptHash = %q, want %q", result.ScriptHash, scriptHash)
	}
}

// --- skipEnvFlags Tests ---

func TestSkipEnvFlags_NoFlags(t *testing.T) {
	remaining := skipEnvFlags([]string{interpPython3, "script.py"})
	if len(remaining) != 2 || remaining[0] != interpPython3 {
		t.Errorf("expected [python3 script.py], got %v", remaining)
	}
}

func TestSkipEnvFlags_DashS(t *testing.T) {
	remaining := skipEnvFlags([]string{"-S", interpPython3, "script.py"})
	if len(remaining) != 2 || remaining[0] != interpPython3 {
		t.Errorf("expected [python3 script.py], got %v", remaining)
	}
}

func TestSkipEnvFlags_DashI(t *testing.T) {
	remaining := skipEnvFlags([]string{"-i", interpPython3, "script.py"})
	if len(remaining) != 2 || remaining[0] != interpPython3 {
		t.Errorf("expected [python3 script.py], got %v", remaining)
	}
}

func TestSkipEnvFlags_DashU(t *testing.T) {
	remaining := skipEnvFlags([]string{"-u", "HOME", interpPython3})
	if len(remaining) != 1 || remaining[0] != interpPython3 {
		t.Errorf("expected [python3], got %v", remaining)
	}
}

func TestSkipEnvFlags_DoubleDash(t *testing.T) {
	remaining := skipEnvFlags([]string{"--", interpPython3, "script.py"})
	if len(remaining) != 2 || remaining[0] != interpPython3 {
		t.Errorf("expected [python3 script.py], got %v", remaining)
	}
}

func TestSkipEnvFlags_CombinedFlags(t *testing.T) {
	remaining := skipEnvFlags([]string{"-i", "-u", "HOME", "-S", interpPython3})
	// -i skipped, -u HOME skipped, -S means next is interpreter
	if len(remaining) != 1 || remaining[0] != interpPython3 {
		t.Errorf("expected [python3], got %v", remaining)
	}
}

func TestSkipEnvFlags_Empty(t *testing.T) {
	remaining := skipEnvFlags([]string{})
	if remaining != nil {
		t.Errorf("expected nil for empty args, got %v", remaining)
	}
}

func TestSkipEnvFlags_OnlyFlags(t *testing.T) {
	remaining := skipEnvFlags([]string{"-i", "-0"})
	if remaining != nil {
		t.Errorf("expected nil when only flags present, got %v", remaining)
	}
}

func TestSkipEnvFlags_DashS_NoInterpreter(t *testing.T) {
	remaining := skipEnvFlags([]string{"-S"})
	if remaining != nil {
		t.Errorf("expected nil for -S without interpreter, got %v", remaining)
	}
}

func TestSkipEnvFlags_DoubleDash_NoInterpreter(t *testing.T) {
	remaining := skipEnvFlags([]string{"--"})
	if remaining != nil {
		t.Errorf("expected nil for -- without interpreter, got %v", remaining)
	}
}

// --- VerifyResult audit evidence tests ---

func TestVerifyResult_ReasonsAccumulate(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("requires Unix")
	}

	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not in PATH")
	}
	resolvedSh, err := filepath.EvalSymlinks(shPath)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "dual-fail.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho dual"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	// Both binary and script have wrong hashes in manifest.
	cfg := &Config{
		Enabled: true,
		Action:  testAction,
		Manifests: map[string]string{
			resolvedSh: "wrong_binary_hash",
			script:     "wrong_script_hash",
		},
	}

	result, err := Verify([]string{"sh", script}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.Verified {
		t.Error("expected Verified=false")
	}
	if len(result.Reasons) < 2 {
		t.Errorf("expected at least 2 Reasons, got %d: %v", len(result.Reasons), result.Reasons)
	}
	// Reason should be set to the last reason (backward compat).
	if result.Reason == "" {
		t.Error("Reason should be non-empty")
	}
}

func TestVerifyResult_ExpectedScriptHash(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("requires Unix")
	}

	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not in PATH")
	}
	resolvedSh, err := filepath.EvalSymlinks(shPath)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	shHash, err := hashFileByFD(resolvedSh)
	if err != nil {
		t.Fatalf("hashing sh: %v", err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "esh.sh")
	scriptContent := "#!/bin/sh\necho expected\n"
	if err := os.WriteFile(script, []byte(scriptContent), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	scriptHash := hashOfString(t, scriptContent)

	cfg := &Config{
		Enabled: true,
		Action:  testAction,
		Manifests: map[string]string{
			resolvedSh: shHash,
			script:     scriptHash,
		},
	}

	result, err := Verify([]string{"sh", script}, cfg, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.ExpectedScriptHash != scriptHash {
		t.Errorf("ExpectedScriptHash = %q, want %q", result.ExpectedScriptHash, scriptHash)
	}
}

// --- helpers ---

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsSubstring(s, substr)
}

func containsSubstring(s, sub string) bool {
	for i := range len(s) - len(sub) + 1 {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func readFileContent(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading %q: %v", path, err)
	}
	return string(data)
}
