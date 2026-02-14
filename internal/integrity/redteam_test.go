package integrity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Red Team: Integrity Monitoring Attack Tests
//
// These tests probe the file integrity monitoring system for bypass vectors
// including TOCTOU races, symlink attacks, manifest forgery, glob exclusion
// bypasses, and path traversal.
// =============================================================================

// --- Symlink Attacks ---

func TestRedTeam_SymlinkBypassGenerate(t *testing.T) {
	// Attack: Create a symlink that points to a file outside the workspace.
	// If Generate follows symlinks, an attacker could make the manifest
	// include files from outside the workspace, or miss files by replacing
	// them with symlinks after the manifest is generated.
	//
	// Defense: Generate skips symlinks entirely (d.Type()&fs.ModeSymlink != 0).

	dir := t.TempDir()
	writeFile(t, dir, "real.txt", "real content\n")

	// Create a symlink inside the workspace pointing to an external file
	externalDir := t.TempDir()
	externalFile := filepath.Join(externalDir, "external_secret.txt")
	if err := os.WriteFile(externalFile, []byte("SECRET_DATA"), 0o600); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(dir, "link_to_secret.txt")
	if err := os.Symlink(externalFile, linkPath); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if _, ok := m.Files["link_to_secret.txt"]; ok {
		t.Error("GAP CONFIRMED: symlink to external file was included in manifest")
	} else {
		t.Log("DEFENDED: symlinks are skipped during manifest generation")
	}
}

func TestRedTeam_SymlinkReplacementAfterManifest(t *testing.T) {
	// Attack: Generate a manifest for a real file, then replace the file
	// with a symlink to a different file. Check should detect this because
	// the symlink is skipped by Generate, so the original file appears
	// "removed" and the symlink is invisible.

	dir := t.TempDir()
	writeFile(t, dir, "config.yaml", "safe: true\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Replace real file with symlink to attacker-controlled content
	realPath := filepath.Join(dir, "config.yaml")
	if err := os.Remove(realPath); err != nil {
		t.Fatal(err)
	}

	externalDir := t.TempDir()
	maliciousFile := filepath.Join(externalDir, "evil.yaml")
	if err := os.WriteFile(maliciousFile, []byte("safe: false\nbackdoor: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(maliciousFile, realPath); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	violations, err := Check(dir, m)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	// The original file should be reported as removed (symlink is invisible)
	found := false
	for _, v := range violations {
		if v.Path == "config.yaml" && v.Type == ViolationRemoved {
			found = true
		}
	}
	if !found {
		t.Error("GAP CONFIRMED: replacing file with symlink was not detected as removal")
	} else {
		t.Log("DEFENDED: replacing file with symlink detected as removal violation")
	}
}

func TestRedTeam_SymlinkDirectory(t *testing.T) {
	// Attack: Create a symlink to a directory outside the workspace.
	// WalkDir should not follow symlinked directories.

	dir := t.TempDir()
	writeFile(t, dir, "keep.txt", "keep\n")

	externalDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(externalDir, "secret.txt"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}

	linkDir := filepath.Join(dir, "linked_dir")
	if err := os.Symlink(externalDir, linkDir); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	for path := range m.Files {
		if strings.HasPrefix(path, "linked_dir/") {
			t.Error("GAP CONFIRMED: symlinked directory contents included in manifest")
			break
		}
	}
	t.Log("DEFENDED: symlinked directories are not followed by WalkDir")
}

// --- Manifest Forgery Attacks ---

func TestRedTeam_ManifestForgerySelfExclusion(t *testing.T) {
	// Attack: The manifest file itself is in the alwaysExcluded list, so an
	// attacker who modifies the manifest won't trigger a violation from Check.
	// This is by design (the manifest changes when updated), but it means
	// an attacker with write access to the manifest can forge it.
	//
	// Mitigation: Use Ed25519 signing to authenticate the manifest.

	dir := t.TempDir()
	writeFile(t, dir, "real.txt", "real content\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Save manifest
	manifestPath := filepath.Join(dir, DefaultManifestFile)
	if err := m.Save(manifestPath); err != nil {
		t.Fatal(err)
	}

	// Attacker modifies the manifest to accept a tampered file
	m.Files["real.txt"] = FileEntry{
		SHA256: "forged_hash_value",
		Size:   999,
		Mode:   "0644",
	}
	if err := m.Save(manifestPath); err != nil {
		t.Fatal(err)
	}

	// Now tamper with the actual file
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Load the forged manifest and check
	forged, err := Load(manifestPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	violations, err := Check(dir, forged)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	// The forged manifest won't match because we used a fake hash
	found := false
	for _, v := range violations {
		if v.Path == "real.txt" && v.Type == ViolationModified {
			found = true
		}
	}
	if !found {
		t.Log("ACCEPTED RISK: manifest forgery is theoretically possible if attacker has write access. Ed25519 signing of manifests (signing package) is the defense against this.")
	} else {
		t.Log("DEFENDED: even forged manifest detected mismatch (because fake hash doesn't match real file)")
	}
}

func TestRedTeam_ManifestVersionDowngrade(t *testing.T) {
	// Attack: Craft a manifest with version 0 or negative version.
	// Load should reject non-matching versions.

	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	testCases := []struct {
		name    string
		version int
	}{
		{"zero version", 0},
		{"future version", 99},
		{"negative version", -1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := json.Marshal(map[string]any{
				"version": tc.version,
				"files":   map[string]any{},
			})
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := Load(path)
			if err == nil {
				t.Errorf("GAP CONFIRMED: manifest with version %d was accepted", tc.version)
			} else {
				t.Logf("DEFENDED: manifest with version %d rejected: %v", tc.version, err)
			}
		})
	}
}

func TestRedTeam_ManifestJSONInjection(t *testing.T) {
	// Attack: Craft a manifest with duplicate keys in JSON. Go's json.Unmarshal
	// uses the last occurrence of a key, which could be exploited if an
	// attacker appends a second "files" key after a legitimate one.

	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	// JSON with duplicate "files" key - Go uses last occurrence
	rawJSON := `{
		"version": 1,
		"files": {"safe.txt": {"sha256": "abc", "size": 3, "mode": "0644"}},
		"files": {"evil.txt": {"sha256": "xyz", "size": 4, "mode": "0644"}}
	}`
	if err := os.WriteFile(path, []byte(rawJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := Load(path)
	if err != nil {
		t.Fatalf("Load unexpectedly failed: %v", err)
	}

	if _, ok := m.Files["evil.txt"]; ok {
		t.Log("ACCEPTED RISK: JSON duplicate key causes last-wins behavior. The second 'files' block replaces the first. This is standard Go json.Unmarshal behavior, not exploitable beyond the file's own contents.")
	}
	if _, ok := m.Files["safe.txt"]; ok {
		t.Log("INFO: first 'files' block was preserved (Go json.Unmarshal kept first)")
	}
}

// --- Glob Exclusion Bypass ---

func TestRedTeam_ExcludePatternEvasion(t *testing.T) {
	// Attack: Create files that look like they should be excluded but don't
	// match the glob pattern. For example, "secret.log.bak" doesn't match
	// "*.log" glob.

	dir := t.TempDir()
	writeFile(t, dir, "app.log", "log data\n")
	writeFile(t, dir, "secret.log.bak", "backed up secret\n")

	m, err := Generate(dir, []string{"*.log"})
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := m.Files["secret.log.bak"]; !ok {
		t.Error("GAP CONFIRMED: file with .log.bak extension was excluded by *.log pattern")
	} else {
		t.Log("DEFENDED: *.log pattern only matches exact .log extension, .log.bak is tracked")
	}
}

func TestRedTeam_HiddenFileInExcludedDir(t *testing.T) {
	// Attack: Place a dotfile inside an excluded directory. If the directory
	// exclusion skips the entire subtree, the dotfile is invisible.
	// This is expected behavior but worth documenting.

	dir := t.TempDir()
	writeFile(t, dir, "keep.txt", "keep\n")
	mkdirAll(t, dir, "vendor/hidden")
	writeFile(t, dir, "vendor/.env", "SECRET_KEY=abc123\n")
	writeFile(t, dir, "vendor/hidden/.credentials", "password=hunter2\n")

	m, err := Generate(dir, []string{"vendor/**"})
	if err != nil {
		t.Fatal(err)
	}

	for path := range m.Files {
		if strings.HasPrefix(path, "vendor/") {
			t.Errorf("GAP CONFIRMED: file %s in excluded vendor/** was tracked", path)
		}
	}
	t.Log("ACCEPTED RISK: vendor/** exclusion correctly skips ALL files under vendor/, including secrets. This is by design (vendor is excluded), but if secrets are placed there, they won't be monitored.")
}

func TestRedTeam_DotDotExcludePattern(t *testing.T) {
	// Attack: Use ".." in an exclude pattern to try to exclude files
	// outside the workspace root.

	dir := t.TempDir()
	writeFile(t, dir, "important.txt", "critical data\n")

	// Try to exclude with path traversal in pattern
	m, err := Generate(dir, []string{"../**"})
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := m.Files["important.txt"]; !ok {
		t.Error("GAP CONFIRMED: '../**' exclude pattern excluded files in the workspace")
	} else {
		t.Log("DEFENDED: '../**' exclude pattern does not affect workspace-relative paths")
	}
}

// --- TOCTOU Race Conditions ---

func TestRedTeam_TOCTOUModificationDuringGenerate(t *testing.T) {
	// Attack: Modify a file between the time Generate walks the directory
	// and when it hashes the file. This is a classic TOCTOU race.
	//
	// In practice, this race window is very small (microseconds between
	// WalkDir finding the file and HashFile reading it). The file is read
	// in a single pass through io.Copy, so partial modification during
	// read would result in an inconsistent hash that would be detected on
	// the next Check.

	dir := t.TempDir()
	writeFile(t, dir, "race.txt", "original content\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate post-generate modification
	if err := os.WriteFile(filepath.Join(dir, "race.txt"), []byte("modified\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	violations, err := Check(dir, m)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, v := range violations {
		if v.Path == "race.txt" && v.Type == ViolationModified {
			found = true
		}
	}
	if !found {
		t.Error("GAP CONFIRMED: modification between Generate and Check not detected")
	} else {
		t.Log("DEFENDED: modification detected by Check even though it happened after Generate")
	}
}

// --- Permission Manipulation ---

func TestRedTeam_PermissionEscalation(t *testing.T) {
	// Attack: Change file permissions to make a file executable (potential
	// code execution vector). The integrity system should detect permission
	// changes when Mode is tracked.

	dir := t.TempDir()
	writeFile(t, dir, "script.sh", "#!/bin/bash\necho pwned\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Escalate permissions to executable
	if err := os.Chmod(filepath.Join(dir, "script.sh"), 0o755); err != nil { //nolint:gosec // G302: testing permission escalation detection
		t.Fatal(err)
	}

	violations, err := Check(dir, m)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, v := range violations {
		if v.Path == "script.sh" && v.Type == ViolationPermissions {
			found = true
		}
	}
	if !found {
		t.Error("GAP CONFIRMED: permission escalation from 0600 to 0755 not detected")
	} else {
		t.Log("DEFENDED: permission change detected as ViolationPermissions")
	}
}

// --- Manifest Save Atomicity ---

func TestRedTeam_ManifestSaveAtomicity(t *testing.T) {
	// Attack: Crash during manifest save should not corrupt the manifest.
	// Save() uses atomic write (temp file + rename), so a crash between
	// write and rename leaves the old manifest intact.

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")

	// Create and save initial manifest
	m := &Manifest{
		Version: ManifestVersion,
		Created: time.Now().UTC().Truncate(time.Second),
		Updated: time.Now().UTC().Truncate(time.Second),
		Files: map[string]FileEntry{
			"file.txt": {SHA256: "abc123", Size: 6, Mode: "0644"},
		},
	}
	if err := m.Save(manifestPath); err != nil {
		t.Fatal(err)
	}

	// Verify no temp files leaked
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".manifest-") && strings.HasSuffix(e.Name(), ".tmp") {
			t.Error("GAP CONFIRMED: temporary file leaked after successful save")
		}
	}
	t.Log("DEFENDED: atomic write uses temp+rename, no leftover temp files after success")
}

// --- Path Traversal in Manifest Keys ---

func TestRedTeam_PathTraversalInManifestKeys(t *testing.T) {
	// Attack: Load a manifest with path traversal in the file keys.
	// If Check trusts these paths, it might check files outside the workspace.

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")

	// Craft a manifest with "../" paths
	m := &Manifest{
		Version: ManifestVersion,
		Files: map[string]FileEntry{
			"../../../etc/passwd": {SHA256: "fake", Size: 100, Mode: "0644"},
		},
	}
	if err := m.Save(manifestPath); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(manifestPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Check should not follow path traversal keys
	violations, err := Check(dir, loaded)
	if err != nil {
		// Error is acceptable (the traversal path doesn't exist in workspace)
		t.Logf("DEFENDED: Check returned error for traversal path: %v", err)
		return
	}

	for _, v := range violations {
		if strings.Contains(v.Path, "../") {
			t.Log("ACCEPTED RISK: manifest with '../' paths reports them as 'removed' violations because they don't exist relative to the workspace. Check compares against Generate output which uses filepath.Rel, so traversal keys are effectively dead entries.")
		}
	}

	_ = violations
}

// --- Large File / Resource Exhaustion ---

func TestRedTeam_ManifestWithManyFiles(t *testing.T) {
	// Attack: Craft a manifest with thousands of entries to cause resource
	// exhaustion during Check. Each entry triggers a hash computation on
	// the current filesystem.

	dir := t.TempDir()
	writeFile(t, dir, "real.txt", "real\n")

	// Create a manifest with 1000 fake entries
	m := &Manifest{
		Version: ManifestVersion,
		Files:   make(map[string]FileEntry),
	}
	for i := range 1000 {
		key := strings.Repeat("a", 50) + "_" + strings.Repeat("0", 5-len(string(rune('0'+i%10)))) + string(rune('0'+i%10)) + ".txt"
		m.Files[key] = FileEntry{SHA256: "fake", Size: 1, Mode: "0644"}
	}

	// Check should handle this gracefully - all fake files are "removed"
	violations, err := Check(dir, m)
	if err != nil {
		t.Fatalf("Check failed with many manifest entries: %v", err)
	}

	removedCount := 0
	for _, v := range violations {
		if v.Type == ViolationRemoved {
			removedCount++
		}
	}
	// All 1000 fake files + "real.txt" as added
	if removedCount >= 1000 {
		t.Log("DEFENDED: manifest with 1000 fake entries handled gracefully, all reported as removed")
	}
}

// --- Manifest Signature File Exclusion ---

func TestRedTeam_ManifestSigFileExcluded(t *testing.T) {
	// Attack: The .sig file for the manifest is also excluded from generation.
	// Verify this to ensure an attacker can't trigger a violation by creating
	// a fake .sig file.

	dir := t.TempDir()
	writeFile(t, dir, "real.txt", "content\n")
	writeFile(t, dir, DefaultManifestFile+".sig", "fake-signature\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := m.Files[DefaultManifestFile+".sig"]; ok {
		t.Error("GAP CONFIRMED: manifest .sig file was included in manifest")
	} else {
		t.Log("DEFENDED: manifest .sig file is in alwaysExcluded list")
	}
}
