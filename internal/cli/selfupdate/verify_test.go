// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_CosignAbsentFailsClosedByDefault(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "ORIGINAL")
	opts := baseOptions(rs, target)
	opts.CosignAvailable = func() bool { return false }

	_, err := opts.Run(context.Background())
	if !errors.Is(err, ErrSignatureUnavailable) {
		t.Fatalf("expected ErrSignatureUnavailable, got %v", err)
	}
	if string(readT(target)) != "ORIGINAL" {
		t.Fatalf("target mutated when cosign unavailable: %q", readT(target))
	}
	if _, err := os.Stat(target + backupSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup should not exist after signature-unavailable abort")
	}
}

func TestRun_InsecureSkipSignatureAllowsChecksumOnly(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)
	stderr := &bytes.Buffer{}
	opts.Stderr = stderr
	opts.CosignAvailable = func() bool { return false }
	opts.AllowUnsignedChecksums = true

	st, err := opts.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !st.Applied || !st.SignatureSkipped || st.SignatureVerified {
		t.Fatalf("expected applied + skipped, got %+v", st)
	}
	if !strings.Contains(stderr.String(), "--insecure-skip-signature") {
		t.Fatalf("expected insecure warning, got %q", stderr.String())
	}
}

func TestRun_CosignPresentAndPasses(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)
	opts.CosignAvailable = func() bool { return true }
	var cosignArgs []string
	// Runner: cosign verify-blob succeeds; --version echoes the binary file.
	opts.RunCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == cosignBinary {
			cosignArgs = append([]string(nil), args...)
			return []byte("Verified OK"), nil
		}
		return stubVersionRunner("")(ctx, name, args...)
	}

	st, err := opts.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !st.Applied || st.SignatureSkipped || !st.SignatureVerified {
		t.Fatalf("expected applied + verified, got %+v", st)
	}
	if !containsArgPair(cosignArgs, "--certificate-identity", fmt.Sprintf(releaseWorkflowIdentity, testLatest)) {
		t.Fatalf("cosign args did not pin release workflow identity: %v", cosignArgs)
	}
}

func TestRun_CosignPresentAndFailsAborts(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "ORIGINAL")
	opts := baseOptions(rs, target)
	opts.CosignAvailable = func() bool { return true }
	opts.RunCommand = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == cosignBinary {
			return []byte("error: no matching signatures"), errors.New("exit status 1")
		}
		return nil, nil
	}

	_, err := opts.Run(context.Background())
	if !errors.Is(err, ErrSignatureVerify) {
		t.Fatalf("expected ErrSignatureVerify, got %v", err)
	}
	if string(readT(target)) != "ORIGINAL" {
		t.Fatalf("target mutated on signature failure: %q", readT(target))
	}
	if _, err := os.Stat(target + backupSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup should not exist after signature abort")
	}
}

func TestExtractBinary_TarTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	archive := makeTarGz(t, map[string][]byte{"../../etc/evil": []byte("x")})
	_, err := extractBinary(archive, false, dir, binaryName)
	// Traversal entry is rejected; since it's the only entry, either the unsafe
	// error or "not found" is acceptable — but it must NOT write outside dir.
	if err == nil {
		t.Fatalf("expected error for traversal archive")
	}
	if !errors.Is(err, ErrUnsafeArchive) && !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSafeEntryName(t *testing.T) {
	cases := []struct {
		name    string
		wantErr bool
		wantOut string
	}{
		{"pipelock", false, "pipelock"},
		{"dir/pipelock", false, "pipelock"},
		{`dir\pipelock`, false, "pipelock"},
		{"../pipelock", true, ""},
		{"a/../../pipelock", true, ""},
		{`..\pipelock`, true, ""},
		{"/abs/pipelock", true, ""},
		{`C:\abs\pipelock`, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := safeEntryName(tc.name)
			if tc.wantErr {
				if !errors.Is(err, ErrUnsafeArchive) {
					t.Fatalf("want ErrUnsafeArchive, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.wantOut {
				t.Fatalf("got %q want %q", got, tc.wantOut)
			}
		})
	}
}

func TestExtractZip_TraversalRejected(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("../../evil")
	_, _ = w.Write([]byte("x"))
	_ = zw.Close()
	_, err := extractBinary(buf.Bytes(), true, dir, binaryName)
	if err == nil {
		t.Fatalf("expected error for zip-slip")
	}
}

func TestExtractZip_WindowsExeEntry(t *testing.T) {
	dir := t.TempDir()
	archive := makeZip(t, map[string][]byte{
		archiveBinaryName("windows"): fakeBinaryBytes("2.8.0"),
	})
	tmp, err := extractBinary(archive, true, dir, archiveBinaryName("windows"))
	if err != nil {
		t.Fatalf("extract windows zip: %v", err)
	}
	if !strings.HasSuffix(tmp, ".exe") {
		t.Fatalf("windows temp binary should keep .exe suffix, got %q", tmp)
	}
	got, _ := os.ReadFile(tmp) // #nosec G304 -- test temp file
	if !strings.Contains(string(got), "version 2.8.0") {
		t.Fatalf("wrong binary extracted: %q", got)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestCopyBounded_RejectsOversize(t *testing.T) {
	err := copyBounded(io.Discard, io.LimitReader(zeroReader{}, maxDownloadBytes+1))
	if !errors.Is(err, ErrBinaryTooLarge) {
		t.Fatalf("expected ErrBinaryTooLarge, got %v", err)
	}
}

func TestVersionOutputMatchesWholeTokenOnly(t *testing.T) {
	if !versionOutputMatches("pipelock version 2.8.0\n", "2.8.0") {
		t.Fatal("expected exact bare version token to match")
	}
	if !versionOutputMatches("pipelock version v2.8.0\n", "2.8.0") {
		t.Fatal("expected exact v-prefixed version token to match")
	}
	if versionOutputMatches("pipelock version 12.8.0\n", "2.8.0") {
		t.Fatal("substring version match should fail")
	}
	// Pre-release pins must match EXACTLY, not collapse to the core version.
	if !versionOutputMatches("pipelock version 2.8.0-rc1\n", "v2.8.0-rc1") {
		t.Fatal("expected exact pre-release token to match")
	}
	if versionOutputMatches("pipelock version 2.8.0\n", "2.8.0-rc1") {
		t.Fatal("a stable binary must NOT satisfy a pre-release pin")
	}
	if versionOutputMatches("pipelock version 2.8.0-rc2\n", "2.8.0-rc1") {
		t.Fatal("rc2 binary must NOT satisfy an rc1 pin")
	}
}

// TestVersionTagPreservesPrerelease guards the bareVersion-vs-versionTag split:
// asset names and version checks must keep the pre-release suffix so a pinned
// "v2.8.0-rc1" resolves the rc archive, not the stable one.
func TestVersionTagPreservesPrerelease(t *testing.T) {
	if got := versionTag("v2.8.0-rc1"); got != "2.8.0-rc1" {
		t.Fatalf("versionTag should keep pre-release: got %q", got)
	}
	if got := bareVersion("v2.8.0-rc1"); got != "2.8.0" {
		t.Fatalf("bareVersion should drop pre-release for comparison: got %q", got)
	}
	if got := assetName(versionTag("v2.8.0-rc1"), "linux", "amd64"); got != "pipelock_2.8.0-rc1_linux_amd64.tar.gz" {
		t.Fatalf("pre-release asset name wrong: got %q", got)
	}
}

func TestRun_TargetNotWritableAborts(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits don't gate writes")
	}
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)

	// Put the target in a directory we make read-only.
	dir := t.TempDir()
	roDir := filepath.Join(dir, "ro")
	if err := os.Mkdir(roDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(roDir, "pipelock")
	if err := os.WriteFile(target, []byte("ORIGINAL"), 0o755); err != nil { // #nosec G306 -- test fixture binary needs exec bit
		t.Fatalf("write target: %v", err)
	}
	// Drop write on the dir AFTER placing the file.
	if err := os.Chmod(roDir, 0o500); err != nil { // #nosec G302 -- test needs a read-only dir to exercise the not-writable abort
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) }) // #nosec G302 -- restore writable so TempDir cleanup can remove it

	opts := baseOptions(rs, target)
	_, err := opts.Run(context.Background())
	if !errors.Is(err, ErrNotWritable) {
		t.Fatalf("expected ErrNotWritable, got %v", err)
	}
	if string(readT(target)) != "ORIGINAL" {
		t.Fatalf("target mutated despite not-writable: %q", readT(target))
	}
}

func TestRollback_RestoresBackup(t *testing.T) {
	target := writeTargetBinary(t, "NEW")
	// Place a backup.
	if err := os.WriteFile(target+backupSuffix, []byte("PREVIOUS"), 0o755); err != nil { // #nosec G306 -- test fixture binary needs exec bit
		t.Fatalf("write backup: %v", err)
	}
	opts := &Options{
		TargetPath:     target,
		CurrentVersion: testCurrent,
		Stdout:         &bytes.Buffer{},
		Stderr:         &bytes.Buffer{},
	}
	st, err := opts.Rollback(context.Background())
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !st.Applied {
		t.Fatalf("rollback not applied: %+v", st)
	}
	if string(readT(target)) != "PREVIOUS" {
		t.Fatalf("target = %q, want PREVIOUS", readT(target))
	}
}

func TestRollback_NoBackup(t *testing.T) {
	target := writeTargetBinary(t, "NEW")
	opts := &Options{
		TargetPath:     target,
		CurrentVersion: testCurrent,
		Stdout:         &bytes.Buffer{},
		Stderr:         &bytes.Buffer{},
	}
	_, err := opts.Rollback(context.Background())
	if !errors.Is(err, ErrNoBackup) {
		t.Fatalf("expected ErrNoBackup, got %v", err)
	}
}

func TestIsNewer(t *testing.T) {
	cases := []struct {
		cur, latest string
		want        bool
	}{
		{"v2.7.0", "v2.8.0", true},
		{"v2.7.0", "v2.7.1", true},
		{"v2.7.0", "v3.0.0", true},
		{"v2.7.0", "v2.7.0", false},
		{"v2.8.0", "v2.7.0", false},
		{"0.1.0-dev", "v2.8.0", true}, // dev build -> any real release is newer
		{"unknown", "v2.8.0", true},   // unparseable current -> newer
		{"v2.7.0", "garbage", false},  // unparseable latest -> not newer
	}
	for _, tc := range cases {
		t.Run(tc.cur+"->"+tc.latest, func(t *testing.T) {
			if got := isNewer(tc.cur, tc.latest); got != tc.want {
				t.Fatalf("isNewer(%q,%q) = %v, want %v", tc.cur, tc.latest, got, tc.want)
			}
		})
	}
}

func TestParseChecksums(t *testing.T) {
	data := []byte("abc123  pipelock_2.8.0_linux_amd64.tar.gz\n" +
		"def456  pipelock_2.8.0_darwin_arm64.tar.gz\n" +
		"malformed-line-no-sep\n")
	m := parseChecksums(data)
	if m["pipelock_2.8.0_linux_amd64.tar.gz"] != "abc123" {
		t.Fatalf("linux entry wrong: %v", m)
	}
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(m), m)
	}
}

func TestAssetName(t *testing.T) {
	if got := assetName("2.8.0", "linux", "amd64"); got != "pipelock_2.8.0_linux_amd64.tar.gz" {
		t.Fatalf("linux: %q", got)
	}
	if got := assetName("2.8.0", "windows", "amd64"); got != "pipelock_2.8.0_windows_amd64.zip" {
		t.Fatalf("windows: %q", got)
	}
}

func containsArgPair(args []string, key, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}
