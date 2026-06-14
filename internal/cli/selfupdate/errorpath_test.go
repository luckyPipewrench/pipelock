// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchRelease_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	opts := &Options{APIBase: srv.URL, HTTPClient: srv.Client(), TargetPath: writeTargetBinary(t, "x")}
	if err := opts.fillDefaults(); err != nil {
		t.Fatalf("fillDefaults: %v", err)
	}
	if _, err := opts.fetchRelease(context.Background()); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestFetchRelease_MissingTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"assets":[]}`))
	}))
	defer srv.Close()
	opts := &Options{APIBase: srv.URL, HTTPClient: srv.Client(), TargetPath: writeTargetBinary(t, "x")}
	_ = opts.fillDefaults()
	if _, err := opts.fetchRelease(context.Background()); err == nil || !strings.Contains(err.Error(), "tag_name") {
		t.Fatalf("expected missing tag_name error, got %v", err)
	}
}

func TestFetchRelease_HTTPStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	opts := &Options{APIBase: srv.URL, HTTPClient: srv.Client(), TargetPath: writeTargetBinary(t, "x"), TargetVersion: "v9.9.9"}
	_ = opts.fillDefaults()
	if _, err := opts.fetchRelease(context.Background()); err == nil {
		t.Fatal("expected non-200 error")
	}
}

func TestHTTPGet_SizeCapExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Stream more than the cap.
		buf := make([]byte, 1<<20)
		for range (maxDownloadBytes / len(buf)) + 2 {
			_, _ = w.Write(buf)
		}
	}))
	defer srv.Close()
	opts := &Options{HTTPClient: srv.Client()}
	if _, err := opts.httpGet(context.Background(), srv.URL); err == nil ||
		!strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("expected size cap error, got %v", err)
	}
}

func TestHTTPGet_BadRequest(t *testing.T) {
	opts := &Options{HTTPClient: http.DefaultClient}
	// A URL with a control character fails http.NewRequestWithContext.
	if _, err := opts.httpGet(context.Background(), "http://example.com/\x7f"); err == nil {
		t.Fatal("expected request-creation error")
	}
}

func TestRollback_BackupIsDirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "pipelock")
	if err := os.WriteFile(target, []byte("NEW"), 0o755); err != nil { // #nosec G306 -- test fixture binary needs exec bit
		t.Fatalf("write target: %v", err)
	}
	// Make the backup path a DIRECTORY so copyFile(open) fails mid-rollback.
	if err := os.Mkdir(target+backupSuffix, 0o755); err != nil { // #nosec G301 -- test fixture directory
		t.Fatalf("mkdir backup: %v", err)
	}
	opts := &Options{TargetPath: target, CurrentVersion: testCurrent, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	if _, err := opts.Rollback(context.Background()); err == nil {
		t.Fatal("expected rollback staging error")
	}
}

func TestFillDefaults_PopulatesAll(t *testing.T) {
	opts := &Options{TargetPath: writeTargetBinary(t, "x")}
	if err := opts.fillDefaults(); err != nil {
		t.Fatalf("fillDefaults: %v", err)
	}
	if opts.APIBase != defaultAPIBase || opts.HTTPClient == nil || opts.GOOS == "" ||
		opts.GOARCH == "" || opts.CosignAvailable == nil || opts.RunCommand == nil ||
		opts.Stdout == nil || opts.Stderr == nil {
		t.Fatalf("defaults not fully populated: %+v", opts)
	}
	// APIBase trailing slash trimmed.
	opts2 := &Options{APIBase: "https://x/", TargetPath: writeTargetBinary(t, "y")}
	_ = opts2.fillDefaults()
	if opts2.APIBase != "https://x" {
		t.Fatalf("trailing slash not trimmed: %q", opts2.APIBase)
	}
}

func TestCopyFile_SourceMissing(t *testing.T) {
	dir := t.TempDir()
	err := copyFile(filepath.Join(dir, "nope"), filepath.Join(dir, "dst"))
	if err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestCopyFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	got, _ := os.ReadFile(dst) // #nosec G304 -- test reads its own temp file
	if string(got) != "payload" {
		t.Fatalf("dst = %q", got)
	}
	info, _ := os.Stat(dst)
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("perm = %v", info.Mode().Perm())
	}
}

func TestCopyFile_DestDirMissing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	// dst dir doesn't exist -> CreateTemp fails.
	err := copyFile(src, filepath.Join(dir, "missing", "dst"))
	if err == nil {
		t.Fatal("expected error for missing dst dir")
	}
}

func TestInstallBinary_BackupFails(t *testing.T) {
	dir := t.TempDir()
	// target's source file is missing so the backup copy (copyFile target->bak) fails.
	target := filepath.Join(dir, "pipelock") // does not exist
	_, err := installBinary(target, filepath.Join(dir, "tmp"))
	if err == nil {
		t.Fatal("expected backup failure")
	}
	if !strings.Contains(err.Error(), "backing up") {
		t.Fatalf("expected backup error, got %v", err)
	}
}

func TestInstallBinary_RestoreOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "pipelock")
	if err := os.WriteFile(target, []byte("ORIGINAL"), 0o755); err != nil { // #nosec G306 -- test fixture binary needs exec bit
		t.Fatalf("write target: %v", err)
	}
	// tmpPath points at a directory, so os.Rename(tmp, target) fails -> restore path.
	tmpDir := filepath.Join(dir, "tmpisdir")
	if err := os.Mkdir(tmpDir, 0o755); err != nil { // #nosec G301 -- test fixture directory
		t.Fatalf("mkdir: %v", err)
	}
	_, err := installBinary(target, tmpDir)
	if err == nil {
		t.Fatal("expected rename failure")
	}
	// After failed rename, target restored to ORIGINAL from backup.
	if string(readT(target)) != "ORIGINAL" {
		t.Fatalf("target not restored: %q", readT(target))
	}
}

func TestVerifyBinaryVersion_RunError(t *testing.T) {
	opts := &Options{RunCommand: stubVersionRunner("boom")}
	err := opts.verifyBinaryVersion(context.Background(), "/x", "2.8.0")
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("expected ErrVersionMismatch, got %v", err)
	}
}

func TestRun_NoArchiveAssetOnPinned(t *testing.T) {
	// Release exists with checksums but NO archive for our os/arch.
	assets, _ := standardAssets(t, testLatest, testGOOS)
	delete(assets, assetName(strings.TrimPrefix(testLatest, "v"), testGOOS, testGOARCH))
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "ORIGINAL")
	opts := baseOptions(rs, target)
	_, err := opts.Run(context.Background())
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("expected ErrUnsupportedPlatform, got %v", err)
	}
	if string(readT(target)) != "ORIGINAL" {
		t.Fatalf("target mutated: %q", readT(target))
	}
}

func TestRun_MissingChecksumsAsset(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	delete(assets, checksumsFile)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "ORIGINAL")
	opts := baseOptions(rs, target)
	_, err := opts.Run(context.Background())
	if err == nil {
		t.Fatal("expected error when checksums asset missing")
	}
	if string(readT(target)) != "ORIGINAL" {
		t.Fatalf("target mutated: %q", readT(target))
	}
}

func TestEmit_HumanAndJSON(t *testing.T) {
	out := &bytes.Buffer{}
	cmd := Cmd()
	cmd.SetOut(out)
	// human
	if err := emit(cmd, &Options{}, &Status{}, "hello"); err != nil {
		t.Fatalf("emit human: %v", err)
	}
	if !strings.Contains(out.String(), "hello") {
		t.Fatalf("human output missing: %q", out.String())
	}
	// json
	out.Reset()
	if err := emit(cmd, &Options{JSON: true}, &Status{LatestVersion: "v9"}, "ignored"); err != nil {
		t.Fatalf("emit json: %v", err)
	}
	if !strings.Contains(out.String(), `"latest_version": "v9"`) {
		t.Fatalf("json output wrong: %q", out.String())
	}
}

func TestDisplay(t *testing.T) {
	if display("") != "unknown" {
		t.Fatal("empty should be unknown")
	}
	if display("v2.7.0") != "v2.7.0" {
		t.Fatal("passthrough")
	}
}
