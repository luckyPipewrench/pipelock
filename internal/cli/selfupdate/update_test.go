// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	releasetrust "github.com/luckyPipewrench/pipelock/internal/release"
)

const (
	testLatest  = "v2.8.0"
	testCurrent = "v2.7.0"
	testGOOS    = "linux"
	testGOARCH  = "amd64"
)

var (
	testReleasePriv   = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	testReleasePubHex = hex.EncodeToString(testReleasePriv.Public().(ed25519.PublicKey))
)

// fakeBinaryScript is the payload we pack into the fake archive. The test
// "version verifier" (a stub RunCommand) reads its bytes, not its execution.
func fakeBinaryBytes(version string) []byte {
	return []byte("#!/bin/sh\necho pipelock version " + version + "\n")
}

// makeTarGz builds a gzip-compressed tar containing the named entries.
func makeTarGz(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range entries {
		hdr := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	return buf.Bytes()
}

// makeZip builds a zip archive containing the named entries.
func makeZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func sum(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// readT reads a file the test created. Centralizes the gosec G304 suppression
// (every path here is a test-owned temp file).
func readT(path string) []byte {
	b, _ := os.ReadFile(path) // #nosec G304 -- test reads its own temp file
	return b
}

// releaseServer is a configurable fake GitHub release API + asset host.
type releaseServer struct {
	tag      string
	assets   map[string][]byte // filename -> bytes
	srv      *httptest.Server
	failBody bool // serve 500 on asset download
}

func newReleaseServer(t *testing.T, tag string, assets map[string][]byte) *releaseServer {
	t.Helper()
	rs := &releaseServer{tag: tag, assets: assets}
	mux := http.NewServeMux()

	releaseJSON := func(w http.ResponseWriter, base string) {
		type asset struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		}
		out := struct {
			TagName string  `json:"tag_name"`
			Assets  []asset `json:"assets"`
		}{TagName: rs.tag}
		for name := range rs.assets {
			out.Assets = append(out.Assets, asset{Name: name, URL: base + "/dl/" + name})
		}
		_ = json.NewEncoder(w).Encode(out)
	}

	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		releaseJSON(w, base)
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		if rs.failBody {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/dl/")
		data, ok := rs.assets[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(data)
	})
	rs.srv = httptest.NewServer(mux)
	t.Cleanup(rs.srv.Close)
	return rs
}

// standardAssets builds a coherent release: archive + matching checksums.txt +
// native Ed25519-signed release.json. The manifest is the in-process publisher
// identity check; checksums.txt is only integrity data.
func standardAssets(t *testing.T, version, goos string) (assets map[string][]byte, archiveName string) {
	t.Helper()
	bare := strings.TrimPrefix(version, "v")
	bin := fakeBinaryBytes(bare)
	isZip := goos == "windows"
	var archive []byte
	if isZip {
		archive = makeZip(t, map[string][]byte{archiveBinaryName(goos): bin})
	} else {
		archive = makeTarGz(t, map[string][]byte{archiveBinaryName(goos): bin})
	}
	archiveName = assetName(bare, goos, testGOARCH)
	checks := fmt.Sprintf("%s  %s\n", sum(archive), archiveName)
	manifest, sig := signedReleaseManifest(t, version, goos, archiveName, archive, []byte(checks))
	return map[string][]byte{
		archiveName:                  archive,
		checksumsFile:                []byte(checks),
		checksumsSig:                 []byte("fake-signature"),
		checksumsPEM:                 []byte("fake-certificate"),
		releasetrust.ManifestFile:    manifest,
		releasetrust.ManifestSigFile: sig,
	}, archiveName
}

func signedReleaseManifest(t *testing.T, version, goos, archiveName string, archive, checksums []byte) ([]byte, []byte) {
	t.Helper()
	manifest := releasetrust.Manifest{
		Schema:             "pipelock-release-v1",
		Repo:               "github.com/luckyPipewrench/pipelock",
		Tag:                version,
		Commit:             strings.Repeat("a", 40),
		CreatedUTC:         time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		ChecksumFileSHA256: sum(checksums),
		Assets: []releasetrust.Asset{{
			Name:   archiveName,
			SHA256: sum(archive),
			GOOS:   goos,
			GOARCH: testGOARCH,
			Binary: archiveBinaryName(goos),
		}},
		SignerKeyID: testReleasePubHex, // must match the signing key (verification binds signer_key_id to the verifying key)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal release manifest: %v", err)
	}
	return data, []byte(releasetrust.SignManifest(data, testReleasePriv))
}

// writeTargetBinary creates a stand-in installed binary in a temp dir and
// returns its path. The contents identify it so tests can assert (un)changed.
func writeTargetBinary(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock")
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil { // #nosec G306 -- test fixture binary needs exec bit
		t.Fatalf("write target: %v", err)
	}
	return path
}

// baseOptions wires a test Options pointed at the fake server, with cosign
// present by default so success paths exercise publisher verification.
func baseOptions(rs *releaseServer, target string) *Options {
	return &Options{
		APIBase:           rs.srv.URL,
		HTTPClient:        rs.srv.Client(),
		TargetPath:        target,
		CurrentVersion:    testCurrent,
		GOOS:              testGOOS,
		GOARCH:            testGOARCH,
		ReleaseKeyringHex: testReleasePubHex,
		CosignAvailable:   func() bool { return true },
		RunCommand:        stubVersionRunner(""),
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
	}
}

// stubVersionRunner returns a RunCommand that, for a "--version" call, echoes
// the version string read from the extracted binary file. forceErr (if set)
// makes every invocation fail.
func stubVersionRunner(forceErr string) CommandRunner {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		if forceErr != "" {
			return []byte(forceErr), errors.New(forceErr)
		}
		// Simulate "<binary> --version": read the binary file we extracted and
		// echo its embedded version line.
		if len(args) == 1 && args[0] == "--version" {
			data, err := os.ReadFile(name) // #nosec G304 -- test reads its own temp file
			if err != nil {
				return nil, err
			}
			return data, nil
		}
		return nil, nil
	}
}

func TestCheck_UpdateAvailable(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)

	st, err := opts.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !st.UpdateAvailable {
		t.Fatalf("expected update available; got %+v", st)
	}
	if st.LatestVersion != testLatest {
		t.Fatalf("latest = %q, want %q", st.LatestVersion, testLatest)
	}
	// --check makes NO changes.
	if string(readT(target)) != "OLD" {
		t.Fatalf("Check mutated target: %q", readT(target))
	}
}

func TestCheck_AlreadyCurrent(t *testing.T) {
	assets, _ := standardAssets(t, testCurrent, testGOOS)
	rs := newReleaseServer(t, testCurrent, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)

	st, err := opts.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if st.UpdateAvailable {
		t.Fatalf("expected no update; got %+v", st)
	}
}

func TestRun_SuccessReplacesAndBacksUp(t *testing.T) {
	assets, archiveName := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)

	st, err := opts.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !st.Applied {
		t.Fatalf("expected applied; got %+v", st)
	}
	if st.Asset != archiveName {
		t.Fatalf("asset = %q, want %q", st.Asset, archiveName)
	}
	// Target now holds the new binary contents.
	if got := readT(target); !strings.Contains(string(got), "version 2.8.0") {
		t.Fatalf("target not replaced: %q", got)
	}
	// Backup holds the OLD bytes.
	if bak := readT(target + backupSuffix); string(bak) != "OLD" {
		t.Fatalf("backup = %q, want OLD", bak)
	}
	if st.SignatureSkipped || !st.SignatureVerified {
		t.Fatalf("expected signature verified; got %+v", st)
	}
}

func TestRun_PinnedVersion(t *testing.T) {
	const pinned = "v2.7.5"
	assets, _ := standardAssets(t, pinned, testGOOS)
	rs := newReleaseServer(t, pinned, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)
	opts.TargetVersion = pinned

	st, err := opts.Run(context.Background())
	if err != nil {
		t.Fatalf("Run pinned: %v", err)
	}
	if !st.Applied || st.LatestVersion != pinned {
		t.Fatalf("pinned install failed: %+v", st)
	}
}

func TestRun_DoesNotExecuteDownloadedBinaryBeforeInstall(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("shell-script execution PoC is linux-only")
	}
	marker := filepath.Join(t.TempDir(), "candidate-executed")
	payload := []byte("#!/bin/sh\nprintf executed > " + shellQuote(marker) + "\necho pipelock version 2.8.0\n")
	archive := makeTarGz(t, map[string][]byte{binaryName: payload})
	archiveName := assetName(strings.TrimPrefix(testLatest, "v"), testGOOS, testGOARCH)
	checks := fmt.Sprintf("%s  %s\n", sum(archive), archiveName)
	manifest, sig := signedReleaseManifest(t, testLatest, testGOOS, archiveName, archive, []byte(checks))
	assets := map[string][]byte{
		archiveName:                  archive,
		checksumsFile:                []byte(checks),
		releasetrust.ManifestFile:    manifest,
		releasetrust.ManifestSigFile: sig,
	}
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "ORIGINAL")
	opts := baseOptions(rs, target)
	opts.CosignAvailable = func() bool { return false }
	opts.AllowUnsignedChecksums = true
	opts.RunCommand = defaultCommandRunner

	if _, err := opts.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("downloaded candidate executed before install; marker stat err=%v contents=%q", err, readT(marker))
	}
}

func TestRun_ChecksumMismatchAborts(t *testing.T) {
	assets, archiveName := standardAssets(t, testLatest, testGOOS)
	// Corrupt the checksums entry so it no longer matches the archive.
	checks := []byte("deadbeef  " + archiveName + "\n")
	assets[checksumsFile] = checks
	manifest, sig := signedReleaseManifest(t, testLatest, testGOOS, archiveName, assets[archiveName], checks)
	assets[releasetrust.ManifestFile] = manifest
	assets[releasetrust.ManifestSigFile] = sig
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "ORIGINAL")
	opts := baseOptions(rs, target)

	_, err := opts.Run(context.Background())
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch, got %v", err)
	}
	// Target UNCHANGED.
	if string(readT(target)) != "ORIGINAL" {
		t.Fatalf("target mutated on checksum mismatch: %q", readT(target))
	}
	// No backup created.
	if _, err := os.Stat(target + backupSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup should not exist after abort")
	}
}

func TestRun_NetworkErrorFailsClosed(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	rs.failBody = true // asset downloads return 500
	target := writeTargetBinary(t, "ORIGINAL")
	opts := baseOptions(rs, target)

	_, err := opts.Run(context.Background())
	if err == nil {
		t.Fatalf("expected network error, got nil")
	}
	if string(readT(target)) != "ORIGINAL" {
		t.Fatalf("target mutated on network error: %q", readT(target))
	}
}

func TestRun_ManifestTagMismatchAborts(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	archiveName := assetName(strings.TrimPrefix(testLatest, "v"), testGOOS, testGOARCH)
	archive := assets[archiveName]
	checks := assets[checksumsFile]
	manifest, sig := signedReleaseManifest(t, "v9.9.9", testGOOS, archiveName, archive, checks)
	assets[releasetrust.ManifestFile] = manifest
	assets[releasetrust.ManifestSigFile] = sig
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "ORIGINAL")
	opts := baseOptions(rs, target)

	_, err := opts.Run(context.Background())
	if !errors.Is(err, ErrSignatureVerify) {
		t.Fatalf("expected ErrSignatureVerify, got %v", err)
	}
	if string(readT(target)) != "ORIGINAL" {
		t.Fatalf("target mutated on manifest mismatch: %q", readT(target))
	}
	// Temp file should be cleaned up (no leftover .pipelock-update-* in dir).
	assertNoTempLeftovers(t, filepath.Dir(target))
}

func TestRun_UnsupportedPlatform(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "ORIGINAL")
	opts := baseOptions(rs, target)
	opts.GOOS = "plan9"
	opts.GOARCH = "mips"

	_, err := opts.Run(context.Background())
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("expected ErrUnsupportedPlatform, got %v", err)
	}
	if string(readT(target)) != "ORIGINAL" {
		t.Fatalf("target mutated on unsupported platform: %q", readT(target))
	}
}

func TestRun_WindowsZip(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, "windows")
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)
	opts.GOOS = "windows"
	opts.GOARCH = "amd64"

	st, err := opts.Run(context.Background())
	if err != nil {
		t.Fatalf("Run windows: %v", err)
	}
	if !st.Applied {
		t.Fatalf("windows zip update not applied: %+v", st)
	}
	if !strings.HasSuffix(st.Asset, ".zip") {
		t.Fatalf("expected .zip asset, got %q", st.Asset)
	}
}

func assertNoTempLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".pipelock-update-") ||
			strings.HasPrefix(e.Name(), ".pipelock-copy-") ||
			strings.HasPrefix(e.Name(), ".pipelock-rollback-") {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
}
