// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// parseChecksums maps filename -> sha256 hex from a GoReleaser checksums.txt.
// Each line is "<hex>  <filename>". Lines that don't parse are skipped.
func parseChecksums(data []byte) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		out[fields[1]] = strings.ToLower(fields[0])
	}
	return out
}

// verifyPublisherSignature checks checksums.txt against its keyless cosign
// signature. Behavior:
//   - cosign NOT on PATH: returns ErrSignatureUnavailable unless the caller
//     explicitly enabled checksum-only mode.
//   - cosign present and verification FAILS: returns (false, ErrSignatureVerify)
//     — fail-closed, caller aborts with no changes.
//   - cosign present and verification PASSES: returns (false-skipped, nil).
//
// It is a single helper with injected availability + runner so tests cover
// all three paths without a real cosign binary.
func (o *Options) verifyPublisherSignature(ctx context.Context, dir, tagName string) (skipped bool, err error) {
	if !o.CosignAvailable() {
		if !o.AllowUnsignedChecksums {
			return false, ErrSignatureUnavailable
		}
		return true, nil
	}
	// #nosec G204 -- all args are fixed consts or paths we constructed in our temp dir.
	out, runErr := o.RunCommand(ctx, cosignBinary,
		"verify-blob",
		"--certificate", filepath.Join(dir, checksumsPEM),
		"--signature", filepath.Join(dir, checksumsSig),
		"--certificate-identity", fmt.Sprintf(releaseWorkflowIdentity, tagName),
		"--certificate-oidc-issuer", oidcIssuer,
		filepath.Join(dir, checksumsFile),
	)
	if runErr != nil {
		return false, fmt.Errorf("%w: cosign verify-blob: %s: %s", ErrSignatureVerify, runErr.Error(), strings.TrimSpace(string(out)))
	}
	return false, nil
}

// sha256Hex returns the lowercase hex SHA256 of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func archiveBinaryName(goos string) string {
	if goos == "windows" {
		return binaryName + ".exe"
	}
	return binaryName
}

// extractBinary pulls the single expected binary out of a release
// archive (tar.gz or zip) into a temp file in dir. It rejects path-traversal
// and absolute-path entries (zip-slip / tar "..") and only ever writes the
// expected binary name. Returns the temp file path; caller is responsible for
// removing it on any later failure.
func extractBinary(archive []byte, isZip bool, dir, expectedBinary string) (string, error) {
	pattern := ".pipelock-update-*"
	if strings.HasSuffix(expectedBinary, ".exe") {
		pattern += ".exe"
	}
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("creating temp file in %q: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	var writeErr error
	if isZip {
		writeErr = extractZip(archive, tmp, expectedBinary)
	} else {
		writeErr = extractTarGz(archive, tmp, expectedBinary)
	}
	if writeErr != nil {
		cleanup()
		return "", writeErr
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("closing temp file: %w", err)
	}
	// Executable bit is required for a binary — deliberate 0o600-rule exception.
	if err := os.Chmod(tmpPath, extractedBinaryPerm); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("setting executable bit: %w", err)
	}
	return tmpPath, nil
}

// safeEntryName validates an archive entry name and returns its base name. It
// rejects absolute paths and any entry containing a ".." traversal segment.
func safeEntryName(name string) (string, error) {
	if strings.Contains(name, "\x00") || strings.Contains(name, ":") {
		return "", fmt.Errorf("%w: invalid path %q", ErrUnsafeArchive, name)
	}
	clean := path.Clean(strings.ReplaceAll(name, `\`, "/"))
	if path.IsAbs(clean) || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("%w: absolute path %q", ErrUnsafeArchive, name)
	}
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: traversal in %q", ErrUnsafeArchive, name)
		}
	}
	return path.Base(clean), nil
}

// extractTarGz writes the entry whose base name equals expectedBinary into w.
func extractTarGz(archive []byte, w io.Writer, expectedBinary string) error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return fmt.Errorf("opening gzip stream: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}
		base, err := safeEntryName(hdr.Name)
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg || base != expectedBinary {
			continue
		}
		if hdr.Size > maxDownloadBytes {
			return fmt.Errorf("extracting %q: %w", expectedBinary, ErrBinaryTooLarge)
		}
		if err := copyBounded(w, tr); err != nil {
			return fmt.Errorf("extracting %q: %w", expectedBinary, err)
		}
		return nil
	}
	return fmt.Errorf("%w: %s not found in archive", ErrAssetNotFound, expectedBinary)
}

// extractZip writes the entry whose base name equals expectedBinary into w.
func extractZip(archive []byte, w io.Writer, expectedBinary string) error {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return fmt.Errorf("opening zip archive: %w", err)
	}
	for _, f := range zr.File {
		base, err := safeEntryName(f.Name)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() || base != expectedBinary {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening %q in zip: %w", expectedBinary, err)
		}
		copyErr := copyBounded(w, rc)
		_ = rc.Close()
		if copyErr != nil {
			return fmt.Errorf("extracting %q: %w", expectedBinary, copyErr)
		}
		return nil
	}
	return fmt.Errorf("%w: %s not found in archive", ErrAssetNotFound, expectedBinary)
}

// verifyBinaryVersion runs "<path> --version" and confirms the output mentions
// the expected bare version. Fail-closed: any error or a missing version match
// returns ErrVersionMismatch.
func (o *Options) verifyBinaryVersion(ctx context.Context, path, wantVersion string) error {
	// #nosec G204 -- path is a temp file we just extracted into our own dir.
	out, err := o.RunCommand(ctx, path, "--version")
	if err != nil {
		return fmt.Errorf("%w: running --version: %s", ErrVersionMismatch, err.Error())
	}
	got := string(out)
	if !versionOutputMatches(got, wantVersion) {
		return fmt.Errorf("%w: expected %q in %q", ErrVersionMismatch, wantVersion, strings.TrimSpace(got))
	}
	return nil
}

func versionOutputMatches(output, wantVersion string) bool {
	// Exact match including any pre-release suffix: a "2.8.0" binary must NOT
	// satisfy a "2.8.0-rc1" pin. Strip only the leading "v".
	want := versionTag(wantVersion)
	for _, field := range strings.Fields(output) {
		if field == want || field == "v"+want {
			return true
		}
	}
	return false
}

func copyBounded(w io.Writer, r io.Reader) error {
	n, err := io.Copy(w, io.LimitReader(r, maxDownloadBytes+1))
	if err != nil {
		return err
	}
	if n > maxDownloadBytes {
		return ErrBinaryTooLarge
	}
	return nil
}

// checkWritable confirms the target binary and its directory are writable by
// the current user BEFORE any destructive step. Returns ErrNotWritable
// otherwise so the caller can abort cleanly with a privileged-path message.
func checkWritable(target string) error {
	dir := filepath.Dir(target)
	// Directory must be writable for the atomic temp+rename.
	probe, err := os.CreateTemp(dir, ".pipelock-write-probe-*")
	if err != nil {
		return fmt.Errorf("%w: directory %q: %s", ErrNotWritable, dir, err.Error())
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())

	// The target file itself must be writable if it already exists.
	if info, statErr := os.Stat(target); statErr == nil && info.Mode().IsRegular() {
		f, openErr := os.OpenFile(target, os.O_WRONLY, info.Mode().Perm()) // #nosec G304 -- target is the resolved running binary path
		if openErr != nil {
			return fmt.Errorf("%w: file %q: %s", ErrNotWritable, target, openErr.Error())
		}
		_ = f.Close()
	}
	return nil
}

// installBinary backs up the current binary to <target>.bak (overwriting any
// prior backup) and renames the verified temp binary into place. On rename
// failure it restores from the backup. tmpPath and backup live in the same
// directory as target, so the rename is atomic on one filesystem on Unix.
//
// Windows note: os.Rename cannot overwrite an existing file, so the old binary
// is removed first; the replace is therefore NOT atomic on Windows, but the
// .bak backup is the recovery path. Replacing a running .exe still fails (the
// OS locks it) — fail-closed, backup intact.
func installBinary(target, tmpPath string) (backupPath string, err error) {
	backupPath = target + backupSuffix

	// Back up the current binary by copying its bytes (the original keeps its
	// inode; copy preserves the running process's mapping on Linux).
	if err := copyFile(target, backupPath); err != nil {
		return "", fmt.Errorf("backing up current binary: %w", err)
	}

	if err := replaceBinary(tmpPath, target); err != nil {
		// Restore from backup on failure, best-effort.
		if restoreErr := copyFile(backupPath, target); restoreErr != nil {
			return backupPath, fmt.Errorf("install failed AND restore failed (backup at %s): %w",
				backupPath, errors.Join(err, restoreErr))
		}
		return backupPath, fmt.Errorf("installing new binary: %w (restored from backup)", err)
	}
	return backupPath, nil
}

// rollback restores <target>.bak over the target binary. Returns ErrNoBackup if
// no backup exists.
func rollback(target string) (backupPath string, err error) {
	backupPath = target + backupSuffix
	if _, statErr := os.Stat(backupPath); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return backupPath, ErrNoBackup
		}
		return backupPath, fmt.Errorf("checking backup %q: %w", backupPath, statErr)
	}
	// Stage the restored bytes into a temp file in the target dir, then replace.
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".pipelock-rollback-*")
	if err != nil {
		return backupPath, fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	if err := copyFile(backupPath, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return backupPath, fmt.Errorf("staging backup: %w", err)
	}
	if err := replaceBinary(tmpPath, target); err != nil {
		_ = os.Remove(tmpPath)
		return backupPath, fmt.Errorf("restoring backup: %w", err)
	}
	return backupPath, nil
}

// replaceBinary moves the staged file at tmpPath over target. On Unix this is an
// atomic rename. On Windows os.Rename cannot overwrite an existing file, so the
// old target is removed first — NOT atomic, but install/rollback both keep a
// .bak backup as the recovery path. Replacing a running .exe still fails (the OS
// locks it): fail-closed, backup intact.
func replaceBinary(tmpPath, target string) error {
	if runtime.GOOS == "windows" {
		if rmErr := os.Remove(target); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return rmErr
		}
	}
	return os.Rename(tmpPath, target)
}

// copyFile copies src to dst with the executable binary perm. dst is written
// via a temp + rename in dst's directory so a partial copy never leaves a
// corrupt file. perm is fixed at extractedBinaryPerm (0o755) because both
// callers copy executables.
func copyFile(src, dst string) error {
	const perm = extractedBinaryPerm
	in, err := os.Open(src) // #nosec G304 -- src is a path we control (target binary or our temp file)
	if err != nil {
		return fmt.Errorf("opening %q: %w", src, err)
	}
	defer func() { _ = in.Close() }()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".pipelock-copy-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if err := copyBounded(tmp, in); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("copying bytes: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("setting permissions: %w", err)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming into place: %w", err)
	}
	return nil
}
