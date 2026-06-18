// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// firstVersionWithUpdate is the earliest release that ships the "update"
// subcommand. Any target version strictly older than this lacks the rollback
// command, so the operator needs a manual recovery path printed.
const firstVersionWithUpdate = "v2.8.0"

// versionTag strips only a leading "v" and surrounding whitespace, PRESERVING
// any pre-release/build suffix. Use this for asset-name resolution and the
// extracted-binary version check, where "v2.8.0-rc1" must stay "2.8.0-rc1"
// (GoReleaser keeps the suffix in the archive name and the binary reports it).
func versionTag(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

// bareVersion additionally strips the pre-release/build suffix, leaving only the
// X.Y.Z core for semver COMPARISON. "v2.7.0" -> "2.7.0", "2.7.0-rc1" -> "2.7.0".
// Never use it for asset names or version-token matching (see versionTag).
func bareVersion(v string) string {
	v = versionTag(v)
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	return v
}

// parseSemver parses "X.Y.Z" into three ints. Returns ok=false if not parseable
// (e.g. a "0.1.0-dev" dev build's core still parses, but "unknown" does not).
func parseSemver(v string) (major, minor, patch int, ok bool) {
	parts := strings.Split(bareVersion(v), ".")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	var err error
	if major, err = strconv.Atoi(parts[0]); err != nil {
		return 0, 0, 0, false
	}
	if minor, err = strconv.Atoi(parts[1]); err != nil {
		return 0, 0, 0, false
	}
	if patch, err = strconv.Atoi(parts[2]); err != nil {
		return 0, 0, 0, false
	}
	return major, minor, patch, true
}

// isNewer reports whether latest is a newer release than current. If current is
// not parseable semver (dev build), ANY parseable latest counts as newer so a
// dev build can always move to a real release.
func isNewer(current, latest string) bool {
	cMaj, cMin, cPatch, cOK := parseSemver(current)
	lMaj, lMin, lPatch, lOK := parseSemver(latest)
	if !lOK {
		return false // can't reason about a non-semver target
	}
	if !cOK {
		return true // dev/unknown current -> any real release is "newer"
	}
	switch {
	case lMaj != cMaj:
		return lMaj > cMaj
	case lMin != cMin:
		return lMin > cMin
	default:
		return lPatch > cPatch
	}
}

// lacksUpdateCommand reports whether the given release version predates the
// "update" subcommand. When true, "pipelock update --rollback" will not be
// available from the downgraded binary.
func lacksUpdateCommand(version string) bool {
	return isNewer(version, firstVersionWithUpdate)
}

// Check resolves the latest (or pinned) release and reports status WITHOUT
// making any changes. Used by --check.
func (o *Options) Check(ctx context.Context) (*Status, error) {
	if err := o.fillDefaults(); err != nil {
		return nil, err
	}
	rel, err := o.fetchRelease(ctx)
	if err != nil {
		return nil, err
	}
	st := &Status{
		CurrentVersion:  o.CurrentVersion,
		LatestVersion:   rel.TagName,
		TargetPath:      o.TargetPath,
		UpdateAvailable: isNewer(o.CurrentVersion, rel.TagName),
	}
	return st, nil
}

// Run performs the full verified update: resolve release -> verify publisher
// signature (best-effort) -> download archive -> checksum match -> extract ->
// verify version -> back up -> atomic replace. FAIL-CLOSED at every step: any
// error aborts and leaves the installed binary untouched.
//
// The cobra layer is responsible for any interactive confirmation before
// calling Run; Run itself always proceeds (it is the "yes" path).
func (o *Options) Run(ctx context.Context) (*Status, error) {
	if err := o.fillDefaults(); err != nil {
		return nil, err
	}
	rel, err := o.fetchRelease(ctx)
	if err != nil {
		return nil, err
	}

	st := &Status{
		CurrentVersion:  o.CurrentVersion,
		LatestVersion:   rel.TagName,
		TargetPath:      o.TargetPath,
		UpdateAvailable: isNewer(o.CurrentVersion, rel.TagName),
	}

	// Nothing to do unless pinned to a specific version or genuinely newer.
	if !st.UpdateAvailable && o.TargetVersion == "" {
		return st, ErrUpToDate
	}

	// Writability gate FIRST — never start a destructive flow we can't finish.
	if err := checkWritable(o.TargetPath); err != nil {
		return st, err
	}

	assetVer := versionTag(rel.TagName)
	isZip := o.GOOS == "windows"
	asset := assetName(assetVer, o.GOOS, o.GOARCH)
	st.Asset = asset

	// Resolve all asset URLs up front; an unsupported os/arch is an early abort.
	archiveURL, err := assetURL(rel, asset)
	if err != nil {
		return st, fmt.Errorf("%w: %s/%s (looked for %s)", ErrUnsupportedPlatform, o.GOOS, o.GOARCH, asset)
	}
	sumsURL, err := assetURL(rel, checksumsFile)
	if err != nil {
		return st, fmt.Errorf("resolving checksums asset: %w", err)
	}

	// Stage checksums + signature material in the target directory's tempdir so
	// cosign can read them by path and the extracted binary lands on the same FS.
	dir := filepath.Dir(o.TargetPath)

	// --- 1. checksums.txt + cosign authenticity (fail-closed unless --insecure-skip-signature) ---
	sums, err := o.httpGet(ctx, sumsURL)
	if err != nil {
		return st, fmt.Errorf("downloading %s: %w", checksumsFile, err)
	}
	skipped, err := o.stageAndVerifySignature(ctx, rel, dir, sums)
	if err != nil {
		return st, err // ErrSignatureVerify -> fail-closed, no changes
	}
	st.SignatureSkipped = skipped
	st.SignatureVerified = !skipped
	if skipped {
		_, _ = fmt.Fprintln(o.Stderr,
			"WARNING: --insecure-skip-signature is set and cosign was not found on PATH. "+
				"Publisher identity was NOT verified; proceeding with checksum integrity only.")
	}

	// --- 2. download archive + exact checksum match ---
	archive, err := o.httpGet(ctx, archiveURL)
	if err != nil {
		return st, fmt.Errorf("downloading %s: %w", asset, err)
	}
	wantSum, ok := parseChecksums(sums)[asset]
	if !ok {
		return st, fmt.Errorf("%w: %s has no entry in %s", ErrChecksumMismatch, asset, checksumsFile)
	}
	if got := sha256Hex(archive); got != wantSum {
		return st, fmt.Errorf("%w: %s got %s want %s", ErrChecksumMismatch, asset, got, wantSum)
	}

	// --- 3. extract the pipelock binary into the target dir (atomic-rename ready) ---
	tmpPath, err := extractBinary(archive, isZip, dir, archiveBinaryName(o.GOOS))
	if err != nil {
		return st, err
	}
	// From here, any failure must delete tmpPath and leave target untouched.

	// --- 4. verify the extracted binary self-reports the expected version ---
	if err := o.verifyBinaryVersion(ctx, tmpPath, assetVer); err != nil {
		_ = removeQuiet(tmpPath)
		return st, err
	}

	// --- 5. back up current + atomic replace ---
	backup, err := installBinary(o.TargetPath, tmpPath)
	if err != nil {
		_ = removeQuiet(tmpPath)
		return st, err
	}
	st.BackupPath = backup
	st.Applied = true

	// Warn when the installed version predates the "update" command. The
	// downgraded binary has no "pipelock update --rollback" so the operator
	// needs the manual recovery path printed before they lose this binary.
	if lacksUpdateCommand(rel.TagName) {
		_, _ = fmt.Fprintf(o.Stderr,
			"\nWARNING: %s predates the 'update' command.\n"+
				"'pipelock update --rollback' will NOT be available from the downgraded binary.\n"+
				"To restore manually, run:\n  mv %s %s\n",
			rel.TagName, shellQuote(st.BackupPath), shellQuote(o.TargetPath))
	}

	return st, nil
}

// shellQuote single-quotes a path so the printed manual-recovery command is
// safe to paste verbatim even when the path contains spaces or shell
// metacharacters. Embedded single quotes are escaped by closing the quoted
// string, adding an escaped quote, and reopening the quoted string.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Rollback restores the previous binary from <target>.bak.
func (o *Options) Rollback(_ context.Context) (*Status, error) {
	if err := o.fillDefaults(); err != nil {
		return nil, err
	}
	st := &Status{
		CurrentVersion: o.CurrentVersion,
		TargetPath:     o.TargetPath,
	}
	if err := checkWritable(o.TargetPath); err != nil {
		return st, err
	}
	backup, err := rollback(o.TargetPath)
	if err != nil {
		return st, err
	}
	st.BackupPath = backup
	st.Applied = true
	return st, nil
}

// stageAndVerifySignature writes checksums.txt (+ .sig + .pem if present) into
// a private temp dir under dir, then runs cosign verification. Returns
// skipped=true when cosign is absent (integrity-only), or an error when cosign
// is present and rejects the signature.
func (o *Options) stageAndVerifySignature(ctx context.Context, rel *release, dir string, sums []byte) (skipped bool, err error) {
	stageDir, err := os.MkdirTemp(dir, ".pipelock-verify-*")
	if err != nil {
		return false, fmt.Errorf("creating verification temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(stageDir) }()

	if err := writeFileQuiet(filepath.Join(stageDir, checksumsFile), sums); err != nil {
		return false, fmt.Errorf("staging %s: %w", checksumsFile, err)
	}

	// Best-effort fetch of signature + certificate. If they're missing from the
	// release AND cosign is present, verification will fail closed below.
	if sigURL, e := assetURL(rel, checksumsSig); e == nil {
		if sig, ge := o.httpGet(ctx, sigURL); ge == nil {
			_ = writeFileQuiet(filepath.Join(stageDir, checksumsSig), sig)
		}
	}
	if pemURL, e := assetURL(rel, checksumsPEM); e == nil {
		if pem, ge := o.httpGet(ctx, pemURL); ge == nil {
			_ = writeFileQuiet(filepath.Join(stageDir, checksumsPEM), pem)
		}
	}

	return o.verifyPublisherSignature(ctx, stageDir, rel.TagName)
}
