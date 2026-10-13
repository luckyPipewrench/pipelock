// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type pathSnapshot struct {
	path    string
	info    os.FileInfo
	content []byte
}

type runVerifierFileOps struct {
	open          func(string) (*os.File, os.FileInfo, error)
	seek          func(*os.File, int64) (int64, error)
	stat          func(*os.File) (os.FileInfo, error)
	maxReadStream int64
}

// RunVerifier authenticates appended AEL records while retaining a byte-bound
// prefix digest. VerifyUnchanged re-hashes that prefix before callers rely on
// the head, so a record changed after an earlier Advance cannot pass unnoticed.
type RunVerifier struct {
	mu sync.Mutex

	recorderDir string
	run         string
	signerHex   string
	pub         ed25519.PublicKey
	keyID       string
	dir         string
	streamPath  string
	streamInfo  os.FileInfo
	directories []pathSnapshot
	manifest    pathSnapshot
	key         pathSnapshot

	verifiedHash   hash.Hash
	verifiedOffset int64
	prev           string
	count          uint64
	closed         bool
	finalized      bool
	stickyErr      error
	fileOps        runVerifierFileOps
}

// NewRunVerifier binds an incremental verifier to one run's layout, manifest,
// published key, and stream inode. It uses the same signer and path checks as
// VerifyRun; callers still need VerifyUnchanged before relying on the head.
func NewRunVerifier(recorderDir, run, signerHex string) (*RunVerifier, error) {
	return newRunVerifierWithSnapshot(recorderDir, run, signerHex, readPathSnapshot)
}

func newRunVerifierWithSnapshot(recorderDir, run, signerHex string, snapshot func(string, int64) (pathSnapshot, error)) (*RunVerifier, error) {
	if !runIDPattern.MatchString(run) {
		return nil, errors.New("invalid native AEL run nonce")
	}
	if len(signerHex) != ed25519.PublicKeySize*2 || strings.ToLower(signerHex) != signerHex {
		return nil, errors.New("invalid native AEL signer")
	}
	pub, err := hex.DecodeString(signerHex)
	if err != nil {
		return nil, fmt.Errorf("decode native AEL signer: %w", err)
	}
	sum := sha256.Sum256(pub)
	keyID := hex.EncodeToString(sum[:])
	cleanRecorderDir := filepath.Clean(recorderDir)
	dir := filepath.Join(cleanRecorderDir, "ael", run)
	paths := []string{filepath.Join(cleanRecorderDir, "ael"), dir, filepath.Join(dir, "keys"), filepath.Join(dir, "recorders")}
	verifier := &RunVerifier{
		recorderDir:  cleanRecorderDir,
		run:          run,
		signerHex:    signerHex,
		pub:          ed25519.PublicKey(pub),
		keyID:        keyID,
		dir:          dir,
		streamPath:   filepath.Join(dir, "recorders", "pipelock.jsonl"),
		verifiedHash: sha256.New(),
		prev:         zeroHash,
		fileOps: runVerifierFileOps{
			open:          openRegularAEL,
			seek:          func(file *os.File, offset int64) (int64, error) { return file.Seek(offset, io.SeekStart) },
			stat:          func(file *os.File) (os.FileInfo, error) { return file.Stat() },
			maxReadStream: maxVerifyStreamBytes,
		},
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("native AEL directory %q is missing or redirected", path)
		}
		verifier.directories = append(verifier.directories, pathSnapshot{path: path, info: info})
	}
	if err := verifyRunManifest(dir, run, keyID, pub); err != nil {
		return nil, err
	}
	verifier.manifest, err = snapshot(filepath.Join(dir, "manifest.json"), 4096)
	if err != nil {
		return nil, err
	}
	verifier.key, err = snapshot(filepath.Join(dir, "keys", keyID+".pub"), 128)
	if err != nil {
		return nil, err
	}
	stream, streamInfo, err := openRegularAEL(verifier.streamPath)
	if err != nil {
		return nil, err
	}
	_ = stream.Close()
	if streamInfo.Size() > maxVerifyStreamBytes {
		return nil, errAELStreamTooLarge
	}
	verifier.streamInfo = streamInfo
	if err := verifier.verifyLayout(); err != nil {
		return nil, err
	}
	return verifier, nil
}

// Advance verifies complete records appended since the last successful call.
// With requireClose false, a final unterminated line remains outside the
// checkpoint and will be re-read on the next call. With requireClose true, the
// stream must be complete and contain its signed terminal close.
func (v *RunVerifier) Advance(requireClose bool) (VerifiedHead, error) {
	if v == nil {
		return VerifiedHead{}, errors.New("nil native AEL run verifier")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.stickyErr != nil {
		return VerifiedHead{}, v.stickyErr
	}
	if v.finalized {
		return v.head(), nil
	}
	if err := v.verifyLayout(); err != nil {
		return v.fail(err)
	}
	f, before, err := v.fileOps.open(v.streamPath)
	if err != nil {
		return v.fail(err)
	}
	defer func() { _ = f.Close() }()
	if !os.SameFile(v.streamInfo, before) || before.Size() > maxVerifyStreamBytes {
		return v.fail(errors.New("native AEL stream was replaced or exceeds limit"))
	}
	if before.Size() < v.verifiedOffset {
		return v.fail(errors.New("native AEL stream was truncated after verification"))
	}
	if _, err := v.fileOps.seek(f, v.verifiedOffset); err != nil {
		return v.fail(fmt.Errorf("seek native AEL verification offset: %w", err))
	}
	// Authenticate a fixed on-disk prefix. The live writer may append while
	// we decode it; bytes beyond this snapshot belong to the next Advance.
	// VerifyUnchanged still rehashes the entire authenticated prefix at close.
	r := bufio.NewReaderSize(io.LimitReader(f, before.Size()-v.verifiedOffset), maxVerifyRecordBytes)
	streamBytes := v.verifiedOffset
	for {
		line, readErr := readBoundedAELLine(r, &streamBytes, v.fileOps.maxReadStream)
		if errors.Is(readErr, errAELStreamTooLarge) {
			return v.fail(readErr)
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			return v.fail(errors.New("native AEL record exceeds limit"))
		}
		if errors.Is(readErr, io.EOF) && len(line) == 0 {
			break
		}
		if errors.Is(readErr, io.EOF) && !requireClose && !v.closed {
			break
		}
		if readErr != nil || len(line) == 0 || line[len(line)-1] != '\n' || len(line) > maxVerifyRecordBytes {
			return v.fail(errors.New("native AEL stream has torn or oversized line"))
		}
		next, err := verifyRunRecord(line, runRecordState{pub: v.pub, run: v.run, keyID: v.keyID, prev: v.prev, count: v.count, closed: v.closed})
		if err != nil {
			return v.fail(err)
		}
		_, _ = v.verifiedHash.Write(line)
		v.verifiedOffset += int64(len(line))
		v.prev, v.count, v.closed = next.prev, next.count, next.closed
	}
	after, err := v.fileOps.stat(f)
	if err != nil || !os.SameFile(before, after) || after.Size() < before.Size() ||
		(requireClose && (before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()))) {
		return v.fail(errors.New("native AEL stream changed during verification"))
	}
	if err := v.verifyLayout(); err != nil {
		return v.fail(err)
	}
	if requireClose && (!v.closed || v.count < 2) {
		return v.fail(errors.New("native AEL run has no signed close"))
	}
	if requireClose {
		v.finalized = true
	}
	return v.head(), nil
}

// VerifyUnchanged confirms that every byte authenticated by Advance is still
// present at the same paths and in the same files. It must be called after
// Advance(true) before the returned close head is trusted for another signature.
func (v *RunVerifier) VerifyUnchanged() error {
	if v == nil {
		return errors.New("nil native AEL run verifier")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.stickyErr != nil {
		return v.stickyErr
	}
	if !v.finalized {
		return errors.New("native AEL run verifier has not verified a close")
	}
	return v.latch(v.verifyPrefixUnchanged(true))
}

// VerifyPrefixUnchanged checks the retained layout and authenticated bytes
// even after Advance failed. It does not clear that failure or authenticate
// the remaining suffix; a caller recovering a close must also use VerifyRun.
func (v *RunVerifier) VerifyPrefixUnchanged() error {
	if v == nil {
		return errors.New("nil native AEL run verifier")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.verifyPrefixUnchanged(false)
}

func (v *RunVerifier) verifyPrefixUnchanged(complete bool) error {
	if err := v.verifyLayout(); err != nil {
		return err
	}
	f, before, err := v.fileOps.open(v.streamPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if !os.SameFile(v.streamInfo, before) || before.Size() < v.verifiedOffset || complete && before.Size() != v.verifiedOffset {
		return errors.New("native AEL stream size or identity changed after verification")
	}
	h := sha256.New()
	limit := v.verifiedOffset
	if complete {
		limit++
	}
	if _, err := io.Copy(h, io.LimitReader(f, limit)); err != nil {
		return fmt.Errorf("re-hash native AEL stream: %w", err)
	}
	if !bytes.Equal(h.Sum(nil), v.verifiedHash.Sum(nil)) {
		return errors.New("native AEL stream bytes changed after verification")
	}
	after, err := v.fileOps.stat(f)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || complete && after.Size() != v.verifiedOffset {
		return errors.New("native AEL stream changed during final verification")
	}
	if err := v.verifyLayout(); err != nil {
		return err
	}
	return nil
}

func (v *RunVerifier) verifyLayout() error {
	for _, expected := range v.directories {
		info, err := os.Lstat(expected.path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(expected.info, info) {
			return fmt.Errorf("native AEL directory %q changed or is redirected", expected.path)
		}
	}
	if err := verifyRunManifest(v.dir, v.run, v.keyID, v.pub); err != nil {
		return err
	}
	if err := verifyPathSnapshot(v.manifest); err != nil {
		return err
	}
	if err := verifyPathSnapshot(v.key); err != nil {
		return err
	}
	streamInfo, err := os.Lstat(v.streamPath)
	if err != nil || streamInfo.Mode()&os.ModeSymlink != 0 || !streamInfo.Mode().IsRegular() || !os.SameFile(v.streamInfo, streamInfo) {
		return errors.New("native AEL stream path changed or is redirected")
	}
	return nil
}

func readPathSnapshot(path string, limit int64) (pathSnapshot, error) {
	return readPathSnapshotWithOpen(path, limit, openRegularAEL)
}

func readPathSnapshotWithOpen(path string, limit int64, open func(string) (*os.File, os.FileInfo, error)) (pathSnapshot, error) {
	f, before, err := open(path)
	if err != nil {
		return pathSnapshot{}, err
	}
	defer func() { _ = f.Close() }()
	if before.Size() > limit {
		return pathSnapshot{}, fmt.Errorf("native AEL file %q exceeds limit", path)
	}
	content, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(content)) > limit {
		return pathSnapshot{}, fmt.Errorf("cannot read bounded native AEL file %q", path)
	}
	after, err := f.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, pathInfo) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return pathSnapshot{}, fmt.Errorf("native AEL file %q changed while reading", path)
	}
	return pathSnapshot{path: path, info: before, content: content}, nil
}

func verifyPathSnapshot(expected pathSnapshot) error {
	got, err := readPathSnapshot(expected.path, int64(len(expected.content)))
	if err != nil {
		return err
	}
	if !os.SameFile(expected.info, got.info) || !bytes.Equal(expected.content, got.content) {
		return fmt.Errorf("native AEL file %q changed after verification began", expected.path)
	}
	return nil
}

func (v *RunVerifier) fail(err error) (VerifiedHead, error) {
	return VerifiedHead{}, v.latch(err)
}

func (v *RunVerifier) latch(err error) error {
	if v.stickyErr == nil {
		v.stickyErr = err
	}
	return v.stickyErr
}

func (v *RunVerifier) head() VerifiedHead {
	finalSeq := uint64(0)
	if v.count > 0 {
		finalSeq = v.count - 1
	}
	return VerifiedHead{FinalSeq: finalSeq, FinalHash: v.prev, RecordCount: v.count}
}
