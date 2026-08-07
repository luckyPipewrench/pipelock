// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestWriteEscrow_ConcurrentRecordersKeepEveryPayload(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	const recorderCount = 8
	recorders := make([]*Recorder, 0, recorderCount)
	for range recorderCount {
		recorders = append(recorders, &Recorder{
			cfg:       Config{Dir: dir, FileMode: filePermissions},
			escrowPub: publicKey,
			sessionID: "proxy",
			seq:       42,
		})
	}

	start := make(chan struct{})
	paths := make(chan string, recorderCount)
	errs := make(chan error, recorderCount)
	var wg sync.WaitGroup
	wantByPath := make(map[string][]byte, recorderCount)
	var wantMu sync.Mutex
	for i, rec := range recorders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			want := []byte("raw payload " + strconv.Itoa(i))
			path, writeErr := rec.writeEscrow(want)
			if writeErr != nil {
				errs <- writeErr
				return
			}
			wantMu.Lock()
			wantByPath[path] = want
			wantMu.Unlock()
			paths <- path
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	close(paths)
	for writeErr := range errs {
		t.Fatalf("writeEscrow: %v", writeErr)
	}

	written := make(map[string]struct{}, recorderCount)
	for path := range paths {
		written[path] = struct{}{}
	}
	if len(written) != recorderCount {
		t.Fatalf("unique escrow paths = %d, want %d", len(written), recorderCount)
	}
	for path := range written {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("escrow sidecar %q: %v", path, statErr)
		}
		if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != filePermissions {
			t.Fatalf("escrow sidecar %q mode = %04o, want %04o", path, got, filePermissions)
		}
		payload, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			t.Fatalf("read escrow sidecar %q: %v", path, readErr)
		}
		if len(payload) < x25519KeySize+24+box.Overhead {
			t.Fatalf("escrow sidecar %q is too short", path)
		}
		var ephemeralPublic [x25519KeySize]byte
		copy(ephemeralPublic[:], payload[:x25519KeySize])
		var nonce [24]byte
		copy(nonce[:], payload[x25519KeySize:x25519KeySize+len(nonce)])
		got, ok := box.Open(nil, payload[x25519KeySize+len(nonce):], &nonce, &ephemeralPublic, privateKey)
		if !ok {
			t.Fatalf("decrypt escrow sidecar %q", path)
		}
		if !bytes.Equal(got, wantByPath[path]) {
			t.Fatalf("decrypted escrow sidecar %q = %q, want %q", path, got, wantByPath[path])
		}
	}
	// Every sidecar must still be recognizable as one, so the new token in the
	// filename cannot hide a payload from anything that enumerates sidecars.
	sidecars, globErr := filepath.Glob(filepath.Join(dir, "evidence-*.raw.enc"))
	if globErr != nil {
		t.Fatalf("Glob: %v", globErr)
	}
	if len(sidecars) != recorderCount {
		t.Fatalf("discoverable sidecars = %d, want %d", len(sidecars), recorderCount)
	}
}

func TestWriteEscrow_AlwaysUsesOwnerOnlyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix owner/group permission bits")
	}
	dir := t.TempDir()
	publicKey, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rec := &Recorder{
		cfg:       Config{Dir: dir, FileMode: 0o660},
		escrowPub: publicKey,
		sessionID: "proxy",
	}
	path, err := rec.writeEscrow([]byte("sensitive raw payload"))
	if err != nil {
		t.Fatalf("writeEscrow: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != filePermissions {
		t.Fatalf("escrow mode = %04o, want %04o", got, filePermissions)
	}
}

func TestWriteEscrowPayload_RefusesUnboundedCollisionRetries(t *testing.T) {
	dir := t.TempDir()
	const (
		sessionID = "proxy"
		seq       = 42
	)
	token := bytes.Repeat([]byte{0x42}, escrowNameTokenBytes)
	name := "evidence-" + sessionID + "-42-raw-" + hex.EncodeToString(token) + ".raw.enc"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("existing"), filePermissions); err != nil {
		t.Fatalf("create colliding sidecar: %v", err)
	}
	rec := &Recorder{cfg: Config{Dir: dir, FileMode: filePermissions}, sessionID: sessionID, seq: seq}
	_, err := rec.writeEscrowPayloadWithReader([]byte("payload"), bytes.NewReader(bytes.Repeat(token, maxEscrowNameAttempts)))
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("writeEscrowPayloadWithReader collision error = %v, want fs.ErrExist", err)
	}
	root, openErr := os.OpenRoot(dir)
	if openErr != nil {
		t.Fatalf("open evidence directory: %v", openErr)
	}
	defer func() { _ = root.Close() }()
	data, readErr := root.ReadFile(name)
	if readErr != nil {
		t.Fatalf("read existing sidecar: %v", readErr)
	}
	if string(data) != "existing" {
		t.Fatalf("existing sidecar changed to %q", data)
	}
}

func TestWriteEscrowPayload_RemovesIncompleteSidecar(t *testing.T) {
	dir := t.TempDir()
	token := bytes.Repeat([]byte{0x24}, escrowNameTokenBytes)
	rec := &Recorder{
		cfg:       Config{Dir: dir, FileMode: filePermissions},
		sessionID: "proxy",
		seq:       42,
	}
	wantErr := errors.New("injected escrow write failure")

	_, err := rec.writeEscrowPayloadWithReaderAndWriter(
		[]byte("payload"),
		bytes.NewReader(token),
		func(file *os.File, _ []byte, _ os.FileMode) error {
			if _, writeErr := file.Write([]byte("partial")); writeErr != nil {
				return writeErr
			}
			if closeErr := file.Close(); closeErr != nil {
				return closeErr
			}
			return wantErr
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("writeEscrowPayload error = %v, want injected failure", err)
	}

	name := "evidence-proxy-42-raw-" + hex.EncodeToString(token) + ".raw.enc"
	if _, statErr := os.Stat(filepath.Join(dir, name)); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("incomplete escrow sidecar remains after failure: %v", statErr)
	}
}

func TestWriteEscrowPayload_ReportsDirectoryAndEntropyFailures(t *testing.T) {
	t.Run("missing evidence directory", func(t *testing.T) {
		rec := &Recorder{cfg: Config{Dir: filepath.Join(t.TempDir(), "missing")}}
		_, err := rec.writeEscrowPayloadWithReader([]byte("payload"), bytes.NewReader(make([]byte, escrowNameTokenBytes)))
		if err == nil || !strings.Contains(err.Error(), "opening evidence directory") {
			t.Fatalf("writeEscrowPayloadWithReader error = %v, want evidence directory failure", err)
		}
	})

	t.Run("filename entropy failure", func(t *testing.T) {
		rec := &Recorder{cfg: Config{Dir: t.TempDir()}}
		_, err := rec.writeEscrowPayloadWithReader([]byte("payload"), errorReader{})
		if err == nil || !strings.Contains(err.Error(), "generating escrow filename token") {
			t.Fatalf("writeEscrowPayloadWithReader error = %v, want filename entropy failure", err)
		}
	})
}

func TestWriteEscrowPayload_ReportsCreateFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix directory write bits")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, dirPermissions&^0o200); err != nil {
		t.Fatalf("remove evidence directory write permission: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, dirPermissions) })
	rec := &Recorder{cfg: Config{Dir: dir}, sessionID: "proxy"}
	_, err := rec.writeEscrowPayloadWithReader([]byte("payload"), bytes.NewReader(make([]byte, escrowNameTokenBytes)))
	if err == nil || !strings.Contains(err.Error(), "creating escrow file") {
		t.Fatalf("writeEscrowPayloadWithReader error = %v, want create failure", err)
	}
}

func TestWriteEscrowPayload_ReportsCleanupFailure(t *testing.T) {
	dir := t.TempDir()
	token := bytes.Repeat([]byte{0x31}, escrowNameTokenBytes)
	name := "evidence-proxy-0-raw-" + hex.EncodeToString(token) + ".raw.enc"
	wantErr := errors.New("injected write failure")
	rec := &Recorder{cfg: Config{Dir: dir}, sessionID: "proxy"}

	_, err := rec.writeEscrowPayloadWithReaderAndWriter(
		[]byte("payload"),
		bytes.NewReader(token),
		func(file *os.File, _ []byte, _ os.FileMode) error {
			if closeErr := file.Close(); closeErr != nil {
				return closeErr
			}
			path := filepath.Join(dir, name)
			if removeErr := os.Remove(path); removeErr != nil {
				return removeErr
			}
			if mkdirErr := os.Mkdir(path, dirPermissions); mkdirErr != nil {
				return mkdirErr
			}
			if childErr := os.WriteFile(filepath.Join(path, "child"), []byte("occupied"), filePermissions); childErr != nil {
				return childErr
			}
			return wantErr
		},
	)
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "removing incomplete escrow file") {
		t.Fatalf("writeEscrowPayload error = %v, want joined write and cleanup failures", err)
	}
}

func TestWriteEscrowFile_ReportsWriteFailure(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "closed-escrow-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close before write: %v", err)
	}
	err = writeEscrowFile(file, []byte("payload"), filePermissions)
	if err == nil || !strings.Contains(err.Error(), "writing escrow file") {
		t.Fatalf("writeEscrowFile error = %v, want write failure", err)
	}
}
