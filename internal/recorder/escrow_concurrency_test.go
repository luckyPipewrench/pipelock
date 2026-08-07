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
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestWriteEscrow_ConcurrentRecordersKeepEveryPayload(t *testing.T) {
	dir := t.TempDir()
	publicKey, _, err := box.GenerateKey(rand.Reader)
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
	for _, rec := range recorders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			path, writeErr := rec.writeEscrow([]byte("raw payload"))
			if writeErr != nil {
				errs <- writeErr
				return
			}
			paths <- path
		}()
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
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("escrow sidecar %q: %v", path, statErr)
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
