// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package ael emits native Agent Evidence Levels v0.1 artifacts.
package ael

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	recordVersion = 1
	recorderID    = "pipelock"
	zeroHash      = "0000000000000000000000000000000000000000000000000000000000000000"
	maxSafeInt    = uint64(1<<53 - 1)
)

var runIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type Activity struct{ Class, ID, Direction string }

type manifest struct {
	Format    int                `json:"ael_format"`
	Coverage  string             `json:"coverage"`
	Custody   string             `json:"custody"`
	Recorders []manifestRecorder `json:"recorders"`
	Runs      []string           `json:"runs"`
}

type manifestRecorder struct {
	File string `json:"file"`
	ID   string `json:"id"`
	Key  string `json:"key"`
	Run  string `json:"run"`
}

type artifactOps struct {
	mkdir          func(string, os.FileMode) error
	writeExclusive func(string, []byte, os.FileMode) error
	openFile       func(string, int, os.FileMode) (*os.File, error)
	syncDirectory  func(string) error
}

var systemArtifactOps = artifactOps{
	mkdir:          os.Mkdir,
	writeExclusive: writeExclusive,
	openFile:       os.OpenFile,
	syncDirectory:  syncDirectory,
}

// Emitter writes one artifact consumed directly by stock aelcheck.
type Emitter struct {
	privKey    ed25519.PrivateKey
	run, keyID string
	hmax       int
	htol       int
	now        func() time.Time
	file       *os.File
	dir        string

	mu             sync.Mutex
	seq            uint64
	prev           string
	opened, closed bool
	lastErr        error
}

// NewEmitter creates the manifest, published key, and compact record stream.
// Initialization errors are sticky and surface through the first lifecycle
// emission so require_receipts can fail closed.
func NewEmitter(rec *recorder.Recorder, privKey ed25519.PrivateKey, run string, heartbeatSeconds int) *Emitter {
	if rec == nil || len(privKey) != ed25519.PrivateKeySize || !runIDPattern.MatchString(run) || rec.Dir() == "" {
		return nil
	}
	pub := privKey.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	if heartbeatSeconds < 0 {
		heartbeatSeconds = 0
	}
	heartbeatTolerance := 0
	if heartbeatSeconds > 0 {
		heartbeatTolerance = max(1, heartbeatSeconds/10)
	}
	e := &Emitter{privKey: privKey, run: run, keyID: hex.EncodeToString(sum[:]), hmax: heartbeatSeconds, htol: heartbeatTolerance, now: time.Now, prev: zeroHash}
	e.lastErr = e.initializeArtifact(rec.Dir(), pub)
	return e
}

func (e *Emitter) Dir() string {
	if e == nil {
		return ""
	}
	return e.dir
}

func (e *Emitter) initializeArtifact(recorderDir string, pub ed25519.PublicKey) error {
	return e.initializeArtifactWithOps(recorderDir, pub, systemArtifactOps)
}

func (e *Emitter) initializeArtifactWithOps(recorderDir string, pub ed25519.PublicKey, ops artifactOps) error {
	root := filepath.Join(filepath.Clean(recorderDir), "ael")
	if err := ensureDirectory(root); err != nil {
		return fmt.Errorf("prepare AEL artifact root: %w", err)
	}
	e.dir = filepath.Join(root, e.run)
	if err := ops.mkdir(e.dir, 0o750); err != nil {
		return fmt.Errorf("create AEL run directory: %w", err)
	}
	for _, name := range []string{"keys", "recorders"} {
		if err := ops.mkdir(filepath.Join(e.dir, name), 0o750); err != nil {
			return fmt.Errorf("create AEL %s directory: %w", name, err)
		}
	}
	if err := ops.writeExclusive(filepath.Join(e.dir, "keys", e.keyID+".pub"), []byte(base64.StdEncoding.EncodeToString(pub)), 0o600); err != nil {
		return fmt.Errorf("publish AEL key: %w", err)
	}
	m := manifest{Format: 1, Runs: []string{e.run}, Recorders: []manifestRecorder{{ID: recorderID, Run: e.run, Key: e.keyID, File: "recorders/pipelock.jsonl"}}, Coverage: "mediated-only", Custody: "same-process"}
	manifestBytes, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal AEL manifest: %w", err)
	}
	if err := ops.writeExclusive(filepath.Join(e.dir, "manifest.json"), manifestBytes, 0o600); err != nil {
		return fmt.Errorf("write AEL manifest: %w", err)
	}
	e.file, err = ops.openFile(filepath.Join(e.dir, "recorders", "pipelock.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create AEL record stream: %w", err)
	}
	for _, path := range []string{filepath.Join(e.dir, "keys"), filepath.Join(e.dir, "recorders"), e.dir, root, filepath.Clean(recorderDir)} {
		if err := ops.syncDirectory(path); err != nil {
			_ = e.file.Close()
			return fmt.Errorf("sync AEL artifact directory: %w", err)
		}
	}
	return nil
}

func ensureDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// A concurrently-starting sibling can win the race to create the shared
		// artifact root between this Lstat and our Mkdir. Tolerate that benign
		// EEXIST, then fall through to re-stat and enforce the same
		// symlink/directory invariant on whatever now exists — a racing attacker
		// who planted a symlink or file still lands in the refusal below.
		if mkErr := os.Mkdir(path, 0o750); mkErr != nil && !errors.Is(mkErr, os.ErrExist) {
			return mkErr
		}
		if info, err = os.Lstat(path); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refuse non-directory or symlink at %s", path)
	}
	return nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	// #nosec G304 -- callers construct paths from the recorder root plus fixed
	// names or validated lowercase-hex identifiers; no request input reaches it.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (e *Emitter) EmitOpen() error      { return e.emit("open", nil, true) }
func (e *Emitter) EmitHeartbeat() error { return e.emit("heartbeat", nil, false) }
func (e *Emitter) EmitClose() error     { return e.emit("close", nil, true) }

func (e *Emitter) EmitActivity(activity Activity, durable bool) error {
	if activity.Class == "" || activity.ID == "" {
		return errors.New("AEL activity class and id are required")
	}
	switch activity.Direction {
	case "in", "out", "internal":
	default:
		return fmt.Errorf("invalid AEL activity direction %q", activity.Direction)
	}
	return e.emit("activity", map[string]any{"event": map[string]any{"class": activity.Class, "dir": activity.Direction, "id": activity.ID}}, durable)
}

func (e *Emitter) Opened() bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.opened
}

func (e *Emitter) emit(kind string, extra map[string]any, durable bool) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastErr != nil {
		return fmt.Errorf("native AEL emitter unhealthy: %w", e.lastErr)
	}
	if e.closed {
		return errors.New("native AEL run is closed")
	}
	if kind == "open" {
		if e.opened || e.seq != 0 {
			return errors.New("native AEL run is already open")
		}
	} else if !e.opened {
		return errors.New("native AEL run is not open")
	}
	if e.seq > maxSafeInt {
		e.lastErr = errors.New("native AEL sequence exceeds the canonical JSON safe-integer limit")
		return e.lastErr
	}
	payload := map[string]any{"key": e.keyID, "prev": e.prev, "recorder": recorderID, "run": e.run, "seq": e.seq, "ts": e.now().UTC().Format(time.RFC3339Nano), "type": kind, "v": recordVersion}
	for key, value := range extra {
		payload[key] = value
	}
	if kind == "open" {
		payload["hmax"], payload["htol"] = e.hmax, e.htol
	}
	if kind == "close" {
		payload["count"], payload["head"] = e.seq+1, e.prev
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal canonical AEL payload: %w", err)
	}
	sig := ed25519.Sign(e.privKey, canonical)
	line := base64.RawURLEncoding.EncodeToString(canonical) + "." + base64.RawURLEncoding.EncodeToString(sig) + "\n"
	next := sha256.Sum256(canonical)
	// Advance first: persistence failure leaves a detectable gap, never a fork.
	e.seq++
	e.prev = hex.EncodeToString(next[:])
	if kind == "open" {
		e.opened = true
	}
	if kind == "close" {
		e.closed = true
	}
	if _, err = e.file.WriteString(line); err == nil && durable {
		err = e.file.Sync()
	}
	if err != nil {
		e.lastErr = err
		return fmt.Errorf("persist native AEL %s: %w", kind, err)
	}
	if kind == "close" {
		if err := e.file.Close(); err != nil {
			e.lastErr = err
			return fmt.Errorf("close native AEL stream: %w", err)
		}
		if err := syncDirectory(filepath.Join(e.dir, "recorders")); err != nil {
			e.lastErr = err
			return fmt.Errorf("sync closed native AEL stream directory: %w", err)
		}
	}
	return nil
}
