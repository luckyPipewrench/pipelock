// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	maxVerifyRecordBytes = 1 << 20
	maxVerifyStreamBytes = 256 << 20
)

var errAELStreamTooLarge = errors.New("native AEL stream exceeds 256 MiB")

// VerifiedHead is the final signed native AEL record, including the close.
type VerifiedHead struct {
	FinalSeq    uint64
	FinalHash   string
	RecordCount uint64
}

// VerifyRun reads one native AEL run with constant memory and requires its
// manifest, published key, every signature, hash link, and terminal close.
// The caller obtains run from the signed receipt session_open, never by
// picking a directory entry.
func VerifyRun(recorderDir, run, signerHex string) (VerifiedHead, error) {
	return verifyRun(recorderDir, run, signerHex, true)
}

// VerifyPresentRun authenticates every complete record in a claimed open run.
// Only a final unterminated line may be ignored as a live torn write.
func VerifyPresentRun(recorderDir, run, signerHex string) (VerifiedHead, error) {
	return verifyRun(recorderDir, run, signerHex, false)
}

func verifyRun(recorderDir, run, signerHex string, requireClose bool) (VerifiedHead, error) {
	if !runIDPattern.MatchString(run) {
		return VerifiedHead{}, errors.New("invalid native AEL run nonce")
	}
	if len(signerHex) != ed25519.PublicKeySize*2 || strings.ToLower(signerHex) != signerHex {
		return VerifiedHead{}, errors.New("invalid native AEL signer")
	}
	pub, err := hex.DecodeString(signerHex)
	if err != nil {
		return VerifiedHead{}, fmt.Errorf("decode native AEL signer: %w", err)
	}
	keyDigest := sha256.Sum256(pub)
	keyID := hex.EncodeToString(keyDigest[:])
	dir := filepath.Join(filepath.Clean(recorderDir), "ael", run)
	for _, path := range []string{filepath.Join(filepath.Clean(recorderDir), "ael"), dir, filepath.Join(dir, "keys"), filepath.Join(dir, "recorders")} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return VerifiedHead{}, fmt.Errorf("native AEL directory %q is missing or redirected", path)
		}
	}
	if err := verifyRunManifest(dir, run, keyID, pub); err != nil {
		return VerifiedHead{}, err
	}
	path := filepath.Join(dir, "recorders", "pipelock.jsonl")
	f, before, err := openRegularAEL(path)
	if err != nil {
		return VerifiedHead{}, err
	}
	defer func() { _ = f.Close() }()
	if before.Size() > maxVerifyStreamBytes {
		return VerifiedHead{}, errAELStreamTooLarge
	}
	r := bufio.NewReaderSize(f, maxVerifyRecordBytes)
	prev := zeroHash
	var count uint64
	var streamBytes int64
	closed := false
	for {
		line, readErr := readBoundedAELLine(r, &streamBytes, maxVerifyStreamBytes)
		if errors.Is(readErr, errAELStreamTooLarge) {
			return VerifiedHead{}, readErr
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			return VerifiedHead{}, errors.New("native AEL record exceeds limit")
		}
		if errors.Is(readErr, io.EOF) && len(line) == 0 {
			break
		}
		if errors.Is(readErr, io.EOF) && !requireClose && !closed {
			break // A live write may leave only its final line incomplete.
		}
		if readErr != nil || len(line) == 0 || line[len(line)-1] != '\n' || len(line) > maxVerifyRecordBytes {
			return VerifiedHead{}, errors.New("native AEL stream has torn or oversized line")
		}
		trimmed := recorder.TrimEntryLine(string(bytes.TrimSuffix(line, []byte{'\n'})))
		if trimmed == "" {
			continue
		}
		if closed {
			return VerifiedHead{}, errors.New("native AEL has records after close")
		}
		payload, err := verifyAELLine([]byte(trimmed), pub)
		if err != nil {
			return VerifiedHead{}, err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(payload, &fields); err != nil {
			return VerifiedHead{}, err
		}
		var record struct {
			Version  int    `json:"v"`
			Type     string `json:"type"`
			Run      string `json:"run"`
			Recorder string `json:"recorder"`
			Key      string `json:"key"`
			Prev     string `json:"prev"`
			Seq      uint64 `json:"seq"`
			TS       string `json:"ts"`
			Count    uint64 `json:"count"`
			Head     string `json:"head"`
		}
		if err := json.Unmarshal(payload, &record); err != nil {
			return VerifiedHead{}, err
		}
		if record.Version != recordVersion || record.Run != run || record.Recorder != recorderID || record.Key != keyID || record.Prev != prev || record.Seq != count || count > maxSafeInt {
			return VerifiedHead{}, fmt.Errorf("native AEL record %d breaks run binding or chain", count)
		}
		stamp, err := time.Parse(time.RFC3339Nano, record.TS)
		if err != nil || record.TS != stamp.UTC().Format(time.RFC3339Nano) {
			return VerifiedHead{}, fmt.Errorf("native AEL record %d has invalid timestamp", count)
		}
		if err := verifyAELFields(record.Type, count, fields, record.Count, record.Head, prev); err != nil {
			return VerifiedHead{}, err
		}
		h := sha256.Sum256(payload)
		prev = hex.EncodeToString(h[:])
		count++
		closed = record.Type == "close"
	}
	if requireClose && (!closed || count < 2) {
		return VerifiedHead{}, errors.New("native AEL run has no signed close")
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return VerifiedHead{}, errors.New("native AEL stream changed during verification")
	}
	finalSeq := uint64(0)
	if count > 0 {
		finalSeq = count - 1
	}
	return VerifiedHead{FinalSeq: finalSeq, FinalHash: prev, RecordCount: count}, nil
}

func readBoundedAELLine(r *bufio.Reader, total *int64, limit int64) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if int64(len(line)) > limit-*total {
		return nil, errAELStreamTooLarge
	}
	*total += int64(len(line))
	return line, err
}

func openRegularAEL(path string) (*os.File, os.FileInfo, error) {
	return recorder.OpenEvidenceFile(path)
}

func verifyRunManifest(dir, run, keyID string, pub []byte) error {
	manifestPath := filepath.Join(dir, "manifest.json")
	mf, info, err := openRegularAEL(manifestPath)
	if err != nil {
		return err
	}
	defer func() { _ = mf.Close() }()
	if info.Size() > 4096 {
		return errors.New("native AEL manifest exceeds limit")
	}
	raw, err := io.ReadAll(io.LimitReader(mf, 4097))
	if err != nil || len(raw) > 4096 {
		return errors.New("cannot read bounded native AEL manifest")
	}
	if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
		return err
	}
	var got manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		return err
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errors.New("native AEL manifest has trailing tokens")
	}
	want := manifest{Format: 1, Runs: []string{run}, Recorders: []manifestRecorder{{ID: recorderID, Run: run, Key: keyID, File: "recorders/pipelock.jsonl"}}, Coverage: "mediated-only", Custody: "same-process"}
	wantBytes, _ := json.Marshal(want)
	if !bytes.Equal(raw, wantBytes) {
		return errors.New("native AEL manifest differs from signed run layout")
	}
	keyPath := filepath.Join(dir, "keys", keyID+".pub")
	kf, keyInfo, err := openRegularAEL(keyPath)
	if err != nil {
		return err
	}
	defer func() { _ = kf.Close() }()
	if keyInfo.Size() != int64(base64.StdEncoding.EncodedLen(len(pub))) {
		return errors.New("native AEL published key length differs")
	}
	keyBytes, err := io.ReadAll(io.LimitReader(kf, 128))
	if err != nil || string(keyBytes) != base64.StdEncoding.EncodeToString(pub) {
		return errors.New("native AEL published key differs from trusted signer")
	}
	return nil
}

func verifyAELLine(line []byte, pub ed25519.PublicKey) ([]byte, error) {
	parts := bytes.Split(line, []byte{'.'})
	if len(parts) != 2 {
		return nil, errors.New("invalid native AEL compact record")
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
	if err != nil || len(payload) > maxVerifyRecordBytes || base64.RawURLEncoding.EncodeToString(payload) != string(parts[0]) {
		return nil, errors.New("invalid native AEL payload encoding")
	}
	sig, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil || len(sig) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(sig) != string(parts[1]) || !ed25519.Verify(pub, payload, sig) {
		return nil, errors.New("invalid native AEL signature")
	}
	if err := jsonscan.RejectDuplicateKeys(payload); err != nil {
		return nil, err
	}
	if err := jsonscan.RejectUnsafeNumbers(payload); err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(payload, &value); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(payload, canonical) {
		return nil, errors.New("native AEL payload is not canonical JSON")
	}
	return payload, nil
}

func verifyAELFields(kind string, seq uint64, fields map[string]json.RawMessage, count uint64, head, prev string) error {
	allowed := map[string]bool{"key": true, "prev": true, "recorder": true, "run": true, "seq": true, "ts": true, "type": true, "v": true}
	switch kind {
	case "open":
		if seq != 0 {
			return errors.New("native AEL open is not first")
		}
		allowed["hmax"], allowed["htol"] = true, true
	case "activity":
		allowed["event"] = true
	case "heartbeat":
	case "close":
		allowed["count"], allowed["head"] = true, true
		if count != seq+1 || head != prev {
			return errors.New("native AEL close head or count differs")
		}
	default:
		return errors.New("unknown native AEL record type")
	}
	if seq > 0 && kind == "open" || seq == 0 && kind != "open" {
		return errors.New("invalid native AEL lifecycle order")
	}
	if len(fields) != len(allowed) {
		return errors.New("native AEL record fields differ from type schema")
	}
	for key := range fields {
		if !allowed[key] {
			return fmt.Errorf("unexpected native AEL field %q", key)
		}
	}
	if kind == "open" {
		var hmax, htol int
		if err := json.Unmarshal(fields["hmax"], &hmax); err != nil {
			return errors.New("invalid native AEL heartbeat maximum")
		}
		if err := json.Unmarshal(fields["htol"], &htol); err != nil || hmax < 0 || htol < 0 || htol > hmax {
			return errors.New("invalid native AEL heartbeat bounds")
		}
	}
	if kind == "activity" {
		var event struct {
			Class string `json:"class"`
			Dir   string `json:"dir"`
			ID    string `json:"id"`
		}
		if err := jsonscan.RejectDuplicateKeys(fields["event"]); err != nil {
			return err
		}
		if err := json.Unmarshal(fields["event"], &event); err != nil || event.Class == "" || event.ID == "" || (event.Dir != "in" && event.Dir != "out" && event.Dir != "internal") {
			return errors.New("invalid native AEL activity")
		}
		var eventFields map[string]json.RawMessage
		if err := json.Unmarshal(fields["event"], &eventFields); err != nil || len(eventFields) != 3 {
			return errors.New("invalid native AEL activity fields")
		}
	}
	return nil
}
