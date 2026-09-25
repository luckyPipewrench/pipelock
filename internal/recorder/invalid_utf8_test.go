// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// TestRecordedEntryWithInvalidUTF8VerifiesFromDisk covers an entry whose text
// fields hold invalid UTF-8, for example a summary built from request bytes.
// The written JSON replaces each invalid byte with U+FFFD, so the hash must
// cover that same text or the chain reads back as tampered.
func TestRecordedEntryWithInvalidUTF8VerifiesFromDisk(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1,
		SignCheckpoints:    true,
	}, nil, priv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := rec.Record(recorder.Entry{
		SessionID: "utf8",
		Type:      "test",
		Transport: "forward",
		Summary:   "blocked " + string([]byte{0xff, 0xfe}) + " target",
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-utf8-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if err := recorder.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

// TestRecordRefusesNonUTF8SessionID pins that a session ID with invalid UTF-8
// is refused rather than rewritten: it names the evidence file, so a
// rewritten ID would write one filename while resume looked up another.
func TestRecordRefusesNonUTF8SessionID(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir}, nil, priv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = rec.Close() }()
	err = rec.Record(recorder.Entry{SessionID: "agent" + string([]byte{0xff}), Type: "test", Transport: "forward"})
	if err == nil || !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Fatalf("Record error = %v, want non-UTF-8 session refusal", err)
	}
}
