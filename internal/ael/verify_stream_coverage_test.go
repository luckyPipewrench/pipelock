// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestVerifyRunRejectsSignedRecordSchemaAndLifecycleDamage(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	const run = "0123456789abcdef0123456789abcdef"
	emitter := NewEmitter(rec, priv, run, 30)
	if err := emitter.EmitOpen(); err != nil {
		t.Fatal(err)
	}
	if err := emitter.EmitClose(); err != nil {
		t.Fatal(err)
	}
	signer := hex.EncodeToString(pub)
	path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
	original, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if head, err := VerifyRun(dir, run, signer); err != nil || head.RecordCount != 2 {
		t.Fatalf("intact signed run head=%+v err=%v", head, err)
	}
	lines := bytes.SplitAfter(original, []byte{'\n'})
	if len(lines) != 3 {
		t.Fatalf("signed run lines=%d, want 2", len(lines)-1)
	}
	parts := bytes.SplitN(bytes.TrimSpace(lines[0]), []byte{'.'}, 2)
	if len(parts) != 2 {
		t.Fatal("opening is not a compact signed record")
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
	if err != nil {
		t.Fatal(err)
	}
	var opening map[string]any
	if err := json.Unmarshal(payload, &opening); err != nil {
		t.Fatal(err)
	}
	sign := func(body []byte) []byte {
		out := []byte(base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, body)))
		return append(out, '\n')
	}
	for _, tc := range []struct {
		name, want string
		mutate     func(map[string]any)
	}{
		{"wrong run", "breaks run binding or chain", func(m map[string]any) { m["run"] = strings.Repeat("f", 32) }},
		{"bad timestamp", "invalid timestamp", func(m map[string]any) { m["ts"] = "not-a-time" }},
		{"wrong sequence type", "cannot unmarshal", func(m map[string]any) { m["seq"] = "zero" }},
		{"extra opening field", "record fields differ", func(m map[string]any) { m["extra"] = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyOpening := make(map[string]any, len(opening)+1)
			for key, value := range opening {
				copyOpening[key] = value
			}
			tc.mutate(copyOpening)
			body, err := json.Marshal(copyOpening)
			if err != nil {
				t.Fatal(err)
			}
			changed := append(sign(body), lines[1]...)
			if bytes.Equal(changed, original) {
				t.Fatal("signed mutation did not change stream")
			}
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			head, err := VerifyRun(dir, run, signer)
			if err == nil || head.RecordCount != 0 || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("damaged run head=%+v err=%v, want %q", head, err, tc.want)
			}
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, tc := range []struct {
		name, want string
		stream     []byte
	}{
		{"records after close", "records after close", append(bytes.Clone(original), lines[0]...)},
		{"oversized record", "record exceeds limit", append(bytes.Repeat([]byte{'x'}, maxVerifyRecordBytes+1), '\n')},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, tc.stream, 0o600); err != nil {
				t.Fatal(err)
			}
			head, err := VerifyRun(dir, run, signer)
			if err == nil || head.RecordCount != 0 || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("invalid stream head=%+v err=%v, want %q", head, err, tc.want)
			}
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
	withBlank := append([]byte("\n"), original...)
	if err := os.WriteFile(path, withBlank, 0o600); err != nil {
		t.Fatal(err)
	}
	if head, err := VerifyRun(dir, run, signer); err != nil || head.RecordCount != 2 {
		t.Fatalf("blank line changed signed head=%+v err=%v", head, err)
	}
}
