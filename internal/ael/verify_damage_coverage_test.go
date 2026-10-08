// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestVerifyRunRejectsManifestAndKeyDamage(t *testing.T) {
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
	if head, err := VerifyRun(dir, run, signer); err != nil || head.RecordCount != 2 {
		t.Fatalf("intact run head=%+v err=%v", head, err)
	}
	if head, err := VerifyRun(dir, "invalid", signer); err == nil || head.RecordCount != 0 || !strings.Contains(err.Error(), "run nonce") {
		t.Fatalf("invalid run head=%+v err=%v", head, err)
	}
	if head, err := VerifyRun(dir, run, strings.ToUpper(signer)); err == nil || head.RecordCount != 0 || !strings.Contains(err.Error(), "signer") {
		t.Fatalf("noncanonical signer head=%+v err=%v", head, err)
	}
	if head, err := VerifyRun(dir, run, strings.Repeat("x", 64)); err == nil || head.RecordCount != 0 || !strings.Contains(err.Error(), "decode native AEL signer") {
		t.Fatalf("undecodable signer head=%+v err=%v", head, err)
	}
	manifestPath := filepath.Join(emitter.Dir(), "manifest.json")
	manifest, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		t.Fatal(err)
	}
	keyFiles, err := filepath.Glob(filepath.Join(emitter.Dir(), "keys", "*.pub"))
	if err != nil || len(keyFiles) != 1 {
		t.Fatalf("key files=%v err=%v", keyFiles, err)
	}
	key, err := os.ReadFile(keyFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, want string
		value            []byte
	}{
		{"oversized manifest", manifestPath, "manifest exceeds limit", make([]byte, 4097)},
		{"trailing manifest", manifestPath, "trailing tokens", append(append([]byte(nil), manifest...), []byte(" {}")...)},
		{"wrong manifest", manifestPath, "differs from signed run layout", []byte(`{}`)},
		{"short published key", keyFiles[0], "published key length differs", []byte("short")},
		{"wrong published key", keyFiles[0], "published key differs", []byte(strings.Repeat("A", len(key)))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := manifest
			if tc.path == keyFiles[0] {
				original = key
			}
			if err := os.WriteFile(tc.path, tc.value, 0o600); err != nil {
				t.Fatal(err)
			}
			head, err := VerifyRun(dir, run, signer)
			if err == nil || head.RecordCount != 0 || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("damaged run head=%+v err=%v, want %q", head, err, tc.want)
			}
			if err := os.WriteFile(tc.path, original, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	if head, err := VerifyRun(dir, run, signer); !errors.Is(err, os.ErrNotExist) || head.RecordCount != 0 {
		t.Fatalf("missing manifest head=%+v err=%v", head, err)
	}
}

func TestVerifyAELLineRejectsMalformedOrAmbiguousSignedPayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := func(payload string) []byte {
		body := []byte(payload)
		return []byte(base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, body)))
	}
	for _, tc := range []struct {
		name, want string
		line       []byte
	}{
		{"missing separator", "invalid native AEL compact record", []byte("broken")},
		{"bad payload encoding", "invalid native AEL payload encoding", []byte("!.sig")},
		{"bad signature", "invalid native AEL signature", []byte("e30.bad")},
		{"duplicate keys", "duplicate", signed(`{"v":1,"v":2}`)},
		{"noncanonical payload", "not canonical JSON", signed(`{ "v": 1 }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := verifyAELLine(tc.line, pub)
			if err == nil || payload != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("payload=%q err=%v, want %q", payload, err, tc.want)
			}
		})
	}
	if payload, err := verifyAELLine(signed(`{"v":1}`), pub); err != nil || string(payload) != `{"v":1}` {
		t.Fatalf("valid signed payload=%q err=%v", payload, err)
	}
}
