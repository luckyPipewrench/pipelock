// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestVerifyEpochPinBindsExactPinAndCurrentSource(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "recorder")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeInspectEpochFixture(t, dir, priv)
	pinPath := filepath.Join(parent, "epochs.json")
	if err := runInspectEpochs(inspectEpochsOutputCommand(&bytes.Buffer{}), inspectEpochsOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), outFile: pinPath}); err != nil {
		t.Fatalf("inspect epochs: %v", err)
	}
	// #nosec G304 -- pinPath is the test's own inspection output.
	pin, err := os.ReadFile(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(pin)
	valid := verifyEpochPinOptions{receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub), pinFile: pinPath, pinSHA256: hex.EncodeToString(digest[:])}
	var out bytes.Buffer
	if err := runVerifyEpochPin(inspectEpochsOutputCommand(&out), valid); err != nil {
		t.Fatalf("verify epoch pin: %v", err)
	}
	if !strings.Contains(out.String(), "epoch inspection pin verified") {
		t.Fatalf("output = %q", out.String())
	}
	if !strings.Contains(out.String(), "retirement is not authorized") {
		t.Fatalf("output overclaims preflight: %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence-proxy-0.jsonl")); err != nil {
		t.Fatalf("preflight mutated source: %v", err)
	}

	t.Run("wrong digest", func(t *testing.T) {
		opts := valid
		opts.pinSHA256 = strings.Repeat("0", sha256.Size*2)
		err := runVerifyEpochPin(inspectEpochsOutputCommand(&bytes.Buffer{}), opts)
		if err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("empty session", func(t *testing.T) {
		opts := valid
		opts.sessionID = " "
		if err := runVerifyEpochPin(inspectEpochsOutputCommand(&bytes.Buffer{}), opts); err == nil || !strings.Contains(err.Error(), "--session is required") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("session mismatch", func(t *testing.T) {
		opts := valid
		opts.sessionID = "other"
		if err := runVerifyEpochPin(inspectEpochsOutputCommand(&bytes.Buffer{}), opts); err == nil || !strings.Contains(err.Error(), "does not match --session") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("noncanonical pin", func(t *testing.T) {
		noncanonicalPath := filepath.Join(parent, "noncanonical.json")
		noncanonical := append([]byte(" "), pin...)
		if err := os.WriteFile(noncanonicalPath, noncanonical, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(noncanonical)
		opts := valid
		opts.pinFile = noncanonicalPath
		opts.pinSHA256 = hex.EncodeToString(sum[:])
		err := runVerifyEpochPin(inspectEpochsOutputCommand(&bytes.Buffer{}), opts)
		if err == nil || !strings.Contains(err.Error(), "not canonical") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("degraded receipt proof", func(t *testing.T) {
		var document inspectEpochsDocument
		if err := json.Unmarshal(pin, &document); err != nil {
			t.Fatal(err)
		}
		document.ReceiptVerification.Status = "degraded_per_epoch"
		document.RecorderEpochs[0].V1Degraded = true
		writePinAndExpectError(t, parent, document, valid, "degraded in legacy epoch")
	})

	t.Run("single epoch", func(t *testing.T) {
		var document inspectEpochsDocument
		if err := json.Unmarshal(pin, &document); err != nil {
			t.Fatal(err)
		}
		document.RecorderEpochs = document.RecorderEpochs[:1]
		writePinAndExpectError(t, parent, document, valid, "multi-epoch history")
	})

	t.Run("zero signed receipts", func(t *testing.T) {
		var document inspectEpochsDocument
		if err := json.Unmarshal(pin, &document); err != nil {
			t.Fatal(err)
		}
		for i := range document.RecorderEpochs {
			document.RecorderEpochs[i].V1Count = 0
		}
		writePinAndExpectError(t, parent, document, valid, "0 signed receipt")
	})

	t.Run("unsigned checkpoint proof", func(t *testing.T) {
		var document inspectEpochsDocument
		if err := json.Unmarshal(pin, &document); err != nil {
			t.Fatal(err)
		}
		document.CheckpointVerification.Unsigned = []compactUnsignedCheckpoint{{Epoch: 0, RecorderSeq: 1}}
		writePinAndExpectError(t, parent, document, valid, "unsigned checkpoint")
	})

	t.Run("bad receipt directory", func(t *testing.T) {
		opts := valid
		opts.receiptDir = filepath.Join(parent, "missing")
		if err := runVerifyEpochPin(inspectEpochsOutputCommand(&bytes.Buffer{}), opts); err == nil {
			t.Fatal("missing receipt directory accepted")
		}
	})

	t.Run("bad location", func(t *testing.T) {
		opts := valid
		opts.locationID = "../outside"
		if err := runVerifyEpochPin(inspectEpochsOutputCommand(&bytes.Buffer{}), opts); err == nil || !strings.Contains(err.Error(), "resolve evidence location") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("bad key", func(t *testing.T) {
		opts := valid
		opts.publicKey = "bad"
		if err := runVerifyEpochPin(inspectEpochsOutputCommand(&bytes.Buffer{}), opts); err == nil || !strings.Contains(err.Error(), "load --key") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("active writer", func(t *testing.T) {
		rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rec.Close() }()
		if err := runVerifyEpochPin(inspectEpochsOutputCommand(&bytes.Buffer{}), valid); err == nil || !strings.Contains(err.Error(), "lock stopped evidence directory") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("source changed", func(t *testing.T) {
		path := filepath.Join(dir, "evidence-proxy-0.jsonl")
		// #nosec G304 -- path is the test's own evidence fixture.
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		original := append([]byte(nil), data...)
		defer func() {
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Errorf("restore source: %v", err)
			}
		}()
		data[len(data)/2] ^= 1
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		err = runVerifyEpochPin(inspectEpochsOutputCommand(&bytes.Buffer{}), valid)
		if err == nil || !strings.Contains(err.Error(), "re-verify epoch source") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("valid source drift", func(t *testing.T) {
		path := filepath.Join(dir, "evidence-proxy-0.jsonl")
		// #nosec G304 -- path is the test's own evidence fixture.
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Errorf("restore source: %v", err)
			}
		}()
		lines := bytes.Split(bytes.TrimSpace(original), []byte{'\n'})
		var entry recorder.Entry
		if err := json.Unmarshal(lines[1], &entry); err != nil {
			t.Fatal(err)
		}
		entry.Timestamp = time.Unix(99, 0).UTC()
		entry.Hash = recorder.ComputeHash(entry)
		lines[1], err = json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		changed := append(bytes.Join(lines, []byte{'\n'}), '\n')
		if err := os.WriteFile(path, changed, 0o600); err != nil {
			t.Fatal(err)
		}
		err = runVerifyEpochPin(inspectEpochsOutputCommand(&bytes.Buffer{}), valid)
		if err == nil || !strings.Contains(err.Error(), "no longer matches") {
			t.Fatalf("error = %v", err)
		}
	})
}

func writePinAndExpectError(t *testing.T, parent string, document inspectEpochsDocument, valid verifyEpochPinOptions, want string) {
	t.Helper()
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := filepath.Join(parent, strings.ReplaceAll(t.Name(), "/", "-")+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	valid.pinFile = path
	valid.pinSHA256 = hex.EncodeToString(digest[:])
	err = runVerifyEpochPin(inspectEpochsOutputCommand(&bytes.Buffer{}), valid)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestVerifyEpochPinRejectsMalformedDigestBeforeReadingPin(t *testing.T) {
	err := runVerifyEpochPin(inspectEpochsOutputCommand(&bytes.Buffer{}), verifyEpochPinOptions{sessionID: "proxy", pinFile: filepath.Join(t.TempDir(), "missing"), pinSHA256: "bad"})
	if err == nil || !strings.Contains(err.Error(), "exactly 64 hexadecimal") {
		t.Fatalf("error = %v", err)
	}
}

func TestReadEpochPinRejectsMalformedInputs(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "malformed JSON", data: []byte("{\n"), want: "decode --pin"},
		{name: "unsupported version", data: []byte("{\"version\":2}\n"), want: "unsupported epoch pin version"},
		{name: "trailing value", data: []byte("{\"version\":1} true\n"), want: "trailing JSON value"},
		{name: "oversized", data: bytes.Repeat([]byte("x"), (8<<20)+1), want: "exceeds 8 MiB"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pin.json")
			if err := os.WriteFile(path, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(test.data)
			_, _, err := readEpochPin(path, digest[:])
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, _, err := readEpochPin(missing, make([]byte, sha256.Size)); err == nil || !strings.Contains(err.Error(), "open --pin") {
		t.Fatalf("missing pin error = %v", err)
	}
}
