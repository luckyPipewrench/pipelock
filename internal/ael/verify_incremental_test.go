// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const incrementalRunID = "0123456789abcdef0123456789abcdef"

func newIncrementalRun(t *testing.T) (*Emitter, string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	emitter := NewEmitter(rec, priv, incrementalRunID, 30)
	if emitter == nil {
		t.Fatal("nil emitter")
	}
	if err := emitter.EmitOpen(); err != nil {
		t.Fatal(err)
	}
	return emitter, dir, hex.EncodeToString(pub)
}

func closeIncrementalRun(t *testing.T, emitter *Emitter) {
	t.Helper()
	for i := range 3 {
		if err := emitter.EmitActivity(Activity{Class: "read", ID: "action-" + string(rune('1'+i)), Direction: "in"}, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := emitter.EmitClose(); err != nil {
		t.Fatal(err)
	}
}

func TestRunVerifierAdvancesAcrossTornAppend(t *testing.T) {
	emitter, dir, signer := newIncrementalRun(t)
	verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
	if err != nil {
		t.Fatal(err)
	}
	if head, err := verifier.Advance(false); err != nil || head.RecordCount != 1 {
		t.Fatalf("opening head=%+v err=%v", head, err)
	}
	path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
	if err := emitter.EmitActivity(Activity{Class: "read", ID: "action-1", Direction: "in"}, true); err != nil {
		t.Fatal(err)
	}
	stream, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(stream, []byte{'\n'})
	activityLine := lines[1]
	prefixOffset := int64(len(lines[0]))
	partialLength := len(activityLine) / 2
	if err := os.Truncate(path, prefixOffset+int64(partialLength)); err != nil {
		t.Fatal(err)
	}
	if head, err := verifier.Advance(false); err != nil || head.RecordCount != 1 {
		t.Fatalf("torn append head=%+v err=%v", head, err)
	}
	appendFile, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appendFile.Write(activityLine[partialLength:]); err != nil {
		t.Fatal(err)
	}
	if err := appendFile.Close(); err != nil {
		t.Fatal(err)
	}
	if head, err := verifier.Advance(false); err != nil || head.RecordCount != 2 {
		t.Fatalf("completed append head=%+v err=%v", head, err)
	}
	if err := emitter.EmitClose(); err != nil {
		t.Fatal(err)
	}
	if head, err := verifier.Advance(true); err != nil || head.RecordCount != 3 {
		t.Fatalf("closed head=%+v err=%v", head, err)
	}
	if err := verifier.VerifyUnchanged(); err != nil {
		t.Fatalf("unchanged run: %v", err)
	}
}

func TestRunVerifierRejectsChangesAfterAdvance(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *Emitter, string)
	}{
		{
			name: "same-size earlier record alteration",
			mutate: func(t *testing.T, emitter *Emitter, _ string) {
				t.Helper()
				path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
				f, err := os.OpenFile(filepath.Clean(path), os.O_RDWR, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				info, err := f.Stat()
				if err != nil {
					t.Fatal(err)
				}
				var original [1]byte
				if _, err := f.ReadAt(original[:], 10); err != nil {
					t.Fatal(err)
				}
				changed := []byte{'A'}
				if original[0] == changed[0] {
					changed[0] = 'B'
				}
				if _, err := f.WriteAt(changed, 10); err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "reordered already verified records",
			mutate: func(t *testing.T, emitter *Emitter, _ string) {
				t.Helper()
				path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
				content, err := os.ReadFile(filepath.Clean(path))
				if err != nil {
					t.Fatal(err)
				}
				lines := bytes.SplitAfter(content, []byte{'\n'})
				if len(lines) != 6 {
					t.Fatalf("unexpected record stream shape: %d lines", len(lines)-1)
				}
				reordered := bytes.Join([][]byte{lines[0], lines[1], lines[3], lines[2], lines[4], lines[5]}, nil)
				if err := os.WriteFile(filepath.Clean(path), reordered, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "truncated verified tail",
			mutate: func(t *testing.T, emitter *Emitter, _ string) {
				t.Helper()
				path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Truncate(path, info.Size()-1); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "removed stream",
			mutate: func(t *testing.T, emitter *Emitter, _ string) {
				t.Helper()
				if err := os.Remove(filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "same-content replacement",
			mutate: func(t *testing.T, emitter *Emitter, _ string) {
				t.Helper()
				path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
				replaceIncrementalTestFile(t, path)
			},
		},
		{
			name: "changed manifest",
			mutate: func(t *testing.T, emitter *Emitter, _ string) {
				t.Helper()
				path := filepath.Join(emitter.Dir(), "manifest.json")
				if err := os.WriteFile(filepath.Clean(path), []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "same-content manifest replacement",
			mutate: func(t *testing.T, emitter *Emitter, _ string) {
				t.Helper()
				path := filepath.Join(emitter.Dir(), "manifest.json")
				replaceIncrementalTestFile(t, path)
			},
		},
		{
			name: "same-content key replacement",
			mutate: func(t *testing.T, emitter *Emitter, signer string) {
				t.Helper()
				keyID := sha256Hex([]byte(signerFromEmitterForTest(t, emitter, signer)))
				path := filepath.Join(emitter.Dir(), "keys", keyID+".pub")
				replaceIncrementalTestFile(t, path)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			emitter, dir, signer := newIncrementalRun(t)
			closeIncrementalRun(t, emitter)
			verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.Advance(true); err != nil {
				t.Fatalf("initial advance: %v", err)
			}
			tc.mutate(t, emitter, signer)
			if err := verifier.VerifyUnchanged(); err == nil {
				t.Fatal("accepted changed run artifacts")
			}
			if err := verifier.VerifyUnchanged(); err == nil {
				t.Fatal("sticky verification error was not retained")
			}
		})
	}
}

func TestRunVerifierRejectsDamagedUnverifiedSuffix(t *testing.T) {
	for _, tc := range []struct {
		name   string
		want   string
		mutate func(*testing.T, *Emitter)
	}{
		{
			name: "truncated tail",
			want: "native AEL stream has torn or oversized line",
			mutate: func(t *testing.T, emitter *Emitter) {
				t.Helper()
				path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Truncate(path, info.Size()-1); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "record reordering",
			want: "native AEL record 1 breaks run binding or chain",
			mutate: func(t *testing.T, emitter *Emitter) {
				t.Helper()
				path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
				content, err := os.ReadFile(filepath.Clean(path))
				if err != nil {
					t.Fatal(err)
				}
				lines := bytes.SplitAfter(content, []byte{'\n'})
				if len(lines) != 5 {
					t.Fatalf("unexpected record stream shape: %d lines", len(lines)-1)
				}
				mutated := bytes.Join([][]byte{lines[0], lines[2], lines[1], lines[3], lines[4]}, nil)
				if err := os.WriteFile(filepath.Clean(path), mutated, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			emitter, dir, signer := newIncrementalRun(t)
			verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
			if err != nil {
				t.Fatal(err)
			}
			control, err := NewRunVerifier(dir, incrementalRunID, signer)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range []*RunVerifier{verifier, control} {
				if head, err := v.Advance(false); err != nil || head.RecordCount != 1 {
					t.Fatalf("opening advance head=%+v err=%v", head, err)
				}
			}
			for i := range 2 {
				if err := emitter.EmitActivity(Activity{Class: "read", ID: "action-" + string(rune('1'+i)), Direction: "in"}, true); err != nil {
					t.Fatal(err)
				}
			}
			if err := emitter.EmitClose(); err != nil {
				t.Fatal(err)
			}
			if head, err := control.Advance(true); err != nil || head.RecordCount != 4 {
				t.Fatalf("intact signed suffix head=%+v err=%v", head, err)
			}
			tc.mutate(t, emitter)
			if _, err := verifier.Advance(true); err == nil || err.Error() != tc.want {
				t.Fatalf("damaged suffix error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunVerifierValidatesInputsAndRequiresFinalClose(t *testing.T) {
	_, dir, signer := newIncrementalRun(t)
	for _, tc := range []struct {
		name, run, signer string
		want              string
	}{
		{"invalid run", "bad", signer, "run nonce"},
		{"uppercase signer", incrementalRunID, strings.ToUpper(signer), "signer"},
		{"invalid signer hex", incrementalRunID, strings.Repeat("x", 64), "decode native AEL signer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRunVerifier(dir, tc.run, tc.signer); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewRunVerifier error=%v, want %q", err, tc.want)
			}
		})
	}
	verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyUnchanged(); err == nil || !strings.Contains(err.Error(), "has not verified a close") {
		t.Fatalf("unfinalized unchanged check error=%v", err)
	}
	if _, err := verifier.Advance(true); err == nil || !strings.Contains(err.Error(), "no signed close") {
		t.Fatalf("missing close error=%v", err)
	}
	if _, err := verifier.Advance(false); err == nil {
		t.Fatal("sticky error did not reject future advance")
	}
}

func TestRunVerifierRejectsReplacedLayoutDirectory(t *testing.T) {
	emitter, dir, signer := newIncrementalRun(t)
	verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
	if err != nil {
		t.Fatal(err)
	}
	keysPath := filepath.Join(emitter.Dir(), "keys")
	backupPath := keysPath + "-saved"
	if err := os.Rename(keysPath, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backupPath, keysPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := verifier.Advance(false); err == nil || !strings.Contains(err.Error(), "changed or is redirected") {
		t.Fatalf("symlinked layout accepted: %v", err)
	}
}

func TestRunVerifierRejectsStreamGrowthAfterClose(t *testing.T) {
	emitter, dir, signer := newIncrementalRun(t)
	closeIncrementalRun(t, emitter)
	verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Advance(true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyUnchanged(); err == nil {
		t.Fatal("accepted appended bytes after close")
	}
}

func TestNewRunVerifierRejectsDamagedLayout(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *Emitter)
	}{
		{
			name: "missing manifest",
			mutate: func(t *testing.T, emitter *Emitter) {
				t.Helper()
				if err := os.Remove(filepath.Join(emitter.Dir(), "manifest.json")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing key",
			mutate: func(t *testing.T, emitter *Emitter) {
				t.Helper()
				keys, err := filepath.Glob(filepath.Join(emitter.Dir(), "keys", "*.pub"))
				if err != nil || len(keys) != 1 {
					t.Fatalf("key files=%v err=%v", keys, err)
				}
				if err := os.Remove(keys[0]); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing stream",
			mutate: func(t *testing.T, emitter *Emitter) {
				t.Helper()
				if err := os.Remove(filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlinked directory",
			mutate: func(t *testing.T, emitter *Emitter) {
				t.Helper()
				keys := filepath.Join(emitter.Dir(), "keys")
				backup := keys + "-saved"
				if err := os.Rename(keys, backup); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(backup, keys); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			emitter, dir, signer := newIncrementalRun(t)
			tc.mutate(t, emitter)
			if _, err := NewRunVerifier(dir, incrementalRunID, signer); err == nil {
				t.Fatal("accepted damaged run layout")
			}
		})
	}
}

func TestPathSnapshotsDetectMissingOversizedAndReplacedFiles(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.json")
		if _, err := readPathSnapshot(path, 128); err == nil {
			t.Fatal("read missing path snapshot")
		}
	})
	t.Run("oversized file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "large.json")
		if err := os.WriteFile(path, []byte("large"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readPathSnapshot(path, 1); err == nil {
			t.Fatal("read oversized path snapshot")
		}
	})
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string, []byte)
	}{
		{
			name: "content changed",
			mutate: func(t *testing.T, path string, _ []byte) {
				t.Helper()
				if err := os.WriteFile(filepath.Clean(path), []byte("other"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "same content replaced",
			mutate: func(t *testing.T, path string, _ []byte) {
				t.Helper()
				replaceIncrementalTestFile(t, path)
			},
		},
		{
			name: "removed file",
			mutate: func(t *testing.T, path string, _ []byte) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "artifact.json")
			content := []byte("bound content")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			snapshot, err := readPathSnapshot(path, 128)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, path, content)
			if err := verifyPathSnapshot(snapshot); err == nil {
				t.Fatal("accepted changed path snapshot")
			}
		})
	}
}

func TestRunVerifierAdvanceFinalizedIsIdempotent(t *testing.T) {
	emitter, dir, signer := newIncrementalRun(t)
	closeIncrementalRun(t, emitter)
	verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
	if err != nil {
		t.Fatal(err)
	}
	want, err := verifier.Advance(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, requireClose := range []bool{false, true} {
		got, err := verifier.Advance(requireClose)
		if err != nil || got != want {
			t.Fatalf("repeated advance(%t)=%+v err=%v want %+v", requireClose, got, err, want)
		}
	}
}

func TestRunVerifierRejectsPostCheckpointTruncationAndOversize(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string)
		want   string
	}{
		{
			name: "truncated checkpoint",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
			},
			want: "truncated after verification",
		},
		{
			name: "oversized stream",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Truncate(path, maxVerifyStreamBytes+1); err != nil {
					t.Fatal(err)
				}
			},
			want: "replaced or exceeds limit",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			emitter, dir, signer := newIncrementalRun(t)
			verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.Advance(false); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl"))
			if _, err := verifier.Advance(false); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Advance error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunVerifierRejectsLayoutChangeBeforeAdvance(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *Emitter)
		want   string
	}{
		{
			name: "invalid manifest",
			mutate: func(t *testing.T, emitter *Emitter) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(emitter.Dir(), "manifest.json"), []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "manifest differs",
		},
		{
			name: "replaced directory",
			mutate: func(t *testing.T, emitter *Emitter) {
				t.Helper()
				keys := filepath.Join(emitter.Dir(), "keys")
				backup := keys + "-saved"
				if err := os.Rename(keys, backup); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(backup, keys); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			},
			want: "changed or is redirected",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			emitter, dir, signer := newIncrementalRun(t)
			verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, emitter)
			if _, err := verifier.Advance(false); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Advance error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunVerifierNilReceiverFailsClosed(t *testing.T) {
	var verifier *RunVerifier
	if _, err := verifier.Advance(false); err == nil {
		t.Fatal("nil verifier advanced")
	}
	if err := verifier.VerifyUnchanged(); err == nil {
		t.Fatal("nil verifier verified unchanged")
	}
}

func TestRunVerifierFileOperationFailuresAreSticky(t *testing.T) {
	for _, tc := range []struct {
		name  string
		want  string
		setup func(*testing.T, *RunVerifier)
	}{
		{
			name: "open",
			setup: func(_ *testing.T, verifier *RunVerifier) {
				verifier.fileOps.open = func(string) (*os.File, os.FileInfo, error) {
					return nil, nil, errors.New("injected open error")
				}
			},
			want: "injected open error",
		},
		{
			name: "seek",
			setup: func(_ *testing.T, verifier *RunVerifier) {
				verifier.fileOps.seek = func(*os.File, int64) (int64, error) {
					return 0, errors.New("injected seek error")
				}
			},
			want: "injected seek error",
		},
		{
			name: "stat",
			setup: func(_ *testing.T, verifier *RunVerifier) {
				verifier.fileOps.stat = func(*os.File) (os.FileInfo, error) {
					return nil, errors.New("injected stat error")
				}
			},
			want: "changed during verification",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, dir, signer := newIncrementalRun(t)
			verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
			if err != nil {
				t.Fatal(err)
			}
			tc.setup(t, verifier)
			if _, err := verifier.Advance(false); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Advance error=%v", err)
			}
		})
	}
}

func TestRunVerifierRejectsOversizedRecord(t *testing.T) {
	emitter, dir, signer := newIncrementalRun(t)
	verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Advance(false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
	file, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(append(bytes.Repeat([]byte{'x'}, maxVerifyRecordBytes+1), '\n'))
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("append oversized record: write=%v close=%v", writeErr, closeErr)
	}
	if _, err := verifier.Advance(false); err == nil || !strings.Contains(err.Error(), "record exceeds limit") {
		t.Fatalf("oversized record error=%v", err)
	}
}

func TestRunVerifierRejectsStreamGrowthPastConfiguredReadBound(t *testing.T) {
	emitter, dir, signer := newIncrementalRun(t)
	verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Advance(false); err != nil {
		t.Fatal(err)
	}
	verifier.fileOps.maxReadStream = verifier.verifiedOffset + 2
	path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
	file, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString("extra\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("append suffix: write=%v close=%v", writeErr, closeErr)
	}
	if _, err := verifier.Advance(false); !errors.Is(err, errAELStreamTooLarge) {
		t.Fatalf("stream-bound error=%v", err)
	}
}

func TestRunVerifierFinalLayoutChangeDuringAdvance(t *testing.T) {
	emitter, dir, signer := newIncrementalRun(t)
	verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
	if err != nil {
		t.Fatal(err)
	}
	verifier.fileOps.stat = func(file *os.File) (os.FileInfo, error) {
		if err := os.WriteFile(filepath.Join(emitter.Dir(), "manifest.json"), []byte(`{}`), 0o600); err != nil {
			return nil, err
		}
		return file.Stat()
	}
	if _, err := verifier.Advance(false); err == nil || !strings.Contains(err.Error(), "manifest differs") {
		t.Fatalf("manifest mutation during advance accepted: %v", err)
	}
}

func TestRunVerifierUnchangedOperationFailuresAndFinalLayout(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *Emitter, *RunVerifier)
	}{
		{
			name: "open",
			setup: func(_ *testing.T, _ *Emitter, verifier *RunVerifier) {
				verifier.fileOps.open = func(string) (*os.File, os.FileInfo, error) {
					return nil, nil, errors.New("injected open error")
				}
			},
		},
		{
			name: "read",
			setup: func(_ *testing.T, _ *Emitter, verifier *RunVerifier) {
				originalOpen := verifier.fileOps.open
				verifier.fileOps.open = func(path string) (*os.File, os.FileInfo, error) {
					file, info, err := originalOpen(path)
					if err == nil {
						err = file.Close()
					}
					return file, info, err
				}
			},
		},
		{
			name: "stat",
			setup: func(_ *testing.T, _ *Emitter, verifier *RunVerifier) {
				verifier.fileOps.stat = func(*os.File) (os.FileInfo, error) {
					return nil, errors.New("injected stat error")
				}
			},
		},
		{
			name: "layout changed after read",
			setup: func(_ *testing.T, emitter *Emitter, verifier *RunVerifier) {
				verifier.fileOps.stat = func(file *os.File) (os.FileInfo, error) {
					if err := os.WriteFile(filepath.Join(emitter.Dir(), "manifest.json"), []byte(`{}`), 0o600); err != nil {
						return nil, err
					}
					return file.Stat()
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			emitter, dir, signer := newIncrementalRun(t)
			closeIncrementalRun(t, emitter)
			verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.Advance(true); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, emitter, verifier)
			if err := verifier.VerifyUnchanged(); err == nil {
				t.Fatal("accepted injected file operation failure")
			}
		})
	}
}

func TestNewRunVerifierRejectsOversizedInitialStream(t *testing.T) {
	emitter, dir, signer := newIncrementalRun(t)
	path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
	if err := os.Truncate(path, maxVerifyStreamBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRunVerifier(dir, incrementalRunID, signer); !errors.Is(err, errAELStreamTooLarge) {
		t.Fatalf("oversized initial stream error=%v", err)
	}
}

func TestNewRunVerifierReturnsSnapshotFailures(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			_, dir, signer := newIncrementalRun(t)
			calls := 0
			wantErr := errors.New("injected snapshot failure")
			snapshot := func(path string, limit int64) (pathSnapshot, error) {
				calls++
				if calls == failAt {
					return pathSnapshot{}, wantErr
				}
				return readPathSnapshot(path, limit)
			}
			if _, err := newRunVerifierWithSnapshot(dir, incrementalRunID, signer, snapshot); !errors.Is(err, wantErr) {
				t.Fatalf("NewRunVerifier error=%v", err)
			}
		})
	}
}

func TestNewRunVerifierRejectsFinalLayoutChange(t *testing.T) {
	emitter, dir, signer := newIncrementalRun(t)
	calls := 0
	snapshot := func(path string, limit int64) (pathSnapshot, error) {
		calls++
		got, err := readPathSnapshot(path, limit)
		if err != nil {
			return pathSnapshot{}, err
		}
		if calls == 2 {
			keys := filepath.Join(emitter.Dir(), "keys")
			backup := keys + "-saved"
			if err := os.Rename(keys, backup); err != nil {
				return pathSnapshot{}, err
			}
			if err := os.Symlink(backup, keys); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
		}
		return got, nil
	}
	if _, err := newRunVerifierWithSnapshot(dir, incrementalRunID, signer, snapshot); err == nil || !strings.Contains(err.Error(), "changed or is redirected") {
		t.Fatalf("final layout mutation accepted: %v", err)
	}
}

func TestPathSnapshotBoundedReadErrorsAndPathReplacement(t *testing.T) {
	t.Run("closed file read error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "artifact.json")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		closedFile, err := os.Open(path) // #nosec G304 -- path is inside this test's temporary directory.
		if err != nil {
			t.Fatal(err)
		}
		info, err := closedFile.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if err := closedFile.Close(); err != nil {
			t.Fatal(err)
		}
		_, err = readPathSnapshotWithOpen(path, 128, func(string) (*os.File, os.FileInfo, error) {
			return closedFile, info, nil
		})
		if err == nil {
			t.Fatal("accepted read error")
		}
	})
	t.Run("grew beyond limit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "artifact.json")
		if err := os.WriteFile(path, []byte("large"), 0o600); err != nil {
			t.Fatal(err)
		}
		actual, err := os.Open(path) // #nosec G304 -- path is inside this test's temporary directory.
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = actual.Close() }()
		fake, err := os.CreateTemp(t.TempDir(), "small-info-")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = fake.Close() }()
		if _, err := fake.WriteString("x"); err != nil {
			t.Fatal(err)
		}
		info, err := fake.Stat()
		if err != nil {
			t.Fatal(err)
		}
		_, err = readPathSnapshotWithOpen(path, 2, func(string) (*os.File, os.FileInfo, error) {
			return actual, info, nil
		})
		if err == nil || !strings.Contains(err.Error(), "cannot read bounded") {
			t.Fatalf("snapshot error=%v", err)
		}
	})
	t.Run("path replaced while reading", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "artifact.json")
		if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := readPathSnapshotWithOpen(path, 128, func(name string) (*os.File, os.FileInfo, error) {
			f, info, err := openRegularAEL(name)
			if err != nil {
				return nil, nil, err
			}
			backup := name + "-original"
			if err := os.Rename(name, backup); err != nil {
				return nil, nil, err
			}
			if err := os.WriteFile(name, []byte("replacement"), 0o600); err != nil {
				return nil, nil, err
			}
			replacement, err := os.Stat(name)
			if err != nil {
				return nil, nil, err
			}
			if os.SameFile(info, replacement) {
				_ = f.Close()
				t.Fatal("replacement precondition failed: original file identity retained")
			}
			return f, info, nil
		})
		if err == nil || !strings.Contains(err.Error(), "changed while reading") {
			t.Fatalf("snapshot error=%v", err)
		}
	})
}

func TestRunVerifierErrorIsSticky(t *testing.T) {
	emitter, dir, signer := newIncrementalRun(t)
	verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
	if err := os.WriteFile(filepath.Clean(path), []byte("invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Advance(false); err == nil {
		t.Fatal("accepted malformed line")
	}
	if _, err := verifier.Advance(false); err == nil {
		t.Fatal("sticky failure disappeared")
	} else if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected error after sticky failure: %v", err)
	}
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func signerFromEmitterForTest(t *testing.T, _ *Emitter, signer string) string {
	t.Helper()
	decoded, err := hex.DecodeString(signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(decoded)
}

// The existing file-open seam places a real append between the size snapshot
// and decoding. A final rehash must still refuse edits to that verified prefix.
func TestRunVerifierConcurrentAppendUsesFixedPrefix(t *testing.T) {
	for _, mode := range []string{"append", "prefix_edit", "final_append"} {
		t.Run(mode, func(t *testing.T) {
			emitter, dir, signer := newIncrementalRun(t)
			verifier, err := NewRunVerifier(dir, incrementalRunID, signer)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "final_append" {
				closeIncrementalRun(t, emitter)
				if _, err := VerifyRun(dir, incrementalRunID, signer); err != nil {
					t.Fatalf("intact closed stream: %v", err)
				}
			}
			original := verifier.fileOps.open
			verifier.fileOps.open = func(path string) (*os.File, os.FileInfo, error) {
				f, info, err := original(path)
				if err != nil {
					return f, info, err
				}
				if mode == "final_append" {
					appendFile, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
					if err != nil {
						t.Fatal(err)
					}
					_, writeErr := appendFile.WriteString("extra\n")
					closeErr := appendFile.Close()
					if err := errors.Join(writeErr, closeErr); err != nil {
						t.Fatal(err)
					}
				} else if err := emitter.EmitActivity(Activity{Class: "read", ID: "concurrent", Direction: "in"}, true); err != nil {
					t.Fatal(err)
				}
				return f, info, nil
			}
			head, err := verifier.Advance(mode == "final_append")
			verifier.fileOps.open = original
			if mode == "final_append" {
				if err == nil || err.Error() != "native AEL stream changed during verification" {
					t.Fatalf("final append error=%v, want changed during verification", err)
				}
				return
			}
			if err != nil || head.RecordCount != 1 {
				t.Fatalf("fixed prefix head=%+v err=%v", head, err)
			}
			if head, err := verifier.Advance(false); err != nil || head.RecordCount != 2 {
				t.Fatalf("next prefix head=%+v err=%v", head, err)
			}
			if err := emitter.EmitClose(); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyRun(dir, incrementalRunID, signer); err != nil {
				t.Fatalf("intact closed stream: %v", err)
			}
			if mode == "prefix_edit" {
				path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
				raw, err := os.ReadFile(filepath.Clean(path))
				if err != nil {
					t.Fatal(err)
				}
				raw[10] ^= 1
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := verifier.Advance(true); err != nil {
				t.Fatal(err)
			}
			err = verifier.VerifyUnchanged()
			if mode == "prefix_edit" {
				if err == nil || err.Error() != "native AEL stream bytes changed after verification" {
					t.Fatalf("prefix edit error=%v, want bytes changed after verification", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// replaceIncrementalTestFile allocates the replacement before freeing the
// original so filesystems cannot reuse the original identity.
func replaceIncrementalTestFile(t *testing.T, path string) {
	t.Helper()
	original, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := os.CreateTemp(filepath.Dir(path), "replacement-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.Write(content); err != nil {
		_ = replacement.Close()
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement.Name(), path); err != nil {
		t.Fatal(err)
	}
	actual, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(original, actual) {
		t.Fatal("replacement precondition failed: original file identity retained")
	}
}
