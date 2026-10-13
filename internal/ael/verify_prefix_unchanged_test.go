// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRunVerifierPrefixUnchangedAfterFailure(t *testing.T) {
	for _, mode := range []string{"intact", "tampered", "replaced", "truncated", "manifest", "open_error", "stat_error"} {
		t.Run(mode, func(t *testing.T) {
			emitter, dir, signer := newIncrementalRun(t)
			v, err := NewRunVerifier(dir, incrementalRunID, signer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.Advance(false); err != nil {
				t.Fatal(err)
			}
			if err := v.VerifyPrefixUnchanged(); err != nil {
				t.Fatalf("intact prefix: %v", err)
			}
			open := v.fileOps.open
			v.fileOps.open = func(string) (*os.File, os.FileInfo, error) { return nil, nil, syscall.EMFILE }
			if _, err := v.Advance(false); !errors.Is(err, syscall.EMFILE) {
				t.Fatalf("injected open error: %v", err)
			}
			v.fileOps.open = open
			closeIncrementalRun(t, emitter)
			if _, err := VerifyRun(dir, incrementalRunID, signer); err != nil {
				t.Fatalf("fresh full verification: %v", err)
			}
			path := filepath.Join(emitter.Dir(), "recorders", "pipelock.jsonl")
			want := ""
			switch mode {
			case "tampered", "replaced":
				raw, err := os.ReadFile(filepath.Clean(path))
				if err != nil {
					t.Fatal(err)
				}
				if mode == "tampered" {
					raw[0] = '!'
					want = "bytes changed"
				} else {
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					want = "path changed"
				}
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
				want = "size or identity changed"
			case "manifest":
				if err := os.WriteFile(filepath.Join(emitter.Dir(), "manifest.json"), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
				want = "manifest"
			case "open_error":
				v.fileOps.open = func(string) (*os.File, os.FileInfo, error) { return nil, nil, syscall.EMFILE }
				want = syscall.EMFILE.Error()
			case "stat_error":
				v.fileOps.stat = func(*os.File) (os.FileInfo, error) { return nil, syscall.EIO }
				want = "changed during final verification"
			}
			err = v.VerifyPrefixUnchanged()
			if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
				t.Fatalf("prefix check=%v, want %q", err, want)
			}
			if _, err := v.Advance(true); !errors.Is(err, syscall.EMFILE) {
				t.Fatalf("prefix check cleared the original failure: %v", err)
			}
		})
	}
	var v *RunVerifier
	if err := v.VerifyPrefixUnchanged(); err == nil {
		t.Fatal("nil verifier accepted a prefix")
	}
}
