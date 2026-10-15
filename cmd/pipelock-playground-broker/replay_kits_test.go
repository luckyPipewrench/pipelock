// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

func rewriteReplayBundle(t *testing.T, bundle []byte, change string) []byte {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gr.Close() }()
	var out bytes.Buffer
	gw := gzip.NewWriter(&out)
	tw := tar.NewWriter(gw)
	tr := tar.NewReader(gr)
	changed := false
	for {
		header, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		data, readErr := io.ReadAll(tr)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.HasSuffix(header.Name, "replay-archive-authorization.json") {
			changed = true
			if change == "missing authorization" {
				continue
			}
			data = bytes.Replace(data, []byte(`"run_nonce":"`), []byte(`"run_nonce":"tampered-`), 1)
			header.Size = int64(len(data))
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if !changed {
		t.Fatal("fixture has no replay authorization")
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestReplayKits(t *testing.T) {
	bundle, err := os.ReadFile("testdata/replay-bundle.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		wantOK bool
	}{
		{"valid", true}, {"tampered", false}, {"missing authorization", false}, {"malformed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := bundle
			if tc.name == "tampered" || tc.name == "missing authorization" {
				input = rewriteReplayBundle(t, bundle, tc.name)
			}
			if tc.name == "malformed" {
				input = []byte("not a tarball")
			}
			dir := t.TempDir()
			inputPath := filepath.Join(dir, "replay.tar.gz")
			output := filepath.Join(dir, "kits")
			if err := os.WriteFile(inputPath, input, 0o600); err != nil {
				t.Fatal(err)
			}
			verifier := filepath.Join(dir, "verifier")
			// Refused input must fail before even opening a verifier binary.
			if tc.wantOK {
				if err := os.WriteFile(verifier, []byte("test verifier"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := newRootCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs([]string{"replay-kits", "--bundle", inputPath, "--output-dir", output, "--linux-verifier", verifier, "--macos-verifier", verifier, "--windows-verifier", verifier})
			err := cmd.Execute()
			if (err == nil) != tc.wantOK {
				t.Fatalf("error = %v, output = %s", err, out.String())
			}
			if !tc.wantOK {
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatalf("refused replay wrote output: %v", err)
				}
				return
			}
			entries, err := os.ReadDir(output)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 3 {
				t.Fatalf("kits = %d, want 3", len(entries))
			}
			for _, entry := range entries {
				zr, err := zip.OpenReader(filepath.Join(output, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				launchers, authorizations := 0, 0
				for _, f := range zr.File {
					lower := strings.ToLower(f.Name)
					if strings.HasSuffix(lower, ".bat") || strings.HasSuffix(lower, ".command") || strings.HasSuffix(lower, ".sh") {
						launchers++
						r, err := f.Open()
						if err != nil {
							t.Fatal(err)
						}
						body, err := io.ReadAll(r)
						_ = r.Close()
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Contains(body, []byte(" --archive")) {
							t.Fatal("replay launcher lacks archive verification")
						}
					}
					if strings.HasSuffix(f.Name, "replay-archive-authorization.json") {
						authorizations++
					}
					if strings.HasSuffix(f.Name, "/VERIFY.txt") {
						t.Fatalf("%s carries the raw bundle's VERIFY.txt, whose paths don't match the kit", entry.Name())
					}
				}
				_ = zr.Close()
				if launchers != 1 || authorizations != 1 {
					t.Fatalf("%s: launchers=%d authorizations=%d", entry.Name(), launchers, authorizations)
				}
			}
			// An existing destination is never overwritten.
			if err := cmd.Execute(); err == nil {
				t.Fatal("existing kit directory was accepted")
			}
		})
	}
}

func TestReplayKitsHasNoSigningFlags(t *testing.T) {
	cmd := newReplayKitsCmd()
	for _, name := range []string{"orchestrator-key-file", "orchestrator-key-env", "private-key", "key", "run-dir"} {
		t.Run(name, func(t *testing.T) {
			if cmd.Flags().Lookup(name) != nil {
				t.Fatalf("unexpected signing flag %s", name)
			}
			cmd.SetArgs([]string{"--" + name, "unused"})
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unknown flag") {
				t.Fatalf("flag accepted: %v", err)
			}
		})
	}
}

func TestReadBoundedBundleRefusesOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.tar.gz")
	file, err := os.Create(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(playground.MaxBundleFileBytes) + 1); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if _, err := readBoundedBundle(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized bundle: err = %v", err)
	}
	exact := filepath.Join(t.TempDir(), "exact.tar.gz")
	if err := os.WriteFile(exact, make([]byte, 16), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readBoundedBundle(exact); err != nil || len(got) != 16 {
		t.Fatalf("small bundle: len=%d err=%v", len(got), err)
	}
}

func TestPublishArchiveKitDirectoryRollsBackPartialWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kits")
	// The second kit reuses the first name, so its exclusive create fails after
	// the first kit has been written.
	kits := []archiveKit{{name: "kit.zip", data: []byte("first")}, {name: "kit.zip", data: []byte("second")}}
	if err := publishArchiveKitDirectory(dir, kits); err == nil {
		t.Fatal("duplicate kit name was accepted")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("output directory left behind after failed publish: %v", err)
	}
}
