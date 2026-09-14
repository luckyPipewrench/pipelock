// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// rewriteRecorderEntries reads a recorder file, applies mutate to the parsed
// entries, re-links and re-hashes the outer chain, and writes the result to a
// new file. The outer chain stays valid so the test reaches the seal and
// receipt checks rather than failing earlier on a hash break.
func rewriteRecorderEntries(t *testing.T, path, name string, mutate func([]recorder.Entry) []recorder.Entry) string {
	t.Helper()
	entries, err := recorder.ReadEntries(path)
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	entries = mutate(entries)
	var seq uint64
	for i := range entries {
		entries[i].Sequence = seq
		seq++
		if i == 0 {
			entries[i].PrevHash = recorder.GenesisHash
		} else {
			entries[i].PrevHash = entries[i-1].Hash
		}
		entries[i].RawDetail = nil
		entries[i].Hash = recorder.ComputeHash(entries[i])
	}
	var rewritten strings.Builder
	for _, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("Marshal entry: %v", err)
		}
		rewritten.Write(data)
		rewritten.WriteByte('\n')
	}
	out := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(out, []byte(rewritten.String()), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return out
}

func runVerifyReceipt(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := VerifyReceiptCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestVerifyReceiptCmd_WholeRecorderFlagCombinationsRefused(t *testing.T) {
	t.Parallel()

	path, pub := buildSealedRecorderJSONL(t)
	key := hex.EncodeToString(pub)
	singleReceipt := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(singleReceipt, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "clean report", args: []string{path, "--whole-recorder", "--key", key, "--clean-report", filepath.Join(t.TempDir(), "report.json")}, want: "--whole-recorder cannot be combined with --clean-report"},
		{name: "fleet report", args: []string{path, "--whole-recorder", "--fleet-report", "--key", key}, want: "--whole-recorder cannot be combined with --fleet-report"},
		{name: "single receipt json", args: []string{singleReceipt, "--whole-recorder", "--key", key}, want: "--whole-recorder requires a recorder JSONL file or --chain directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runVerifyReceipt(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyReceiptCmd_WholeRecorderInputErrors(t *testing.T) {
	t.Parallel()

	path, pub := buildSealedRecorderJSONL(t)
	key := hex.EncodeToString(pub)

	t.Run("missing file", func(t *testing.T) {
		_, err := runVerifyReceipt(t, filepath.Join(t.TempDir(), "absent.jsonl"), "--whole-recorder", "--key", key)
		if err == nil || !strings.Contains(err.Error(), "reading recorder file") {
			t.Fatalf("err = %v, want reading recorder file", err)
		}
	})

	t.Run("unpinned without allow-unpinned fails closed", func(t *testing.T) {
		out, err := runVerifyReceipt(t, path, "--whole-recorder")
		if err == nil {
			t.Fatalf("unpinned whole-recorder verification must not pass:\n%s", out)
		}
		if strings.Contains(out, "Seal:      sealed at seq") {
			t.Fatalf("unpinned run must not report a seal:\n%s", out)
		}
	})

	t.Run("malformed transcript_root detail", func(t *testing.T) {
		mutated := rewriteRecorderEntries(t, path, "bad-root.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			for i := range entries {
				if entries[i].Type == "transcript_root" {
					entries[i].Detail = "not an object"
				}
			}
			return entries
		})
		out, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", key)
		if err == nil || !strings.Contains(err.Error(), "seal verification failed") || !strings.Contains(out, "SEAL MISMATCH") {
			t.Fatalf("malformed root err=%v output:\n%s", err, out)
		}
	})

	t.Run("transcript_root before any receipt", func(t *testing.T) {
		mutated := rewriteRecorderEntries(t, path, "early-root.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			rootIdx := -1
			for i := range entries {
				if entries[i].Type == "transcript_root" {
					rootIdx = i
				}
			}
			if rootIdx < 0 {
				t.Fatal("fixture has no transcript_root")
			}
			root := entries[rootIdx]
			rest := append([]recorder.Entry{}, entries[:rootIdx]...)
			rest = append(rest, entries[rootIdx+1:]...)
			return append([]recorder.Entry{root}, rest...)
		})
		out, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", key)
		if err == nil || !strings.Contains(err.Error(), "no matching receipt prefix") {
			t.Fatalf("early root err=%v output:\n%s", err, out)
		}
	})

	t.Run("malformed action_receipt detail", func(t *testing.T) {
		mutated := rewriteRecorderEntries(t, path, "bad-receipt.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			for i := range entries {
				if entries[i].Type == "action_receipt" {
					entries[i].Detail = "not a receipt"
					break
				}
			}
			return entries
		})
		_, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", key)
		if err == nil || !strings.Contains(err.Error(), "whole-recorder verification failed") {
			t.Fatalf("malformed receipt err = %v", err)
		}
	})
}
