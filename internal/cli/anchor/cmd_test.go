// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	anchorpkg "github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func cliReceiptJSONL(t *testing.T) (path string, keyHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	prev := receipt.GenesisHash
	base := time.Date(2026, 6, 28, 13, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	for i := range 2 {
		ar := receipt.ActionRecord{
			Version:       receipt.ActionRecordVersion,
			ActionID:      receipt.NewActionID(),
			ActionType:    receipt.ActionRead,
			Timestamp:     base.Add(time.Duration(i) * time.Second),
			Target:        "https://example.test/resource",
			Verdict:       config.ActionAllow,
			Transport:     "fetch",
			ChainPrevHash: prev,
			ChainSeq:      uint64(i),
			PolicyHash:    "policy-test",
		}
		r, err := receipt.Sign(ar, priv)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		line, err := receipt.Marshal(r)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		_, _ = buf.Write(line)
		_ = buf.WriteByte('\n')
		prev, err = receipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash: %v", err)
		}
	}
	path = filepath.Join(t.TempDir(), "receipts.jsonl")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path, hex.EncodeToString(pub)
}

func TestReceiptsCmdWritesLocalAnchorBundle(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T13:00:00Z")
	receiptsPath, keyHex := cliReceiptJSONL(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "anchor.jsonl")
	bundlePath := filepath.Join(dir, "bundle.json")

	cmd := receiptsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		receiptsPath,
		"--key", keyHex,
		"--local-log", logPath,
		"--log-id", "cli-test-log",
		"--out", bundlePath,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "ANCHOR BUNDLE WRITTEN") {
		t.Fatalf("output missing success:\n%s", out.String())
	}
	bundle, err := anchorpkg.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if bundle.Proof.Backend != anchorpkg.LocalBackend || bundle.Proof.LogIndex != 0 {
		t.Fatalf("unexpected bundle proof: %+v", bundle.Proof)
	}
	entries, err := anchorpkg.ReadLocalLog(logPath)
	if err != nil {
		t.Fatalf("ReadLocalLog: %v", err)
	}
	if len(entries) != 1 || entries[0].LogID != "cli-test-log" {
		t.Fatalf("unexpected log entries: %+v", entries)
	}
}

func TestCmdRegistersReceiptsSubcommand(t *testing.T) {
	cmd := Cmd()
	if cmd.Use != "anchor" {
		t.Fatalf("Use = %q, want anchor", cmd.Use)
	}
	if _, _, err := cmd.Find([]string{"receipts"}); err != nil {
		t.Fatalf("Find receipts: %v", err)
	}
}

func TestReceiptsCmdRequiresLocalLogAndOutput(t *testing.T) {
	receiptsPath, keyHex := cliReceiptJSONL(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "local log",
			args: []string{receiptsPath, "--key", keyHex, "--out", filepath.Join(t.TempDir(), "bundle.json")},
			want: "--local-log is required",
		},
		{
			name: "output",
			args: []string{receiptsPath, "--key", keyHex, "--local-log", filepath.Join(t.TempDir(), "anchor.jsonl")},
			want: "--out is required",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := receiptsCmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetArgs(tc.args)
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Execute err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestReceiptsCmdRequiresPinnedKey(t *testing.T) {
	receiptsPath, _ := cliReceiptJSONL(t)
	cmd := receiptsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		receiptsPath,
		"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
		"--out", filepath.Join(t.TempDir(), "bundle.json"),
	})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "at least one --key") {
		t.Fatalf("Execute err = %v, want pinned-key error", err)
	}
}

func TestReceiptsCmdRejectsBlankPinnedKey(t *testing.T) {
	for _, key := range []string{"", "  "} {
		t.Run("blank_"+strings.ReplaceAll(key, " ", "space"), func(t *testing.T) {
			receiptsPath, keyHex := cliReceiptJSONL(t)
			cmd := receiptsCmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetArgs([]string{
				receiptsPath,
				"--key", key,
				"--key", keyHex,
				"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
				"--out", filepath.Join(t.TempDir(), "bundle.json"),
			})
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "public key is empty") {
				t.Fatalf("Execute err = %v, want blank-key error", err)
			}
		})
	}
}

func TestReceiptsCmdReturnsFallbackExtractionError(t *testing.T) {
	_, keyHex := cliReceiptJSONL(t)
	missingPath := filepath.Join(t.TempDir(), "missing.jsonl")
	cmd := receiptsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{
		missingPath,
		"--key", keyHex,
		"--local-log", filepath.Join(t.TempDir(), "anchor.jsonl"),
		"--out", filepath.Join(t.TempDir(), "bundle.json"),
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute err = nil, want missing evidence error")
	}
	if !strings.Contains(err.Error(), "reading raw receipts") {
		t.Fatalf("Execute err = %v, want fallback raw-receipt error", err)
	}
}
