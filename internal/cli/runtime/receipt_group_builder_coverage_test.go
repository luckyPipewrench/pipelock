// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestReceiptGroupBuildersRejectUntrustedOrInvalidStartup(t *testing.T) {
	if shards, opts, err := buildServerReceiptShardGroup(receipt.EmitterConfig{}, 2, "", false); shards != nil || opts != nil || err == nil || !strings.Contains(err.Error(), "persistent recorder") {
		t.Fatalf("server builder accepted missing recorder: shards=%v opts=%v err=%v", shards, opts, err)
	}
	if group, err := buildMCPReceiptGroup(receipt.EmitterConfig{}, 2); group != nil || err == nil || !strings.Contains(err.Error(), "signed recorder") {
		t.Fatalf("MCP builder accepted missing signer: group=%v err=%v", group, err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"invalid signer", "invalid count", "damaged inventory"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, key)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = rec.Close() })
			cfg := receipt.EmitterConfig{Recorder: rec, PrivKey: key}
			count := 2
			want := ""
			switch mode {
			case "invalid signer":
				cfg.PrivKey = ed25519.PrivateKey("bad")
				want = "signing key"
			case "invalid count":
				count = 1
				want = "2 to 32 shards"
			case "damaged inventory":
				name := "receipt-group-" + strings.Repeat("a", 32) + "-open.json"
				if err := os.WriteFile(filepath.Join(dir, name), []byte("damaged"), 0o600); err != nil {
					t.Fatal(err)
				}
				want = "previous receipt group"
			}
			if shards, opts, err := buildServerReceiptShardGroup(cfg, count, "", false); shards != nil || opts != nil || err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("server builder accepted %s: shards=%v opts=%v err=%v", mode, shards, opts, err)
			}
			if group, err := buildMCPReceiptGroup(cfg, count); group != nil || err == nil || !strings.Contains(err.Error(), map[string]string{"invalid signer": "signing key", "invalid count": "2 to 32 shards", "damaged inventory": "previous MCP receipt group"}[mode]) {
				t.Fatalf("MCP builder accepted %s: group=%v err=%v", mode, group, err)
			}
		})
	}
}
