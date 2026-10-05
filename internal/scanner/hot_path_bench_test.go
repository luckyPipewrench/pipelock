// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// benchReceipt is a signed-receipt-shaped document with no credentials. It is
// the per-action text the flight recorder scans before persisting a receipt.
const benchReceipt = `{"action_record":{"action_id":"01a108c0-5102-76ca-9190-fb50e5411a4f","action_type":"read","actor":"test-actor","chain_prev_hash":"genesis","chain_seq":0,"delegation_chain":null,"method":"GET","policy_hash":"abc123","principal":"test-principal","reversibility":"full","run_nonce":"6a8e5c842f4e7c2d5f23f8bf674e9f94","side_effect_class":"external_read","target":"http://api.vendor.example/ok?id=1","timestamp":"2026-10-04T21:09:43.810447048Z","transport":"fetch","verdict":"allow","version":1},"signature":"ed25519:af25ef97c148139ae64483be93d85d43547838a8399c3d8e444e0d61277e5952133064d1ccf573e6c284c71c585e7cee42c02c8c40a6adf7b76d3c20e3e81205","signer_key":"f9e3596921cdda82b2126ec2d24460e74b2782de2f67c610b7d1bd85b75f29fe","version":1}`

func benchReceiptScanner(b *testing.B) *Scanner {
	b.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(s.Close)
	return s
}

// BenchmarkHotPathAlwaysRunPatternsReceipt measures the patterns that the
// literal prefilter cannot rule out, on one receipt view.
func BenchmarkHotPathAlwaysRunPatternsReceipt(b *testing.B) {
	s := benchReceiptScanner(b)
	view := benchReceipt
	for b.Loop() {
		for _, idx := range s.dlpPreFilter.alwaysRun {
			s.dlpPatterns[idx].matchSpanInView(view, view)
		}
	}
}

func BenchmarkHotPathTextDLPReceipt(b *testing.B) {
	s := benchReceiptScanner(b)
	ctx := context.Background()
	for b.Loop() {
		if !s.ScanTextForDLP(ctx, benchReceipt).Clean {
			b.Fatal("receipt fixture must scan clean")
		}
	}
}

// benchKnownSecretsScanner loads count file secrets, the env/file known-value
// path that re-encodes every secret on every scan.
func benchKnownSecretsScanner(b *testing.B, count int) *Scanner {
	b.Helper()
	var secrets strings.Builder
	for i := range count {
		_, _ = fmt.Fprintf(&secrets, "bench-known-value-%02d-"+"Zq7Lm2Xc9Vb4"+"Nn8Kp3Rt6Wy1", i) // split so secret scanners skip the fake value
	}
	path := filepath.Join(b.TempDir(), "secrets.txt")
	if err := os.WriteFile(path, []byte(secrets.String()), 0o600); err != nil {
		b.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.SecretsFile = path
	s, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(s.Close)
	if len(s.fileSecrets) != count {
		b.Fatalf("loaded %d file secrets, want %d", len(s.fileSecrets), count)
	}
	return s
}

func BenchmarkHotPathKnownSecretsTextDLPReceipt(b *testing.B) {
	s := benchKnownSecretsScanner(b, 20)
	ctx := context.Background()
	for b.Loop() {
		if !s.ScanTextForDLP(ctx, benchReceipt).Clean {
			b.Fatal("receipt fixture must scan clean")
		}
	}
}

func BenchmarkHotPathKnownSecretsURL(b *testing.B) {
	s := benchKnownSecretsScanner(b, 20)
	ctx := context.Background()
	const target = "https://api.vendor.example/v1/items?cursor=6a8e5c842f4e7c2d5f23f8bf674e9f94&limit=50"
	for b.Loop() {
		s.Scan(ctx, target)
	}
}

func BenchmarkHotPathResponseSimpleFoldASCII(b *testing.B) {
	content := strings.Repeat("The quick brown fox jumps over the lazy dog. This is normal web content. ", 140)
	b.SetBytes(int64(len(content)))
	for b.Loop() {
		_ = responseSimpleFold(content)
	}
}

func BenchmarkHotPathScanResponseReceipt(b *testing.B) {
	s := MustNew(benchResponseConfig())
	b.Cleanup(s.Close)
	ctx := context.Background()
	for b.Loop() {
		s.ScanResponse(ctx, benchReceipt)
	}
}
