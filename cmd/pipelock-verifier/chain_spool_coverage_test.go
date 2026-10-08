// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

type chainShortWriter struct{}

func (chainShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type chainFailWriter struct{}

func (chainFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriteGroupJSONSpoolRequiresWritableDestination(t *testing.T) {
	result := receipt.ReceiptGroupResult{GroupID: strings.Repeat("a", 32), Verdict: receipt.GroupInvalid}
	var count uint64
	for _, tc := range []struct {
		name, want string
		writer     io.Writer
	}{
		{"missing spool", "unavailable", nil},
		{"short write", "short write", chainShortWriter{}},
		{"write error", "closed pipe", chainFailWriter{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count = 0
			err := writeGroupJSONSpool(chainOptions{groupJSONSpool: tc.writer, groupJSONCount: &count}, result)
			if err == nil || !strings.Contains(err.Error(), tc.want) || count != 0 {
				t.Fatalf("spool error=%v count=%d, want %q and zero", err, count, tc.want)
			}
		})
	}
	var output bytes.Buffer
	if err := writeGroupJSONSpool(chainOptions{groupJSONSpool: &output, groupJSONCount: &count}, result); err != nil || count != 1 || !strings.Contains(output.String(), string(receipt.GroupInvalid)) {
		t.Fatalf("valid spool output=%q count=%d err=%v", output.String(), count, err)
	}
}

func TestEmitGroupedChainJSONRejectsMalformedSpools(t *testing.T) {
	for _, tc := range []struct {
		name, groups, legacy, want string
	}{
		{"invalid group", "not-json\n", "", "malformed JSON"},
		{"oversized group", strings.Repeat("x", 4<<20) + "\n", "", "read group JSON report spool"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			groups := chainSpoolFile(t, tc.groups)
			legacy := chainSpoolFile(t, tc.legacy)
			var out bytes.Buffer
			err := emitGroupedChainJSON(&out, groups, legacy, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) || out.Len() != 0 {
				t.Fatalf("report=%q err=%v, want %q", out.String(), err, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name, legacy, want string
	}{
		{"malformed legacy", "{", "decode legacy JSON report"},
		{"multiple legacy", "{} {}", "multiple legacy JSON reports"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			groups := chainSpoolFile(t, `{"verdict":"GROUP_INVALID"}`+"\n")
			legacy := chainSpoolFile(t, tc.legacy)
			var out bytes.Buffer
			err := emitGroupedChainJSON(&out, groups, legacy, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(out.String(), `"valid":false`) || !strings.Contains(out.String(), `"legacy":null`) {
				t.Fatalf("report=%q err=%v, want fail-closed %q", out.String(), err, tc.want)
			}
		})
	}
}

func TestEmitGroupedChainJSONReportsFailureAndOutputError(t *testing.T) {
	groups := chainSpoolFile(t, `{"verdict":"GROUP_INVALID"}`+"\n")
	legacy := chainSpoolFile(t, `{"valid":true}`)
	var out bytes.Buffer
	want := errors.New("group verification failed")
	if err := emitGroupedChainJSON(&out, groups, legacy, want); !errors.Is(err, want) || !strings.Contains(out.String(), `"valid":false`) || !strings.Contains(out.String(), `"error":"group verification failed"`) {
		t.Fatalf("failure report=%q err=%v", out.String(), err)
	}
	if err := emitGroupedChainJSON(chainFailWriter{}, groups, legacy, nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("output failure = %v, want closed pipe", err)
	}
}

func TestEmitGroupedChainJSONRejectsClosedSpoolsAndMissingScratch(t *testing.T) {
	groups := chainSpoolFile(t, `{"verdict":"GROUP_VALID"}`+"\n")
	legacy := chainSpoolFile(t, `{"valid":true}`)
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := emitGroupedChainJSON(&out, groups, legacy, nil); err == nil || !strings.Contains(err.Error(), "rewind legacy JSON report") || !strings.Contains(out.String(), `"valid":false`) {
		t.Fatalf("closed legacy report output=%q err=%v", out.String(), err)
	}
	goodLegacy := chainSpoolFile(t, `{"valid":true}`)
	if err := groups.Close(); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := emitGroupedChainJSON(&out, groups, goodLegacy, nil); err == nil || !strings.Contains(err.Error(), "rewind group JSON reports") || out.Len() != 0 {
		t.Fatalf("closed group report output=%q err=%v", out.String(), err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("TMPDIR", missing)
	if err := emitGroupedChainJSON(&out, groups, goodLegacy, nil); err == nil || !strings.Contains(err.Error(), "create combined JSON report") {
		t.Fatalf("missing scratch accepted: %v", err)
	}
}

func TestEmitGroupedChainJSONSeparatesMultipleGroups(t *testing.T) {
	groups := chainSpoolFile(t, `{"group_id":"first"}`+"\n"+`{"group_id":"second"}`+"\n")
	legacy := chainSpoolFile(t, "")
	var out bytes.Buffer
	if err := emitGroupedChainJSON(&out, groups, legacy, nil); err != nil || !strings.Contains(out.String(), `"groups":[{"group_id":"first"},{"group_id":"second"}]`) || !strings.Contains(out.String(), `"legacy":null`) {
		t.Fatalf("two-group report=%q err=%v", out.String(), err)
	}
}

func TestRunChainJSONRefusesUnavailableSpoolDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", filepath.Join(dir, "missing"))
	var out bytes.Buffer
	err := runChain(&out, &out, dir, chainOptions{asDir: true, jsonOutput: true})
	if err == nil || !strings.Contains(err.Error(), "create group report spool") || out.Len() != 0 {
		t.Fatalf("unavailable spool output=%q err=%v", out.String(), err)
	}
}

func TestRunChainDirectoryReportsInvalidGroupInventory(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "ael"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "receipt-group-invalid"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, jsonOutput := range []bool{false, true} {
		t.Run(map[bool]string{false: "text", true: "json"}[jsonOutput], func(t *testing.T) {
			var out bytes.Buffer
			err := runChain(&out, io.Discard, dir, chainOptions{asDir: true, sessionID: "proxy", signerKeys: []string{hex.EncodeToString(pub)}, jsonOutput: jsonOutput})
			if err == nil || !strings.Contains(err.Error(), "receipt group inventory failed") || !strings.Contains(out.String(), "GROUP_INVALID") {
				t.Fatalf("invalid inventory output=%q err=%v", out.String(), err)
			}
			if jsonOutput && (!strings.Contains(out.String(), `"valid":false`) || !strings.Contains(out.String(), "unknown receipt group artifact")) {
				t.Fatalf("invalid inventory JSON=%q", out.String())
			}
		})
	}
}

func chainSpoolFile(t *testing.T, content string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "chain-spool-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := io.WriteString(f, content); err != nil {
		t.Fatal(err)
	}
	return f
}
