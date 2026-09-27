// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// These tests hold pipelock-verifier to the verdicts verify-receipt reaches
// on the same real Go-written evidence: the run-chain conformance fixtures.

const (
	parityRun1   = "proxy.run.03b13ee13e01e7f770480f62ea42f1fe"
	parityRun2   = "proxy.run.f7b327337534352a514bd0a256b1d1c0"
	parityReplay = "proxy.run.00000000000000000000000000000000"
	rotatedRun   = "proxy.run.da660e29de374fd065cf1a12b3abde7b"
)

func runFileIn(dir, session string) string {
	return filepath.Join(dir, "evidence-"+session+"-0.jsonl")
}

// editLines rewrites path line by line; returning nil drops the line.
func editLines(t *testing.T, path string, edit func(line []byte) []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, l := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if e := edit(l); e != nil {
			out = append(out, e)
		}
	}
	if err := os.WriteFile(filepath.Clean(path), append(bytes.Join(out, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// forgeFirstV2 edits a signed field of the first EvidenceReceipt v2 and
// recomputes the recorder hash chain, so only the receipt's own signature can
// catch it.
func forgeFirstV2(t *testing.T, path string) {
	t.Helper()
	done := false
	editLines(t, path, func(l []byte) []byte {
		if !done && bytes.Contains(l, []byte(`"type":"evidence_receipt"`)) {
			done = true
			return bytes.Replace(l, []byte(`"actor":"pipelock"`), []byte(`"actor":"pipelocx"`), 1)
		}
		return l
	})
	if !done {
		t.Fatal("no evidence receipt to forge")
	}
	rehashRecorderFile(t, path)
}

func TestChain_RotatedEvidenceTrust(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(runChainFixtures, "key-rotated")
	keyA := readRunChainFixture(t, "signer-key.hex")
	keyB := readRunChainFixture(t, "rotated-signer-key.hex")
	endorsement := filepath.Join(dir, "rotation-endorsement.json")
	for name, tc := range map[string]struct {
		args []string
		code int
	}{
		"first key only":                 {[]string{"--key", keyA}, 1},
		"both keys":                      {[]string{"--key", keyA, "--key", keyB}, 0},
		"first key and endorsement":      {[]string{"--key", keyA, "--rotation-endorsement", endorsement}, 0},
		"endorsement without a root key": {[]string{"--rotation-endorsement", endorsement}, 2},
		"named rotated run, both keys":   {[]string{"--key", keyA, "--key", keyB, "--session", rotatedRun}, 0},
		"named rotated run, endorsed":    {[]string{"--key", keyA, "--rotation-endorsement", endorsement, "--session", rotatedRun}, 0},
		"named rotated run, first only":  {[]string{"--key", keyA, "--session", rotatedRun}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, code := runRoot(t, append([]string{"chain", dir, "--dir"}, tc.args...)...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\n%s%s", code, tc.code, stdout, stderr)
			}
		})
	}
	// The rotated run's own file verifies under its own key.
	if stdout, stderr, code := runRoot(t, "chain", runFileIn(dir, rotatedRun), "--key", keyB); code != 0 {
		t.Fatalf("rotated run file: exit %d\n%s%s", code, stdout, stderr)
	}
}

func TestChain_NamedRunFailsOnAnotherRunsFinding(t *testing.T) {
	t.Parallel()
	key := readRunChainFixture(t, "signer-key.hex")
	clean := copyFixtureDir(t, "valid")
	if stdout, stderr, code := runRoot(t, "chain", clean, "--dir", "--key", key, "--session", parityRun1); code != 0 {
		t.Fatalf("positive control: exit %d\n%s%s", code, stdout, stderr)
	}
	dir := copyFixtureDir(t, "valid")
	forgeFirstV2(t, runFileIn(dir, parityRun2))
	stdout, stderr, code := runRoot(t, "chain", dir, "--dir", "--key", key, "--session", parityRun1, "--json")
	var got chainReport
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if code != 1 || got.Valid || !strings.Contains(got.Error, "corrupt_chain on "+parityRun2) {
		t.Fatalf("exit %d valid=%v error=%q: want a failure naming %s", code, got.Valid, got.Error, parityRun2)
	}
	if !strings.Contains(stderr, parityRun2) {
		t.Fatalf("stderr must name the offending run:\n%s", stderr)
	}
}

func TestChain_DirectoryForgedV2AndDuplicateRun(t *testing.T) {
	t.Parallel()
	key := readRunChainFixture(t, "signer-key.hex")
	t.Run("forged v2 with rehashed recorder chain", func(t *testing.T) {
		t.Parallel()
		dir := copyFixtureDir(t, "valid")
		forgeFirstV2(t, runFileIn(dir, parityRun2))
		stdout, stderr, code := runRoot(t, "chain", dir, "--dir", "--key", key)
		if code != 1 || !strings.Contains(stdout+stderr, "evidence receipt chain") {
			t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
		}
	})
	t.Run("replayed run under a new session name", func(t *testing.T) {
		t.Parallel()
		dir := copyFixtureDir(t, "valid")
		data, err := os.ReadFile(filepath.Clean(runFileIn(dir, parityRun1)))
		if err != nil {
			t.Fatal(err)
		}
		replay := runFileIn(dir, parityReplay)
		if err := os.WriteFile(replay, data, 0o600); err != nil {
			t.Fatal(err)
		}
		editLines(t, replay, func(l []byte) []byte {
			return bytes.ReplaceAll(l, []byte(`"session_id":"`+parityRun1+`"`), []byte(`"session_id":"`+parityReplay+`"`))
		})
		rehashRecorderFile(t, replay)
		stdout, _, code := runRoot(t, "chain", dir, "--dir", "--key", key, "--json")
		var got chainSetReport
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatalf("decode: %v\n%s", err, stdout)
		}
		found := false
		for _, f := range got.Continuity.Findings {
			if f.Kind == receipt.FindingDuplicateRunNonce {
				found = true
			}
		}
		if code != 1 || got.Valid || !found {
			t.Fatalf("exit %d valid=%v findings=%+v: want duplicate_run_nonce", code, got.Valid, got.Continuity.Findings)
		}
	})
}

func TestChain_FileModeRules(t *testing.T) {
	t.Parallel()
	key := readRunChainFixture(t, "signer-key.hex")
	for name, tc := range map[string]struct {
		setup   func(t *testing.T, dir string) string
		code    int
		wantOut string
	}{
		"clean": {
			setup: func(_ *testing.T, dir string) string { return runFileIn(dir, parityRun2) },
		},
		"recorder hash chain broken, receipts intact": {
			setup: func(t *testing.T, dir string) string {
				editLines(t, runFileIn(dir, parityRun2), func(l []byte) []byte {
					if bytes.Contains(l, []byte(`"type":"decision"`)) {
						return bytes.Replace(l, []byte(`"summary":"`), []byte(`"summary":"edited `), 1)
					}
					return l
				})
				return runFileIn(dir, parityRun2)
			},
			code: 1, wantOut: "recorder entry hash chain",
		},
		"another session's entries under this name": {
			setup: func(t *testing.T, dir string) string {
				data, err := os.ReadFile(filepath.Clean(runFileIn(dir, parityRun1)))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(runFileIn(dir, parityReplay), data, 0o600); err != nil {
					t.Fatal(err)
				}
				return runFileIn(dir, parityReplay)
			},
			code: 1, wantOut: "does not match requested session",
		},
		"only evidence receipts": {
			setup: func(t *testing.T, dir string) string {
				editLines(t, runFileIn(dir, parityRun2), func(l []byte) []byte {
					if bytes.Contains(l, []byte(`"type":"action_receipt"`)) {
						return nil
					}
					return l
				})
				rehashRecorderFile(t, runFileIn(dir, parityRun2))
				return runFileIn(dir, parityRun2)
			},
			wantOut: recordTypeEvidenceV2,
		},
		"only evidence receipts, one forged": {
			setup: func(t *testing.T, dir string) string {
				editLines(t, runFileIn(dir, parityRun2), func(l []byte) []byte {
					if bytes.Contains(l, []byte(`"type":"action_receipt"`)) {
						return nil
					}
					return l
				})
				forgeFirstV2(t, runFileIn(dir, parityRun2))
				return runFileIn(dir, parityRun2)
			},
			code: 1, wantOut: "signature",
		},
		"explicit symlinked file is read as given": {
			setup: func(t *testing.T, dir string) string {
				link := filepath.Join(t.TempDir(), filepath.Base(runFileIn(dir, parityRun2)))
				if err := os.Symlink(runFileIn(dir, parityRun2), link); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				return link
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := tc.setup(t, copyFixtureDir(t, "valid"))
			stdout, stderr, code := runRoot(t, "chain", path, "--key", key, "--json")
			if code != tc.code || !strings.Contains(stdout+stderr, tc.wantOut) {
				t.Fatalf("exit %d, want %d with %q\n%s%s", code, tc.code, tc.wantOut, stdout, stderr)
			}
		})
	}
}

func TestChain_DirectorySymlinkRefusedAsVerificationFailure(t *testing.T) {
	t.Parallel()
	key := readRunChainFixture(t, "signer-key.hex")
	dir := copyFixtureDir(t, "valid")
	outside := filepath.Join(t.TempDir(), "run2.jsonl")
	data, err := os.ReadFile(filepath.Clean(runFileIn(dir, parityRun2)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(runFileIn(dir, parityRun2)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, runFileIn(dir, parityRun2)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, extra := range [][]string{nil, {"--session", parityRun1}} {
		_, stderr, code := runRoot(t, append([]string{"chain", dir, "--dir", "--key", key}, extra...)...)
		if code != 1 || !strings.Contains(stderr, "refuse symlink") || !strings.Contains(stderr, filepath.Base(runFileIn(dir, parityRun2))) {
			t.Fatalf("%v: exit %d, want 1 naming the file\n%s", extra, code, stderr)
		}
	}
}

// writeRunPacket wraps one run's evidence file in a v0 Audit Packet whose
// claims match its action chain.
func writeRunPacket(t *testing.T, evidence []byte, keyHex string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evidence.jsonl"), evidence, 0o600); err != nil {
		t.Fatal(err)
	}
	receipts, err := receipt.ExtractReceiptsBytes(evidence)
	if err != nil {
		t.Fatal(err)
	}
	res := receipt.VerifyChain(receipts, keyHex)
	if !res.Valid {
		t.Fatalf("action chain of the packet evidence: %s", res.Error)
	}
	raw, err := os.ReadFile(filepath.Clean("../../sdk/audit-packet/example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	totals := map[string]any{"allow": 0, "block": 0, "warn": 0, "ask": 0, "strip": 0, "forward": 0, "redirect": 0, "other": 0}
	for k, v := range computeTotals(receipts) {
		totals[k] = v
	}
	summary := p["summary"].(map[string]any)
	summary["receipt_count"] = len(receipts)
	summary["totals"] = totals
	v := p["verifier"].(map[string]any)
	v["receipt_count"] = len(receipts)
	v["final_seq"] = res.FinalSeq
	v["root_hash"] = res.RootHash
	v["signer_key"] = keyHex
	p["artifacts"].(map[string]any)["evidence"] = "evidence.jsonl"
	out, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packet.json"), out, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAuditPacket_VerifiesBothChainsOfItsEvidence(t *testing.T) {
	t.Parallel()
	key := readRunChainFixture(t, "signer-key.hex")
	dir := copyFixtureDir(t, "valid")
	clean, err := os.ReadFile(filepath.Clean(runFileIn(dir, parityRun2)))
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runRoot(t, "audit-packet", writeRunPacket(t, clean, key), "--key", key, "--json")
	if code != 0 || !strings.Contains(stdout, `"trusted": true`) {
		t.Fatalf("positive control: exit %d\n%s%s", code, stdout, stderr)
	}
	forgeFirstV2(t, runFileIn(dir, parityRun2))
	forged, err := os.ReadFile(filepath.Clean(runFileIn(dir, parityRun2)))
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runRoot(t, "audit-packet", writeRunPacket(t, forged, key), "--key", key, "--json")
	var got auditPacketReport
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if code != 1 || got.Trusted || got.Valid || got.Verdict == "valid" || got.ChainCheck != statusFail {
		t.Fatalf("forged v2 packet: exit %d trusted=%v valid=%v verdict=%q chain=%q", code, got.Trusted, got.Valid, got.Verdict, got.ChainCheck)
	}
	if !strings.Contains(stderr, "evidence receipt chain") {
		t.Fatalf("stderr must give the reason:\n%s", stderr)
	}
}

// Every failure prints a one-line reason on stderr. Before, each subcommand
// silenced cobra's error printing, so a failure with no report of its own
// exited non-zero with nothing on either stream.
func TestExecute_EveryFailurePrintsReason(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "absent")
	for _, args := range [][]string{
		{"chain", missing},
		{"chain", missing, "--dir"},
		{"chain", runFileIn(filepath.Join(runChainFixtures, "valid"), parityRun1), "--key", "zz"},
		{"receipt", missing},
		{"audit-packet", missing},
		{"evidence", missing},
		{"completeness", missing},
		{"provenance", missing},
		{"aarp", missing},
		{"no-such-subcommand"},
	} {
		stdout, stderr, code := runRoot(t, args...)
		if code == 0 {
			t.Fatalf("%v: exit 0", args)
		}
		if n := strings.Count(stderr, "pipelock-verifier: "); n != 1 {
			t.Fatalf("%v: want exactly one reason line on stderr, got %d\nstdout: %s\nstderr: %s", args, n, stdout, stderr)
		}
	}
}
