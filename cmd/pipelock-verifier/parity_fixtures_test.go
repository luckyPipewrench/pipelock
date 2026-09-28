// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The verifier parity fixtures state one verdict per cell that every Pipelock
// verifier must reach. The TypeScript and Rust verifiers run them in their own
// suites; this runs pipelock-verifier over the same cells, so a disagreement
// between the Go reference and the fixtures fails here rather than being
// settled by whichever verifier the fixtures were last compared with.
const parityClassesDir = "../../sdk/conformance/testdata/parity"

type parityFixtureCell struct {
	Mode         string   `json:"mode"`
	Target       string   `json:"target"`
	Keys         []string `json:"keys"`
	Endorsements []string `json:"endorsements"`
	// AllowUnpinned runs the cell with no key and --allow-unpinned.
	AllowUnpinned bool `json:"allow_unpinned"`
	Valid         bool `json:"valid"`
	Findings      []struct {
		Kind    string `json:"kind"`
		Session string `json:"session"`
	} `json:"findings"`
	Errors []struct {
		Kind string `json:"kind"`
	} `json:"errors"`
}

type parityFixtureExpect struct {
	Symlinks []struct {
		Name   string `json:"name"`
		Target string `json:"target"`
	} `json:"symlinks"`
	Cells []parityFixtureCell `json:"cells"`
}

// parityErrorPhrases names what pipelock-verifier prints for each error kind the
// fixtures use. The Go reference words a broken recorder hash chain in file
// mode as "recorder entry hash chain"; the verdict is the contract, the
// wording is each verifier's own.
var parityErrorPhrases = map[string][]string{
	"outer_chain_broken":     {"outer_chain_broken", "recorder entry hash chain"},
	"action_receipt_chain":   {"CHAIN BROKEN", "action receipt chain", "chain verification failed"},
	"evidence_receipt_chain": {"evidence receipt chain"},
	"session_mismatch":       {"does not match requested session"},
	"symlink_refused":        {"refuse symlink"},
}

// parityNamesAReason reports whether a failing run names at least one of the
// cell's expected findings (kind and session) or errors. The verdict is held
// exactly; the reason only has to be one of the expected ones, because the Go
// reference stops at its first failure where the other verifiers list every
// failing chain, and a directory holding a symlinked evidence file is refused
// before any base finding is computed.
func parityNamesAReason(out string, c parityFixtureCell) bool {
	for _, f := range c.Findings {
		named := strings.Contains(out, f.Kind) || strings.Contains(out, "evidence refused")
		if named && strings.Contains(out, f.Session) {
			return true
		}
	}
	for _, e := range c.Errors {
		for _, p := range parityErrorPhrases[e.Kind] {
			if strings.Contains(out, p) {
				return true
			}
		}
	}
	return false
}

// copyParityClass copies one class directory, including subdirectories, and
// creates the symlinks its expect.json names. The repository holds no links.
func copyParityClass(t *testing.T, src string, exp parityFixtureExpect) string {
	t.Helper()
	dst := physicalTempDir(t)
	// The fixture tree holds no symlinks; CopyFS reads it through a rooted fs.FS.
	err := os.CopyFS(dst, os.DirFS(src))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range exp.Symlinks {
		if err := os.Symlink(filepath.Join(dst, l.Target), filepath.Join(dst, l.Name)); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func parityFixtureArgs(t *testing.T, dir string, c parityFixtureCell) []string {
	t.Helper()
	var args []string
	switch c.Mode {
	case "dir":
		args = []string{"chain", dir, "--dir"}
	case "session":
		args = []string{"chain", dir, "--dir", "--session", c.Target}
	case "file":
		args = []string{"chain", filepath.Join(dir, c.Target)}
	default:
		t.Fatalf("unknown mode %q", c.Mode)
	}
	for _, k := range c.Keys {
		b, err := os.ReadFile(filepath.Clean(filepath.Join(dir, k)))
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, "--key", strings.TrimSpace(string(b)))
	}
	for _, e := range c.Endorsements {
		args = append(args, "--rotation-endorsement", filepath.Join(dir, e))
	}
	if c.AllowUnpinned {
		args = append(args, "--allow-unpinned")
	}
	return args
}

func TestChain_ParityFixtures(t *testing.T) {
	des, err := os.ReadDir(parityClassesDir)
	if err != nil {
		t.Fatal(err)
	}
	classes, cells := 0, 0
	for _, de := range des {
		if !de.IsDir() {
			continue
		}
		classes++
		src := filepath.Join(parityClassesDir, de.Name())
		raw, readErr := os.ReadFile(filepath.Clean(filepath.Join(src, "expect.json")))
		if readErr != nil {
			t.Fatal(readErr)
		}
		var exp parityFixtureExpect
		if jsonErr := json.Unmarshal(raw, &exp); jsonErr != nil {
			t.Fatalf("%s: %v", de.Name(), jsonErr)
		}
		dir := copyParityClass(t, src, exp)
		for _, c := range exp.Cells {
			cells++
			label := de.Name() + " " + c.Mode + " " + c.Target
			stdout, stderr, code := runRoot(t, parityFixtureArgs(t, dir, c)...)
			out := stdout + stderr
			want := 0
			if !c.Valid {
				want = 1
			}
			if code != want {
				t.Errorf("%s: exit %d, want %d\n%s", label, code, want, out)
				continue
			}
			if !c.Valid && !parityNamesAReason(out, c) {
				t.Errorf("%s: failure names none of its expected findings or errors\n%s", label, out)
			}
			for _, e := range c.Errors {
				if _, known := parityErrorPhrases[e.Kind]; !known {
					t.Fatalf("%s: unknown error kind %q", label, e.Kind)
				}
			}
		}
	}
	// Guard against a fixture path that silently matches nothing.
	if classes < 15 || cells < 60 {
		t.Fatalf("ran %d classes and %d cells, want the full parity fixture set", classes, cells)
	}
}

// parityEvidenceReceipt writes the index-th EvidenceReceipt v2 of run B in a
// parity class to its own file, as a single receipt an operator might hold.
func parityEvidenceReceipt(t *testing.T, class string, index int) string {
	t.Helper()
	path := filepath.Join(parityClassesDir, class, "evidence-proxy.run.f7b327337534352a514bd0a256b1d1c0-0.jsonl")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var receipts []json.RawMessage
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var entry struct {
			Type   string          `json:"type"`
			Detail json.RawMessage `json:"detail"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if entry.Type == "evidence_receipt" {
			receipts = append(receipts, entry.Detail)
		}
	}
	if index < 0 {
		index += len(receipts)
	}
	if index < 0 || index >= len(receipts) {
		t.Fatalf("%s holds %d evidence receipts, want index %d", class, len(receipts), index)
	}
	out := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(out, receipts[index], 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

// With no pinned key a v2 receipt's signature is still checked against its
// declared signer, so a receipt edited after signing fails under
// --allow-unpinned instead of being reported self-consistent.
func TestReceipt_UnpinnedEvidenceReceiptSignatureIsChecked(t *testing.T) {
	honest := parityEvidenceReceipt(t, "v2-drop-rehash", 0)
	if stdout, stderr, code := runRoot(t, "receipt", honest, "--allow-unpinned"); code != 0 || !strings.Contains(stdout+stderr, "UNPINNED") {
		t.Fatalf("positive control: exit %d, want 0 and an unpinned report\n%s%s", code, stdout, stderr)
	}
	forged := parityEvidenceReceipt(t, "v2-forge-rehash", -1)
	stdout, stderr, code := runRoot(t, "receipt", forged, "--allow-unpinned")
	if code != 1 || !strings.Contains(stdout+stderr, "signature against declared signer") {
		t.Fatalf("forged receipt: exit %d, want 1 naming the signature\n%s%s", code, stdout, stderr)
	}
}
