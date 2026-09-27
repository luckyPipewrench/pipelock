// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// The verifier parity fixtures state one verdict per cell that every Pipelock
// verifier must reach. The TypeScript and Rust verifiers run them in their own
// suites; this runs verify-receipt over the same cells, so a disagreement
// between the Go reference and the fixtures fails here rather than being
// settled by whichever verifier the fixtures were last compared with.
const parityClassesDir = "../../../sdk/conformance/testdata/parity"

type parityFixtureCell struct {
	Mode         string   `json:"mode"`
	Target       string   `json:"target"`
	Keys         []string `json:"keys"`
	Endorsements []string `json:"endorsements"`
	Valid        bool     `json:"valid"`
	Findings     []struct {
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

// parityErrorPhrases names what verify-receipt prints for each error kind the
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
	dst := t.TempDir()
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
		args = []string{"--chain", dir}
	case "session":
		args = []string{"--chain", dir, "--session", c.Target}
	case "file":
		args = []string{filepath.Join(dir, c.Target)}
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
	return args
}

func TestVerifyReceipt_ParityFixtures(t *testing.T) {
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
			out, runErr := runParityVerify(t, parityFixtureArgs(t, dir, c)...)
			code := 0
			if runErr != nil {
				code = cliutil.ExitCodeOf(runErr)
				out += runErr.Error()
			}
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
