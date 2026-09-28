// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// These tests drive verify-receipt over real Go-written evidence: the
// run-chain conformance fixture, two process runs of base "proxy", each with
// an ActionReceipt v1 chain and an EvidenceReceipt v2 chain.
const (
	parityFixtureDir = "../../../sdk/conformance/testdata/run-chains"
	parityRun1       = "proxy.run.03b13ee13e01e7f770480f62ea42f1fe"
	parityRun2       = "proxy.run.f7b327337534352a514bd0a256b1d1c0"
	parityReplayRun  = "proxy.run.00000000000000000000000000000000"
)

func parityKey(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(parityFixtureDir, "signer-key.hex"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func parityFixture(t *testing.T) string {
	t.Helper()
	src := filepath.Join(parityFixtureDir, "valid")
	dst := physicalTempDir(t)
	des, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if de.IsDir() || de.Name() == "expect.json" {
			continue
		}
		data, readErr := os.ReadFile(filepath.Clean(filepath.Join(src, de.Name())))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if writeErr := os.WriteFile(filepath.Join(dst, de.Name()), data, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	return dst
}

// physicalTempDir returns t.TempDir() with symlinks resolved. An evidence root
// may not pass through a symlink, and the system temp directory does on some
// platforms (macOS /var is a symlink to /private/var).
func physicalTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func parityFile(dir, session string) string {
	return filepath.Join(dir, "evidence-"+session+"-0.jsonl")
}

type parityLine struct {
	Version          int             `json:"v"`
	Sequence         uint64          `json:"seq"`
	Timestamp        time.Time       `json:"ts"`
	SessionID        string          `json:"session_id"`
	ChainKind        string          `json:"chain_kind,omitempty"`
	WriterInstanceID string          `json:"writer_instance_id,omitempty"`
	TraceID          string          `json:"trace_id,omitempty"`
	Type             string          `json:"type"`
	EventKind        string          `json:"event_kind,omitempty"`
	Transport        string          `json:"transport"`
	Summary          string          `json:"summary"`
	Detail           json.RawMessage `json:"detail"`
	RawRef           string          `json:"raw_ref,omitempty"`
	PrevHash         string          `json:"prev_hash"`
	Hash             string          `json:"hash"`
}

// parityRewrite edits (or, returning false, drops) each line of path and with
// rehash recomputes the recorder entry hash chain. Recomputing it needs no
// key: it is what an attacker with write access alone can do.
func parityRewrite(t *testing.T, path string, rehash bool, edit func(l *parityLine) bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	prev := recorder.GenesisHash
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var l parityLine
		if err := json.Unmarshal(raw, &l); err != nil {
			t.Fatal(err)
		}
		if !edit(&l) {
			continue
		}
		if rehash {
			l.PrevHash = prev
			l.Hash = recorder.ComputeHash(recorder.Entry{
				Version: l.Version, Sequence: l.Sequence, Timestamp: l.Timestamp, SessionID: l.SessionID,
				ChainKind: l.ChainKind, WriterInstanceID: l.WriterInstanceID, TraceID: l.TraceID,
				Type: l.Type, EventKind: l.EventKind, Transport: l.Transport, Summary: l.Summary,
				RawDetail: l.Detail, RawRef: l.RawRef, PrevHash: prev,
			})
			prev = l.Hash
		}
		b, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(b)
		out.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Clean(path), out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// forgeEvidence edits a signed field of the first EvidenceReceipt v2.
func forgeEvidence() func(l *parityLine) bool {
	done := false
	return func(l *parityLine) bool {
		if !done && l.Type == "evidence_receipt" {
			l.Detail = bytes.Replace(l.Detail, []byte(`"actor":"`), []byte(`"actor":"x`), 1)
			done = true
		}
		return true
	}
}

func runParityVerify(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	cmd := VerifyReceiptCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func copyParityFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(src))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Clean(dst), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyReceipt_ParityContract(t *testing.T) {
	key := parityKey(t)
	type tc struct {
		name    string
		setup   func(t *testing.T, dir string) []string
		wantErr string // empty: must pass
		wantOut []string
		notOut  []string
	}
	cases := []tc{
		{
			name:    "clean directory verifies both chains of every run",
			setup:   func(_ *testing.T, dir string) []string { return []string{"--chain", dir, "--key", key} },
			wantOut: []string{"EVIDENCE CHAIN VALID", "Evidence receipts: 2", "RESTART CONTINUITY OK"},
		},
		{
			name: "directory: forged evidence receipt with rehashed recorder chain",
			setup: func(t *testing.T, dir string) []string {
				parityRewrite(t, parityFile(dir, parityRun2), true, forgeEvidence())
				return []string{"--chain", dir, "--key", key}
			},
			wantErr: "chain verification failed",
			wantOut: []string{"EVIDENCE CHAIN BROKEN", "evidence receipt chain"},
		},
		{
			name: "named run: clean",
			setup: func(_ *testing.T, dir string) []string {
				return []string{"--chain", dir, "--key", key, "--session", parityRun1}
			},
			wantOut: []string{"EVIDENCE CHAIN VALID", "RESTART CONTINUITY OK"},
		},
		{
			name: "named run fails on a finding in another run of its base",
			setup: func(t *testing.T, dir string) []string {
				parityRewrite(t, parityFile(dir, parityRun2), true, forgeEvidence())
				return []string{"--chain", dir, "--key", key, "--session", parityRun1}
			},
			wantErr: "restart continuity",
			wantOut: []string{"RESTART CONTINUITY FAILED", "corrupt_chain: " + parityRun2},
		},
		{
			name:    "file: clean",
			setup:   func(_ *testing.T, dir string) []string { return []string{parityFile(dir, parityRun2), "--key", key} },
			wantOut: []string{"CHAIN VALID", "EVIDENCE CHAIN VALID"},
		},
		{
			name: "file: forged evidence receipt",
			setup: func(t *testing.T, dir string) []string {
				parityRewrite(t, parityFile(dir, parityRun2), true, forgeEvidence())
				return []string{parityFile(dir, parityRun2), "--key", key}
			},
			wantErr: "evidence receipt chain verification failed",
			wantOut: []string{"EVIDENCE CHAIN BROKEN"},
		},
		{
			name: "file: recorder entry hash chain broken, receipts intact",
			setup: func(t *testing.T, dir string) []string {
				parityRewrite(t, parityFile(dir, parityRun2), false, func(l *parityLine) bool {
					if l.Type == "decision" {
						l.Summary += " edited"
					}
					return true
				})
				return []string{parityFile(dir, parityRun2), "--key", key}
			},
			wantErr: "recorder entry hash chain",
		},
		{
			name: "file: entries of another session under this file name",
			setup: func(t *testing.T, dir string) []string {
				copyParityFile(t, parityFile(dir, parityRun1), parityFile(dir, parityReplayRun))
				return []string{parityFile(dir, parityReplayRun), "--key", key}
			},
			wantErr: "does not match requested session",
		},
		{
			name: "file holding only evidence receipts is verified as a v2 chain",
			setup: func(t *testing.T, dir string) []string {
				parityRewrite(t, parityFile(dir, parityRun2), true, func(l *parityLine) bool { return l.Type != "action_receipt" })
				return []string{parityFile(dir, parityRun2), "--key", key}
			},
			wantOut: []string{"EVIDENCE CHAIN VALID", "Evidence receipts: 2"},
			notOut:  []string{"No receipts found"},
		},
		{
			name: "file holding only a forged evidence receipt chain",
			setup: func(t *testing.T, dir string) []string {
				forge := forgeEvidence()
				parityRewrite(t, parityFile(dir, parityRun2), true, func(l *parityLine) bool { return l.Type != "action_receipt" && forge(l) })
				return []string{parityFile(dir, parityRun2), "--key", key}
			},
			wantErr: "evidence receipt chain verification failed",
		},
		{
			name: "directory: replayed run under a new session name",
			setup: func(t *testing.T, dir string) []string {
				copyParityFile(t, parityFile(dir, parityRun1), parityFile(dir, parityReplayRun))
				parityRewrite(t, parityFile(dir, parityReplayRun), true, func(l *parityLine) bool {
					l.SessionID = parityReplayRun
					return true
				})
				return []string{"--chain", dir, "--key", key}
			},
			wantErr: "restart continuity",
			wantOut: []string{"duplicate_run_nonce"},
		},
		{
			name: "whole-recorder file: clean",
			setup: func(_ *testing.T, dir string) []string {
				return []string{parityFile(dir, parityRun2), "--whole-recorder", "--key", key}
			},
			wantOut: []string{"Evidence:  2 evidence receipts verified"},
		},
		{
			name: "whole-recorder file: checkpoint stripped, anchor waived, evidence receipt forged",
			setup: func(t *testing.T, dir string) []string {
				forge := forgeEvidence()
				parityRewrite(t, parityFile(dir, parityRun2), true, func(l *parityLine) bool { return l.Type != "checkpoint" && forge(l) })
				return []string{parityFile(dir, parityRun2), "--whole-recorder", "--allow-unanchored-seal", "--key", key}
			},
			wantErr: "evidence receipt chain verification failed",
			wantOut: []string{"EVIDENCE CHAIN BROKEN"},
		},
		{
			name: "whole-recorder file: checkpoint stripped and waived, receipts honest",
			setup: func(t *testing.T, dir string) []string {
				parityRewrite(t, parityFile(dir, parityRun2), true, func(l *parityLine) bool { return l.Type != "checkpoint" })
				return []string{parityFile(dir, parityRun2), "--whole-recorder", "--allow-unanchored-seal", "--key", key}
			},
			wantOut: []string{"recorder entries other than action and evidence receipts are hash-linked but not authenticated; both receipt chains were signature-verified"},
		},
		{
			name: "clean report refuses a forged evidence receipt",
			setup: func(t *testing.T, dir string) []string {
				parityRewrite(t, parityFile(dir, parityRun2), true, forgeEvidence())
				return []string{"--chain", dir, "--key", key, "--session", parityRun2, "--clean-report", filepath.Join(t.TempDir(), "r.json")}
			},
			wantErr: "evidence receipt chain verification failed",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := parityFixture(t)
			out, err := runParityVerify(t, c.setup(t, dir)...)
			if c.wantErr == "" && err != nil {
				t.Fatalf("want pass, got %v\n%s", err, out)
			}
			if c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
				t.Fatalf("want error containing %q, got %v\n%s", c.wantErr, err, out)
			}
			if c.wantErr != "" && cliutil.ExitCodeOf(err) != cliutil.ExitGeneral {
				t.Fatalf("verification failure must exit 1, got %d", cliutil.ExitCodeOf(err))
			}
			for _, w := range c.wantOut {
				if !strings.Contains(out, w) {
					t.Fatalf("output missing %q:\n%s", w, out)
				}
			}
			for _, n := range c.notOut {
				if strings.Contains(out, n) {
					t.Fatalf("output must not contain %q:\n%s", n, out)
				}
			}
		})
	}
}

func TestVerifyReceipt_SymlinkPolicy(t *testing.T) {
	key := parityKey(t)
	dir := parityFixture(t)
	outside := filepath.Join(t.TempDir(), "run2.jsonl")
	copyParityFile(t, parityFile(dir, parityRun2), outside)
	if err := os.Remove(parityFile(dir, parityRun2)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, parityFile(dir, parityRun2)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// Inside a directory root, a symlinked evidence file is refused: a
	// verification failure (exit 1) that names the file.
	out, err := runParityVerify(t, "--chain", dir, "--key", key)
	if err == nil || !errors.Is(err, recorder.ErrEvidenceRefused) || !strings.Contains(err.Error(), filepath.Base(parityFile(dir, parityRun2))) {
		t.Fatalf("symlink in evidence root: %v\n%s", err, out)
	}
	if code := cliutil.ExitCodeOf(err); code != cliutil.ExitGeneral {
		t.Fatalf("symlink refusal exit = %d, want 1", code)
	}
	// A file the operator names explicitly is read as given.
	if out, err := runParityVerify(t, parityFile(dir, parityRun2), "--key", key); err != nil {
		t.Fatalf("explicit symlinked file: %v\n%s", err, out)
	}
}

func TestVerifyReceipt_ExplicitPathResolvesSymlinkBeforeDotDot(t *testing.T) {
	key := parityKey(t)
	dir := physicalTempDir(t)
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	for _, path := range []string{a, filepath.Join(b, "sub")} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	name := filepath.Base(parityFile("", parityRun1))
	valid, err := os.ReadFile(filepath.Join(parityFixtureDir, "valid", name)) // #nosec G304 -- name comes from a test fixture constant.
	if err != nil {
		t.Fatal(err)
	}
	pathA := filepath.Join(a, name)
	pathB := filepath.Join(b, name)
	link := filepath.Join(a, "link")
	if err := os.Symlink(filepath.Join(b, "sub"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	input := link + string(filepath.Separator) + ".." + string(filepath.Separator) + name
	for _, tc := range []struct {
		name   string
		aData  []byte
		bData  []byte
		wantOK bool
	}{
		{name: "invalid reached target", aData: valid, bData: []byte("not-json\n")},
		{name: "valid reached target", aData: []byte("not-json\n"), bData: valid, wantOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(pathA, tc.aData, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(pathB, tc.bData, 0o600); err != nil {
				t.Fatal(err)
			}
			resolved, err := filepath.EvalSymlinks(input)
			if err != nil || resolved != pathB {
				t.Fatalf("path resolves to %q, want %q: %v", resolved, pathB, err)
			}
			out, err := runParityVerify(t, input, "--key", key)
			if (err == nil) != tc.wantOK {
				t.Fatalf("want valid=%t, got %v\n%s", tc.wantOK, err, out)
			}
		})
	}
}

func TestVerifyReceipt_ConfigErrorsExitTwo(t *testing.T) {
	dir := parityFixture(t)
	for name, args := range map[string][]string{
		"malformed key":         {"--chain", dir, "--key", "zz"},
		"missing directory":     {"--chain", filepath.Join(dir, "absent"), "--key", parityKey(t)},
		"seal without recorder": {"--chain", dir, "--require-seal"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runParityVerify(t, args...)
			if err == nil || cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
				t.Fatalf("want exit 2, got err=%v code=%d", err, cliutil.ExitCodeOf(err))
			}
		})
	}
}

func TestVerifyReceipt_ChainRootSymlinkRefusedAlongWalkedPath(t *testing.T) {
	key := parityKey(t)
	base := physicalTempDir(t)
	realEv := filepath.Join(base, "a", "ev")
	if err := os.MkdirAll(filepath.Dir(realEv), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parityFixture(t), realEv); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "b", "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "b", "ev"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "b", "sub"), filepath.Join(base, "a", "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(realEv, filepath.Join(base, "evlink")); err != nil {
		t.Fatal(err)
	}
	if out, err := runParityVerify(t, "--chain", realEv, "--key", key); err != nil {
		t.Fatalf("positive control: real directory failed: %v\n%s", err, out)
	}
	sep := string(filepath.Separator)
	for name, target := range map[string]string{
		"symlinked root":            filepath.Join(base, "evlink"),
		"symlink hidden by dot-dot": filepath.Join(base, "a", "link") + sep + ".." + sep + "ev",
	} {
		t.Run(name, func(t *testing.T) {
			out, err := runParityVerify(t, "--chain", target, "--key", key)
			if err == nil || !strings.Contains(out+err.Error(), "refuse symlink in evidence root path") {
				t.Fatalf("want refusal, got %v\n%s", err, out)
			}
		})
	}
}

// A symlink the operator names is read at its target, but the recorder file
// is bound to the session the operator's filename claims. A link named for
// one run that points at another run's file is refused in every file mode.
func TestVerifyReceipt_SymlinkNamedForOtherRunRefused(t *testing.T) {
	key := parityKey(t)
	dir := parityFixture(t)
	links := t.TempDir()
	misnamed := filepath.Join(links, filepath.Base(parityFile("", parityRun1)))
	named := filepath.Join(links, filepath.Base(parityFile("", parityRun2)))
	if err := os.Symlink(parityFile(dir, parityRun2), misnamed); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(parityFile(dir, parityRun2), named); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []struct {
		name  string
		extra func(t *testing.T) []string
	}{
		{name: "plain", extra: func(*testing.T) []string { return nil }},
		{name: "clean report", extra: func(t *testing.T) []string {
			return []string{"--clean-report", filepath.Join(t.TempDir(), "report.json")}
		}},
		{name: "whole recorder", extra: func(*testing.T) []string { return []string{"--whole-recorder"} }},
	} {
		t.Run(mode.name, func(t *testing.T) {
			args := append([]string{named, "--key", key}, mode.extra(t)...)
			if out, err := runParityVerify(t, args...); err != nil {
				t.Fatalf("positive control: link named for its target's run failed: %v\n%s", err, out)
			}
			args = append([]string{misnamed, "--key", key}, mode.extra(t)...)
			out, err := runParityVerify(t, args...)
			if err == nil || !errors.Is(err, recorder.ErrEvidenceRefused) || !strings.Contains(err.Error(), parityRun1) {
				t.Fatalf("want refusal naming %s, got %v\n%s", parityRun1, err, out)
			}
			if strings.Contains(out, "VALID") && !strings.Contains(out, "INVALID") {
				t.Fatalf("refused file reported valid:\n%s", out)
			}
		})
	}
}

// A file named as a directory ("receipt.json/", "receipt.json/.") is refused,
// as the operating system refuses to open it and as every verifier refuses it.
func TestVerifyReceipt_FileNamedAsDirectoryRefused(t *testing.T) {
	file := filepath.Join(physicalTempDir(t), "receipt.json")
	copyParityFile(t, filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "valid-single.json"), file)
	if out, err := runParityVerify(t, file, "--allow-unpinned"); err != nil {
		t.Fatalf("positive control: %v\n%s", err, out)
	}
	sep := string(filepath.Separator)
	for _, input := range []string{file + sep, file + sep + "."} {
		out, err := runParityVerify(t, input, "--allow-unpinned")
		if err == nil || cliutil.ExitCodeOf(err) != cliutil.ExitConfig || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("%q: want exit 2 not-a-directory, got %v (code %d)\n%s", input, err, cliutil.ExitCodeOf(err), out)
		}
	}
}
