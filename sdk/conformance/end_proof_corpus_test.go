// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package conformance_test

// The end-proof corpus is the shared exit and label contract for every chain
// verifier CLI: both Go CLIs and the TypeScript, Python, and Rust verifiers
// run each case in expect.json. Regenerate it with the real emitter:
//
//	go test ./sdk/conformance/ -run TestGenerateEndProofCorpus -update-end-proof

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

var updateEndProof = flag.Bool("update-end-proof", false, "regenerate the end-proof corpus fixtures")

const (
	seedEndProofSigner = "pipelock-end-proof-corpus-signer-v1"
	endProofDir        = "testdata/end-proof"
	endProofPrefix     = "VALID PREFIX, END UNPROVEN"
)

type endProofCase struct {
	Name   string   `json:"name"`
	File   string   `json:"file"`
	Flags  []string `json:"flags"`
	Exit   int      `json:"exit"`
	Status string   `json:"status"`
	Proven bool     `json:"proven"`
}

// endProofRun records one emitter run into dir. A non-empty base mints a
// per-run session; empty records under the legacy shared default session.
func endProofRun(t *testing.T, dir string, priv ed25519.PrivateKey, session string, heartbeat bool, actions int) {
	t.Helper()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	if session == "" {
		session = recorder.DefaultSessionBase
	} else if session, err = recorder.AcquireRunSession(rec, session); err != nil {
		t.Fatal(err)
	}
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: strings.Repeat("c", 64), Principal: "local", Actor: "pipelock", Session: session})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	if heartbeat {
		if err := e.EmitHeartbeat(); err != nil {
			t.Fatal(err)
		}
	}
	for range actions {
		if err := e.Emit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: "allow", Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.EmitSessionClose("graceful_shutdown"); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
}

// readEndProofLines returns the receipt entries of a recorder file. The
// recorder's closing checkpoint is dropped; receipts authenticate themselves,
// and what remains is still a valid recorder prefix.
func readEndProofLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		var entry struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if entry.Type == "action_receipt" {
			lines = append(lines, line)
		}
	}
	return lines
}

// lastReceiptHash is the hash of the final receipt in recorder lines, the
// value an operator would pin with --expect-head.
func lastReceiptHash(t *testing.T, lines []string) string {
	t.Helper()
	var entry struct {
		Detail receipt.Receipt `json:"detail"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatal(err)
	}
	hash, err := receipt.ReceiptHash(entry.Detail)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestGenerateEndProofCorpus(t *testing.T) {
	if !*updateEndProof {
		t.Skip("pass -update-end-proof to regenerate fixtures")
	}
	pub, priv := keyFromSeed(seedEndProofSigner)
	write := func(name string, lines []string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(endProofDir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// A production run: a per-run session, sealed by a signed session_close.
	runDir := t.TempDir()
	endProofRun(t, runDir, priv, recorder.DefaultSessionBase, true, 2)
	files, err := filepath.Glob(filepath.Join(runDir, "evidence-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("run files = %v, %v", files, err)
	}
	closed := readEndProofLines(t, files[0])
	write("closed.jsonl", closed)
	truncated := closed[:len(closed)-1]
	write("truncated.jsonl", truncated)
	write("middle-gap.jsonl", append([]string{closed[0]}, closed[2:]...))

	// A legacy shared session: the restart resumed the same chain after run
	// A's close. The fixture is what remains once run B's file is deleted.
	legacyDir := t.TempDir()
	endProofRun(t, legacyDir, priv, "", false, 1)
	endProofRun(t, legacyDir, priv, "", false, 1)
	legacyFiles, err := filepath.Glob(filepath.Join(legacyDir, "evidence-proxy-*.jsonl"))
	if err != nil || len(legacyFiles) != 2 {
		t.Fatalf("legacy files = %v, %v", legacyFiles, err)
	}
	legacy := readEndProofLines(t, filepath.Join(legacyDir, "evidence-proxy-0.jsonl"))
	write("legacy-close.jsonl", legacy)

	head := lastReceiptHash(t, truncated)
	other := lastReceiptHash(t, closed)
	seq := len(truncated) - 1
	cases := []endProofCase{
		{"truncated", "truncated.jsonl", []string{}, 3, endProofPrefix, false},
		{"allow-prefix", "truncated.jsonl", []string{"--allow-prefix"}, 0, endProofPrefix, false},
		{"closed", "closed.jsonl", []string{}, 0, "CHAIN VALID", true},
		{"middle-gap", "middle-gap.jsonl", []string{}, 1, "CHAIN BROKEN", false},
		{"pin-head-match", "truncated.jsonl", []string{"--expect-head", head}, 0, "CHAIN VALID", true},
		{"pin-head-mismatch", "truncated.jsonl", []string{"--expect-head", other}, 1, "CHAIN BROKEN", false},
		{"pin-seq-match", "truncated.jsonl", []string{"--expect-seq", itoa(seq)}, 0, "CHAIN VALID", true},
		{"pin-seq-mismatch", "truncated.jsonl", []string{"--expect-seq", itoa(seq + 1)}, 1, "CHAIN BROKEN", false},
		{"allow-prefix-invalid", "middle-gap.jsonl", []string{"--allow-prefix"}, 1, "CHAIN BROKEN", false},
		{"pin-mismatch-allow-prefix", "truncated.jsonl", []string{"--expect-head", other, "--allow-prefix"}, 1, "CHAIN BROKEN", false},
		{"legacy-close", "legacy-close.jsonl", []string{}, 3, endProofPrefix, false},
		{"legacy-close-pinned", "legacy-close.jsonl", []string{"--expect-head", lastReceiptHash(t, legacy)}, 0, "CHAIN VALID", true},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(struct {
		Key   string         `json:"key"`
		Cases []endProofCase `json:"cases"`
	}{hex.EncodeToString(pub), cases}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(endProofDir, "expect.json"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestEndProofCorpusShape pins what each fixture is, so a regeneration that
// silently lost the distinction between a per-run and a shared session fails
// here rather than letting every verifier agree on the wrong input.
func TestEndProofCorpusShape(t *testing.T) {
	pub, _ := keyFromSeed(seedEndProofSigner)
	var expect struct{ Key string }
	data, err := os.ReadFile(filepath.Join(endProofDir, "expect.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &expect); err != nil || expect.Key != hex.EncodeToString(pub) {
		t.Fatalf("expect.json key = %q (%v), want the seeded corpus signer", expect.Key, err)
	}
	for file, wantRunScoped := range map[string]bool{"closed.jsonl": true, "truncated.jsonl": true, "legacy-close.jsonl": false} {
		f, err := os.Open(filepath.Clean(filepath.Join(endProofDir, file)))
		if err != nil {
			t.Fatal(err)
		}
		var sessions []string
		var last string
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			var entry struct {
				Detail receipt.Receipt `json:"detail"`
			}
			if err := json.Unmarshal(sc.Bytes(), &entry); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			if c := entry.Detail.ActionRecord.SessionControl; c != nil {
				last = string(c.Kind)
				if c.Open != nil {
					sessions = append(sessions, c.Open.RecorderSession)
				}
			} else {
				last = ""
			}
		}
		_ = f.Close()
		if len(sessions) != 1 {
			t.Fatalf("%s: session_open sessions = %v, want one run", file, sessions)
		}
		if _, ok := receipt.RunSessionBase(sessions[0]); ok != wantRunScoped {
			t.Fatalf("%s: recorder_session %q run-scoped=%v, want %v", file, sessions[0], ok, wantRunScoped)
		}
		if wantClose := file != "truncated.jsonl"; (last == string(receipt.SessionControlClose)) != wantClose {
			t.Fatalf("%s: final control %q, want close=%v", file, last, wantClose)
		}
	}
}
