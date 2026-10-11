// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// Use the real emitter with a historical caller-supplied session, rather
// than shaping the signed open by hand. A close on that shared name is real.
func TestGenerateEndProofSessionCorpus(t *testing.T) {
	if !*updateEndProof {
		t.Skip("pass -update-end-proof")
	}
	_, priv := keyFromSeed(seedEndProofSigner)
	data, err := os.ReadFile(filepath.Join(endProofDir, "expect.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Key   string         `json:"key"`
		Cases []endProofCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, session string
		proven        bool
	}{
		{"run-empty-suffix", "proxy.run.", false},
		{"run-short-suffix", "proxy.run.abc", false},
		{"run-nonhex-suffix", "proxy.run." + strings.Repeat("z", 32), false},
		{"run-upperhex-suffix", "proxy.run." + strings.Repeat("A", 32), false},
		{"run-extra-infix", "proxy.run.x.run." + strings.Repeat("a", 32), false},
		{"run-case-infix", "proxy.RUN." + strings.Repeat("a", 32), false},
		{"run-encoded-infix", "proxy%2erun%2e" + strings.Repeat("a", 32), false},
		{"run-unicode-base", "π.run." + strings.Repeat("a", 32), true},
	} {
		dir := t.TempDir()
		rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
		if err != nil {
			t.Fatal(err)
		}
		e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: strings.Repeat("c", 64), Principal: "local", Actor: "pipelock", Session: tc.session})
		if err := e.EmitSessionOpen(); err != nil {
			t.Fatal(err)
		}
		if err := e.EmitSessionClose("graceful_shutdown"); err != nil {
			t.Fatal(err)
		}
		if err := rec.Close(); err != nil {
			t.Fatal(err)
		}
		files, err := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
		if err != nil || len(files) != 1 {
			t.Fatalf("files=%v: %v", files, err)
		}
		lines := readEndProofLines(t, files[0])
		file := tc.name + ".jsonl"
		if err := os.WriteFile(filepath.Join(endProofDir, file), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, status := 3, endProofPrefix
		if tc.proven {
			code, status = 0, "CHAIN VALID"
		}
		cell := endProofCase{tc.name, file, []string{}, code, status, tc.proven}
		found := false
		for i := range corpus.Cases {
			if corpus.Cases[i].Name == tc.name {
				corpus.Cases[i] = cell
				found = true
			}
		}
		if !found {
			corpus.Cases = append(corpus.Cases, cell)
		}
	}
	data, err = json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(endProofDir, "expect.json"), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
