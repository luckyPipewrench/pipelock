// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// mixedRunSession is the run in the run-chain fixtures whose action chain the
// tampered-predecessor variant forges. Its evidence file holds both an
// ActionReceipt v1 chain and an EvidenceReceipt v2 chain, as every current
// run does.
const mixedRunSession = "proxy.run.03b13ee13e01e7f770480f62ea42f1fe"

func mixedRunFile(dir string) string {
	return filepath.Join(dir, "evidence-"+mixedRunSession+"-0.jsonl")
}

func copyFixtureDir(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join(runChainFixtures, name)
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Clean(filepath.Join(src, e.Name())))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// v2TamperedDir copies the valid fixture and edits one field of the run's last
// EvidenceReceipt v2, leaving its action chain untouched.
func v2TamperedDir(t *testing.T) string {
	t.Helper()
	dir := copyFixtureDir(t, "valid")
	path := mixedRunFile(dir)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(data, []byte("\n"))
	last := -1
	for i, l := range lines {
		if bytes.Contains(l, []byte(`"type":"evidence_receipt"`)) {
			last = i
		}
	}
	if last < 0 || bytes.Count(lines[last], []byte(`"actor":"pipelock"`)) != 1 {
		t.Fatalf("fixture no longer has exactly one actor field in its last evidence receipt")
	}
	lines[last] = bytes.Replace(lines[last], []byte(`"actor":"pipelock"`), []byte(`"actor":"pipelocx"`), 1)
	if err := os.WriteFile(path, bytes.Join(lines, []byte("\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	rehashRecorderFile(t, path)
	return dir
}

// rehashRecorderFile recomputes the recorder entry hash chain of path,
// keeping every detail byte. It needs no signing key, which is why a receipt
// forged this way must still fail on its own signature.
func rehashRecorderFile(t *testing.T, path string) {
	t.Helper()
	type line struct {
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
		var l line
		if err := json.Unmarshal(raw, &l); err != nil {
			t.Fatal(err)
		}
		l.PrevHash = prev
		l.Hash = recorder.ComputeHash(recorder.Entry{
			Version: l.Version, Sequence: l.Sequence, Timestamp: l.Timestamp, SessionID: l.SessionID,
			ChainKind: l.ChainKind, WriterInstanceID: l.WriterInstanceID, TraceID: l.TraceID,
			Type: l.Type, EventKind: l.EventKind, Transport: l.Transport, Summary: l.Summary,
			RawDetail: l.Detail, RawRef: l.RawRef, PrevHash: prev,
		})
		prev = l.Hash
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

// rehashedFixtureDir copies a fixture and recomputes the named run's recorder
// hash chain, so a forged receipt in it is caught by its signature and not by
// the hash chain a keyless attacker can repair.
func rehashedFixtureDir(t *testing.T, name string) string {
	t.Helper()
	dir := copyFixtureDir(t, name)
	rehashRecorderFile(t, mixedRunFile(dir))
	return dir
}

// A session that holds both receipt chains is valid only when both verify, in
// every mode that reads one session: explicit --session, a single file, and
// each run's line in directory mode.
func TestChain_MixedSessionVerifiesBothChains(t *testing.T) {
	t.Parallel()
	key := readRunChainFixture(t, "signer-key.hex")
	dirs := map[string]string{
		"valid":     filepath.Join(runChainFixtures, "valid"),
		"v1-forged": rehashedFixtureDir(t, "tampered-predecessor"),
		"v2-forged": v2TamperedDir(t),
	}
	wantErr := map[string]string{
		"valid":     "",
		"v1-forged": "action receipt chain: ",
		"v2-forged": "evidence receipt chain: ",
	}
	modes := map[string]func(dir string) []string{
		"explicit-session": func(dir string) []string {
			return []string{"chain", dir, "--dir", "--session", mixedRunSession}
		},
		"file": func(dir string) []string {
			return []string{"chain", mixedRunFile(dir)}
		},
	}
	for name, dir := range dirs {
		for mode, args := range modes {
			t.Run(name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				stdout, stderr, code := runRoot(t, append(args(dir), "--key", key, "--json")...)
				var got chainReport
				if err := json.Unmarshal([]byte(stdout), &got); err != nil {
					t.Fatalf("decode: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
				}
				if wantErr[name] == "" {
					if code != 0 || !got.Valid || got.RecordType != recordTypeEvidenceV2 || got.Error != "" {
						t.Fatalf("exit %d valid=%v record_type=%q error=%q, want a clean v2 report", code, got.Valid, got.RecordType, got.Error)
					}
					return
				}
				if code != 1 || got.Valid {
					t.Fatalf("exit %d valid=%v, want exit 1 invalid", code, got.Valid)
				}
				if !strings.HasPrefix(got.Error, wantErr[name]) {
					t.Fatalf("error %q, want it to name the failing chain with %q", got.Error, wantErr[name])
				}
			})
		}
		t.Run(name+"/directory", func(t *testing.T) {
			t.Parallel()
			stdout, _, code := runRoot(t, "chain", dir, "--dir", "--key", key, "--json")
			var got chainSetReport
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatalf("decode: %v\n%s", err, stdout)
			}
			var line *chainSetEntry
			for i := range got.Chains {
				if got.Chains[i].Session == mixedRunSession {
					line = &got.Chains[i]
				}
			}
			if line == nil {
				t.Fatalf("no line for %s", mixedRunSession)
			}
			if wantErr[name] == "" {
				if code != 0 || !line.Valid {
					t.Fatalf("exit %d line valid=%v error=%q, want valid", code, line.Valid, line.Error)
				}
				return
			}
			if code != 1 || line.Valid || got.Valid {
				t.Fatalf("exit %d line valid=%v set valid=%v, want both invalid", code, line.Valid, got.Valid)
			}
		})
	}
}

// Without a key both chains fail only for being unpinned. The report must
// read exactly as it does for a v2-only session rather than listing the
// banner twice.
func TestChain_MixedSessionUnpinnedReportsOnce(t *testing.T) {
	t.Parallel()
	stdout, _, code := runRoot(t, "chain", mixedRunFile(filepath.Join(runChainFixtures, "valid")), "--json")
	var got chainReport
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if code != 1 || got.Valid || got.Error != unpinnedReceiptBanner {
		t.Fatalf("exit %d valid=%v error=%q, want the unpinned banner alone", code, got.Valid, got.Error)
	}
	_, _, code = runRoot(t, "chain", mixedRunFile(filepath.Join(runChainFixtures, "valid")), "--allow-unpinned")
	if code != 0 {
		t.Fatalf("--allow-unpinned exit %d, want 0", code)
	}
}

// Session membership is parsed equality. For session S the name
// evidence-S-evil-0.jsonl belongs to session S-evil, so it must not be read
// into S's chain even though it starts with "evidence-S-".
func TestChain_ExplicitSessionIgnoresPrefixSibling(t *testing.T) {
	t.Parallel()
	key := readRunChainFixture(t, "signer-key.hex")
	dir := t.TempDir()
	clean, err := os.ReadFile(filepath.Clean(mixedRunFile(filepath.Join(runChainFixtures, "valid"))))
	if err != nil {
		t.Fatal(err)
	}
	forged, err := os.ReadFile(filepath.Clean(mixedRunFile(filepath.Join(runChainFixtures, "tampered-predecessor"))))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mixedRunFile(dir), clean, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runRoot(t, "chain", dir, "--dir", "--session", mixedRunSession, "--key", key)
	if code != 0 {
		t.Fatalf("positive control: exit %d\n%s%s", code, stdout, stderr)
	}
	sibling := filepath.Join(dir, "evidence-"+mixedRunSession+"-evil-0.jsonl")
	if err := os.WriteFile(sibling, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	// The sibling is a chain of the same base, so the named run's own chain
	// still verifies clean, and the verdict fails on the base finding the
	// sibling raises: its entries belong to another session.
	stdout, stderr, code = runRoot(t, "chain", dir, "--dir", "--session", mixedRunSession, "--key", key, "--json")
	var got chainReport
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("decode: %v\n%s%s", err, stdout, stderr)
	}
	sibSession := mixedRunSession + "-evil"
	if code != 1 || got.Valid || !strings.HasPrefix(got.Error, "restart continuity: ") || !strings.Contains(got.Error, sibSession) {
		t.Fatalf("exit %d valid=%v error=%q: want the named run clean and the base finding on %s", code, got.Valid, got.Error, sibSession)
	}
}
