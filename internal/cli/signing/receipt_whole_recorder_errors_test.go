// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// rewriteRecorderEntries reads a recorder file, applies mutate to the parsed
// entries, re-links and re-hashes the outer chain, and writes the result to a
// new file. The outer chain stays valid so the test reaches the seal and
// receipt checks rather than failing earlier on a hash break.
func rewriteRecorderEntries(t *testing.T, path, name string, mutate func([]recorder.Entry) []recorder.Entry) string {
	t.Helper()
	entries, err := recorder.ReadEntries(path)
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	entries = mutate(entries)
	var seq uint64
	for i := range entries {
		entries[i].Sequence = seq
		seq++
		if i == 0 {
			entries[i].PrevHash = recorder.GenesisHash
		} else {
			entries[i].PrevHash = entries[i-1].Hash
		}
		entries[i].RawDetail = nil
		entries[i].Hash = recorder.ComputeHash(entries[i])
	}
	var rewritten strings.Builder
	for _, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("Marshal entry: %v", err)
		}
		rewritten.Write(data)
		rewritten.WriteByte('\n')
	}
	out := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(out, []byte(rewritten.String()), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return out
}

// relinkRecorderLines edits recorder JSONL lines in place while keeping every
// untouched entry's detail bytes, and therefore its hash, exactly as written.
// mutate receives each line as a map and reports whether it changed the
// detail; the helper then re-hashes changed entries from their new detail
// bytes and re-links every later entry so the outer chain stays valid. Unlike
// rewriteRecorderEntries this preserves earlier checkpoint signatures, which
// sign the chain hash before them.
func relinkRecorderLines(t *testing.T, path, name string, mutate func(i int, line map[string]any) bool) string {
	t.Helper()
	entries, err := recorder.ReadEntries(path)
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != len(entries) {
		t.Fatalf("line count %d != entry count %d", len(lines), len(entries))
	}
	var rewritten strings.Builder
	for i := range entries {
		var line map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &line); err != nil {
			t.Fatalf("Unmarshal line %d: %v", i, err)
		}
		if mutate(i, line) {
			detailJSON, err := json.Marshal(line["detail"])
			if err != nil {
				t.Fatalf("Marshal detail %d: %v", i, err)
			}
			entries[i].RawDetail = detailJSON
			line["detail"] = json.RawMessage(detailJSON)
		} else {
			line["detail"] = entries[i].RawDetail
		}
		if i > 0 {
			entries[i].PrevHash = entries[i-1].Hash
		}
		entries[i].Hash = recorder.ComputeHash(entries[i])
		line["prev_hash"] = entries[i].PrevHash
		line["hash"] = entries[i].Hash
		data, err := json.Marshal(line)
		if err != nil {
			t.Fatalf("Marshal line %d: %v", i, err)
		}
		rewritten.Write(data)
		rewritten.WriteByte('\n')
	}
	out := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(out, []byte(rewritten.String()), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return out
}

func runVerifyReceipt(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := VerifyReceiptCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestVerifyReceiptCmd_WholeRecorderFlagCombinationsRefused(t *testing.T) {
	t.Parallel()

	path, pub := buildSealedRecorderJSONL(t)
	key := hex.EncodeToString(pub)
	singleReceipt := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(singleReceipt, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "clean report", args: []string{path, "--whole-recorder", "--key", key, "--clean-report", filepath.Join(t.TempDir(), "report.json")}, want: "--whole-recorder cannot be combined with --clean-report"},
		{name: "fleet report", args: []string{path, "--whole-recorder", "--fleet-report", "--key", key}, want: "--whole-recorder cannot be combined with --fleet-report"},
		{name: "single receipt json", args: []string{singleReceipt, "--whole-recorder", "--key", key}, want: "--whole-recorder requires a recorder JSONL file or --chain directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runVerifyReceipt(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyReceiptCmd_WholeRecorderInputErrors(t *testing.T) {
	t.Parallel()

	path, pub := buildSealedRecorderJSONL(t)
	key := hex.EncodeToString(pub)

	t.Run("missing file", func(t *testing.T) {
		_, err := runVerifyReceipt(t, filepath.Join(t.TempDir(), "absent.jsonl"), "--whole-recorder", "--key", key)
		if err == nil || !strings.Contains(err.Error(), "reading recorder file") {
			t.Fatalf("err = %v, want reading recorder file", err)
		}
	})

	t.Run("unpinned without allow-unpinned fails closed", func(t *testing.T) {
		out, err := runVerifyReceipt(t, path, "--whole-recorder")
		if err == nil {
			t.Fatalf("unpinned whole-recorder verification must not pass:\n%s", out)
		}
		if strings.Contains(out, "Seal:      sealed at seq") {
			t.Fatalf("unpinned run must not report a seal:\n%s", out)
		}
	})

	t.Run("malformed transcript_root detail", func(t *testing.T) {
		mutated := rewriteRecorderEntries(t, path, "bad-root.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			for i := range entries {
				if entries[i].Type == "transcript_root" {
					entries[i].Detail = "not an object"
				}
			}
			return entries
		})
		out, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", key)
		if err == nil || !strings.Contains(err.Error(), "seal verification failed") || !strings.Contains(out, "SEAL MISMATCH") {
			t.Fatalf("malformed root err=%v output:\n%s", err, out)
		}
	})

	t.Run("transcript_root before any receipt", func(t *testing.T) {
		mutated := rewriteRecorderEntries(t, path, "early-root.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			rootIdx := -1
			for i := range entries {
				if entries[i].Type == "transcript_root" {
					rootIdx = i
				}
			}
			if rootIdx < 0 {
				t.Fatal("fixture has no transcript_root")
			}
			root := entries[rootIdx]
			rest := append([]recorder.Entry{}, entries[:rootIdx]...)
			rest = append(rest, entries[rootIdx+1:]...)
			return append([]recorder.Entry{root}, rest...)
		})
		out, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", key)
		if err == nil || !strings.Contains(err.Error(), "no matching receipt prefix") {
			t.Fatalf("early root err=%v output:\n%s", err, out)
		}
	})

	t.Run("malformed action_receipt detail", func(t *testing.T) {
		mutated := rewriteRecorderEntries(t, path, "bad-receipt.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			for i := range entries {
				if entries[i].Type == "action_receipt" {
					entries[i].Detail = "not a receipt"
					break
				}
			}
			return entries
		})
		_, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", key)
		if err == nil || !strings.Contains(err.Error(), "whole-recorder verification failed") {
			t.Fatalf("malformed receipt err = %v", err)
		}
	})
}

func TestVerifyReceiptCmd_WholeRecorderOperationalEntryAfterSealIncomplete(t *testing.T) {
	t.Parallel()

	path, pub := buildSealedRecorderJSONL(t)
	key := hex.EncodeToString(pub)

	// Positive control: the clean sealed fixture, trailing checkpoint included,
	// verifies before anything is appended.
	if out, err := runVerifyReceipt(t, path, "--whole-recorder", "--key", key); err != nil || !strings.Contains(out, "Seal:      sealed at seq") {
		t.Fatalf("clean sealed fixture err=%v output:\n%s", err, out)
	}

	mutated := rewriteRecorderEntries(t, path, "post-seal-decision.jsonl", func(entries []recorder.Entry) []recorder.Entry {
		last := entries[len(entries)-1]
		appended := recorder.Entry{
			Version: last.Version, Timestamp: last.Timestamp, SessionID: last.SessionID,
			Type: "decision", Transport: "fetch", EventKind: "url", Summary: "appended after the seal",
		}
		return append(entries, appended)
	})
	out, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", key)
	if err == nil || !strings.Contains(err.Error(), "seal precedes later unsealed decision entry") {
		t.Fatalf("post-seal decision err = %v, want incomplete:\n%s", err, out)
	}
	if !strings.Contains(out, "INCOMPLETE: transcript_root seal precedes later unsealed entries (first: decision") || strings.Contains(out, "CHAIN VALID") || strings.Contains(out, "Seal:      sealed at seq") {
		t.Fatalf("post-seal decision must not report a sealed or valid result:\n%s", out)
	}
}

func TestVerifyReceiptCmd_WholeRecorderDirectFileBoundedRead(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "evidence-proxy-0.jsonl")
	file, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	enc := json.NewEncoder(file)
	for seq := range recorder.MaxEvidenceReadEntries + 1 {
		entry := recorder.Entry{
			Version: recorder.EntryVersion, Sequence: uint64(seq), Timestamp: time.Now().UTC(),
			SessionID: "proxy", Type: "checkpoint", Transport: "fetch", Summary: "checkpoint", PrevHash: recorder.GenesisHash,
		}
		entry.Hash = recorder.ComputeHash(entry)
		if err := enc.Encode(entry); err != nil {
			_ = file.Close()
			t.Fatalf("Encode: %v", err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	out, err := runVerifyReceipt(t, path, "--whole-recorder", "--allow-unpinned")
	if !errors.Is(err, recorder.ErrEvidenceReadLimitExceeded) || strings.Contains(out, "CHAIN VALID") {
		t.Fatalf("direct file over the read limit err=%v output:\n%s", err, out)
	}
}

func TestVerifyReceiptCmd_WholeRecorderSignedCheckpointAnchor(t *testing.T) {
	t.Parallel()

	path, pub := buildSealedRecorderJSONLSigned(t, true)
	key := hex.EncodeToString(pub)

	out, err := runVerifyReceipt(t, path, "--whole-recorder", "--key", key)
	if err != nil || !strings.Contains(out, "signed checkpoints verified") {
		t.Fatalf("signed fixture err=%v output:\n%s", err, out)
	}

	tamperDecision := func(entries []recorder.Entry) []recorder.Entry {
		for i := range entries {
			if entries[i].Type == "decision" {
				entries[i].Summary = "rewritten operational decision"
			}
		}
		return entries
	}

	t.Run("rewritten decision breaks the signed anchor", func(t *testing.T) {
		mutated := rewriteRecorderEntries(t, path, "rewritten-signed.jsonl", tamperDecision)
		out, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", key)
		if err == nil || !strings.Contains(err.Error(), "signature verifies against no trusted key") || !strings.Contains(out, "ANCHOR MISMATCH") {
			t.Fatalf("rewritten signed recorder err=%v output:\n%s", err, out)
		}
	})

	t.Run("unsigned checkpoints are refused unless explicitly allowed, and then reported", func(t *testing.T) {
		unsignedPath, unsignedPub := buildSealedRecorderJSONLSigned(t, false)
		mutated := rewriteRecorderEntries(t, unsignedPath, "rewritten-unsigned.jsonl", tamperDecision)
		out, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", hex.EncodeToString(unsignedPub))
		if err == nil || !strings.Contains(err.Error(), "--allow-unanchored-seal") || strings.Contains(out, "Seal:      sealed at seq") {
			t.Fatalf("unsigned recorder must fail closed by default err=%v output:\n%s", err, out)
		}
		out, err = runVerifyReceipt(t, mutated, "--whole-recorder", "--key", hex.EncodeToString(unsignedPub), "--allow-unanchored-seal")
		if err != nil || !strings.Contains(out, "hash-linked but not authenticated") {
			t.Fatalf("unsigned recorder must state its limit when allowed err=%v output:\n%s", err, out)
		}
	})

	t.Run("relabeled trailing entry without a signature is refused on a signed recorder", func(t *testing.T) {
		mutated := rewriteRecorderEntries(t, path, "relabeled-signed.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			last := len(entries) - 1
			if entries[last].Type != "checkpoint" || entries[last-1].Type != "transcript_root" {
				t.Fatal("fixture must end with transcript_root then checkpoint")
			}
			// Replace the trailing checkpoint with a relabeled operational entry
			// whose span is self-consistent but which carries no signature.
			entries[last] = recorder.Entry{
				Version: entries[last].Version, Timestamp: entries[last].Timestamp, SessionID: entries[last].SessionID,
				Type: "checkpoint", Transport: "fetch", EventKind: "url", Summary: "smuggled after the seal",
				Detail: map[string]any{"entry_count": last, "first_seq": 0, "last_seq": last - 1, "signature": ""},
			}
			return entries
		})
		out, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", key)
		if err == nil || strings.Contains(out, "Seal:      sealed at seq") {
			t.Fatalf("relabeled trailing entry err=%v output:\n%s", err, out)
		}
	})

	t.Run("two entries after the seal are refused even when both are checkpoints", func(t *testing.T) {
		mutated := rewriteRecorderEntries(t, path, "double-trailing.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			last := entries[len(entries)-1]
			return append(entries, last)
		})
		out, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", key)
		if err == nil || !strings.Contains(err.Error(), "seal precedes later unsealed checkpoint entry") || strings.Contains(out, "Seal:      sealed at seq") {
			t.Fatalf("double trailing checkpoint err=%v output:\n%s", err, out)
		}
	})

	t.Run("unsigned recorder cannot authenticate a relabeled trailing entry and says so", func(t *testing.T) {
		unsignedPath, unsignedPub := buildSealedRecorderJSONLSigned(t, false)
		mutated := rewriteRecorderEntries(t, unsignedPath, "relabeled-unsigned.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			last := len(entries) - 1
			entries[last] = recorder.Entry{
				Version: entries[last].Version, Timestamp: entries[last].Timestamp, SessionID: entries[last].SessionID,
				Type: "checkpoint", Transport: "fetch", EventKind: "url", Summary: "smuggled after the seal",
				Detail: map[string]any{"entry_count": last, "first_seq": 0, "last_seq": last - 1, "signature": ""},
			}
			return entries
		})
		out, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", hex.EncodeToString(unsignedPub), "--allow-unanchored-seal")
		if err != nil || !strings.Contains(out, "not authenticated") {
			t.Fatalf("unsigned recorder must report the unauthenticated state err=%v output:\n%s", err, out)
		}
	})

	t.Run("checkpoint span that does not count its entries is refused", func(t *testing.T) {
		unsignedPath, unsignedPub := buildSealedRecorderJSONLSigned(t, false)
		mutated := rewriteRecorderEntries(t, unsignedPath, "bad-span.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			last := len(entries) - 1
			entries[last].Detail = map[string]any{"entry_count": 1, "first_seq": 0, "last_seq": last - 1, "signature": ""}
			return entries
		})
		_, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", hex.EncodeToString(unsignedPub))
		if err == nil || !strings.Contains(err.Error(), "does not hold 1 entries") {
			t.Fatalf("bad span err = %v", err)
		}
	})

	t.Run("unpinned run verifies checkpoints against the trust-on-first-use signer", func(t *testing.T) {
		out, err := runVerifyReceipt(t, path, "--whole-recorder", "--allow-unpinned")
		if err != nil || !strings.Contains(out, "UNPINNED") || !strings.Contains(out, "signed checkpoints verified") {
			t.Fatalf("unpinned signed recorder err=%v output:\n%s", err, out)
		}
	})
}

func TestVerifyReceiptCmd_WholeRecorderCheckpointShapeErrors(t *testing.T) {
	t.Parallel()

	signedPath, signedPub := buildSealedRecorderJSONLSigned(t, true)
	unsignedPath, unsignedPub := buildSealedRecorderJSONLSigned(t, false)

	t.Run("signature that is not hex", func(t *testing.T) {
		mutated := rewriteRecorderEntries(t, signedPath, "bad-hex-signature.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			for i := range entries {
				if entries[i].Type == "checkpoint" {
					entries[i].Detail = map[string]any{"entry_count": entries[i-1].Sequence + 1, "first_seq": 0, "last_seq": entries[i-1].Sequence, "signature": "zz"}
				}
			}
			return entries
		})
		_, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", hex.EncodeToString(signedPub))
		if err == nil || !strings.Contains(err.Error(), "decoding signature") {
			t.Fatalf("bad hex signature err = %v", err)
		}
	})

	t.Run("detail that is not an object", func(t *testing.T) {
		mutated := rewriteRecorderEntries(t, unsignedPath, "string-detail.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			for i := range entries {
				if entries[i].Type == "checkpoint" {
					entries[i].Detail = "not a checkpoint"
				}
			}
			return entries
		})
		_, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", hex.EncodeToString(unsignedPub))
		if err == nil || !strings.Contains(err.Error(), "malformed detail") {
			t.Fatalf("string detail err = %v", err)
		}
	})

	t.Run("checkpoint as the first entry", func(t *testing.T) {
		mutated := rewriteRecorderEntries(t, unsignedPath, "checkpoint-first.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			last := entries[len(entries)-1]
			if last.Type != "checkpoint" {
				t.Fatal("fixture does not end with a checkpoint")
			}
			return append([]recorder.Entry{last}, entries[:len(entries)-1]...)
		})
		_, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", hex.EncodeToString(unsignedPub))
		if err == nil || !strings.Contains(err.Error(), "preceding entry is seq 0") {
			t.Fatalf("checkpoint-first err = %v", err)
		}
	})

	t.Run("trusted key that is not hex", func(t *testing.T) {
		out, err := runVerifyReceipt(t, signedPath, "--whole-recorder", "--key", "not-hex")
		if err == nil || strings.Contains(out, "Seal:      sealed at seq") {
			t.Fatalf("bad trusted key err=%v output:\n%s", err, out)
		}
	})
}

func TestVerifyReceiptCmd_WholeRecorderMixedCheckpointSignaturesRefused(t *testing.T) {
	t.Parallel()

	path, pub := buildSealedRecorderJSONLWith(t, true, 1)
	key := hex.EncodeToString(pub)
	out, err := runVerifyReceipt(t, path, "--whole-recorder", "--key", key)
	if err != nil || !strings.Contains(out, "signed checkpoints verified") {
		t.Fatalf("multi-checkpoint fixture err=%v output:\n%s", err, out)
	}
	entries, err := recorder.ReadEntries(path)
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	var checkpoints []int
	for i := range entries {
		if entries[i].Type == "checkpoint" {
			checkpoints = append(checkpoints, i)
		}
	}
	if len(checkpoints) < 2 {
		t.Fatalf("fixture has %d checkpoints, want at least 2", len(checkpoints))
	}

	// A relink that changes nothing must still verify: proves the helper
	// preserves hashes and signatures rather than the test passing by accident.
	untouched := relinkRecorderLines(t, path, "untouched.jsonl", func(int, map[string]any) bool { return false })
	if out, err := runVerifyReceipt(t, untouched, "--whole-recorder", "--key", key); err != nil {
		t.Fatalf("relinked untouched fixture err=%v output:\n%s", err, out)
	}

	strip := func(target int) func(int, map[string]any) bool {
		return func(i int, line map[string]any) bool {
			if i != target {
				return false
			}
			detail, ok := line["detail"].(map[string]any)
			if !ok {
				t.Fatalf("checkpoint detail is %T", line["detail"])
			}
			detail["signature"] = ""
			line["detail"] = detail
			return true
		}
	}
	for _, tc := range []struct {
		name   string
		target int
		want   string
	}{
		{"last checkpoint stripped", checkpoints[len(checkpoints)-1], "is unsigned while earlier checkpoints in this session are signed"},
		{"first checkpoint stripped", checkpoints[0], "is signed while earlier checkpoints in this session are unsigned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := relinkRecorderLines(t, path, "mixed.jsonl", strip(tc.target))
			out, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", key)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(out, "Seal:      sealed at seq") {
				t.Fatalf("mixed signatures err=%v output:\n%s", err, out)
			}
		})
	}
}

func TestVerifyReceiptCmd_WholeRecorderCheckpointSpanAndTailEdges(t *testing.T) {
	t.Parallel()

	signedPath, signedPub := buildSealedRecorderJSONLWith(t, true, 1)
	signedKey := hex.EncodeToString(signedPub)
	unsignedPath, unsignedPub := buildSealedRecorderJSONLSigned(t, false)
	unsignedKey := hex.EncodeToString(unsignedPub)

	t.Run("span that reaches back inside the previous checkpoint", func(t *testing.T) {
		entries, err := recorder.ReadEntries(signedPath)
		if err != nil {
			t.Fatalf("ReadEntries: %v", err)
		}
		second := -1
		for i := range entries {
			if entries[i].Type == "checkpoint" {
				if second >= 0 {
					second = i
					break
				}
				second = i
			}
		}
		mutated := relinkRecorderLines(t, signedPath, "overlap.jsonl", func(i int, line map[string]any) bool {
			if i != second {
				return false
			}
			detail := line["detail"].(map[string]any)
			detail["first_seq"] = 0
			detail["entry_count"] = second
			line["detail"] = detail
			return true
		})
		_, err = runVerifyReceipt(t, mutated, "--whole-recorder", "--key", signedKey)
		if err == nil || !strings.Contains(err.Error(), "inside the previous checkpoint") {
			t.Fatalf("overlapping span err = %v", err)
		}
	})

	t.Run("span that ends before the preceding entry", func(t *testing.T) {
		mutated := relinkRecorderLines(t, unsignedPath, "short-span.jsonl", func(i int, line map[string]any) bool {
			if line["type"] != "checkpoint" {
				return false
			}
			detail := line["detail"].(map[string]any)
			detail["last_seq"] = i - 2
			line["detail"] = detail
			return true
		})
		_, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", unsignedKey)
		if err == nil || !strings.Contains(err.Error(), "span ends at seq") {
			t.Fatalf("short span err = %v", err)
		}
	})

	t.Run("operational entry directly after the seal", func(t *testing.T) {
		mutated := rewriteRecorderEntries(t, unsignedPath, "decision-first.jsonl", func(entries []recorder.Entry) []recorder.Entry {
			last := entries[len(entries)-1]
			entries[len(entries)-1] = recorder.Entry{
				Version: last.Version, Timestamp: last.Timestamp, SessionID: last.SessionID,
				Type: "decision", Transport: "fetch", EventKind: "url", Summary: "replaced the trailing checkpoint",
			}
			return entries
		})
		_, err := runVerifyReceipt(t, mutated, "--whole-recorder", "--key", unsignedKey)
		if err == nil || !strings.Contains(err.Error(), "seal precedes later unsealed decision entry") {
			t.Fatalf("decision after seal err = %v", err)
		}
	})
}

func TestVerifyReceiptCmd_WholeRecorderSealMustBeCoveredBySignedCheckpoint(t *testing.T) {
	t.Parallel()

	path, pub := buildSealedRecorderJSONLWith(t, true, 1)
	key := hex.EncodeToString(pub)
	entries, err := recorder.ReadEntries(path)
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	last := len(entries) - 1
	if entries[last].Type != "checkpoint" || entries[last-1].Type != "transcript_root" {
		t.Fatal("fixture must end with transcript_root then checkpoint")
	}

	// Drop the trailing checkpoint and relink: an earlier signed checkpoint
	// still verifies, but nothing signed covers the seal any more.
	truncated := filepath.Join(t.TempDir(), "no-trailing-checkpoint.jsonl")
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if err := os.WriteFile(truncated, []byte(strings.Join(lines[:last], "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out, err := runVerifyReceipt(t, truncated, "--whole-recorder", "--key", key)
	if err == nil || !strings.Contains(err.Error(), "no signed checkpoint covers the transcript_root seal") || strings.Contains(out, "Seal:      sealed at seq") {
		t.Fatalf("seal without a covering checkpoint must be refused err=%v output:\n%s", err, out)
	}
	out, err = runVerifyReceipt(t, truncated, "--whole-recorder", "--key", key, "--allow-unanchored-seal")
	if err != nil || !strings.Contains(out, "none after the seal (accepted by --allow-unanchored-seal)") {
		t.Fatalf("explicitly accepted unanchored seal err=%v output:\n%s", err, out)
	}

	// Positive control: the untouched fixture is covered and says so.
	out, err = runVerifyReceipt(t, path, "--whole-recorder", "--key", key)
	if err != nil || !strings.Contains(out, "every entry through the seal is committed by a trusted key") {
		t.Fatalf("covered seal err=%v output:\n%s", err, out)
	}
}
