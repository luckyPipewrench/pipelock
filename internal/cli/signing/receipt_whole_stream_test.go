// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// The streaming whole-recorder verifier must reach exactly the verdict the
// in-memory verifier reached, with the same output and the same error, on
// every recorder. These tests run both over the conformance corpus, over
// recorders the emitter writes, and over every single-entry mutation of them
// that the attacks below describe.

const conformanceTestdata = "../../../sdk/conformance/testdata"

// parityVerdict is one implementation's complete observable result.
type parityVerdict struct {
	out      string
	err      string
	unsealed bool
}

func verdictOf(out *bytes.Buffer, err error) parityVerdict {
	v := parityVerdict{out: out.String()}
	if err != nil {
		v.err = err.Error()
		v.unsealed = errors.Is(err, errUnsealedRecorder)
	}
	return v
}

// wholeParityCase is one recorder input with one set of verifier options.
type wholeParityCase struct {
	name string
	dir  string
	keys []string
	opts verifyReceiptOptions
}

// compareWholeRecorder runs the streaming and the in-memory verifier over
// every session directory and every recorder file in c.dir and fails on any
// difference. It returns each verdict's error text so a caller can check the
// matrix reached the failures it was built to reach.
func compareWholeRecorder(t *testing.T, c wholeParityCase) []string {
	t.Helper()
	var verdicts []string
	location, locErr := recorder.ResolveEvidenceLocation(c.dir, "")
	sessions, listErr := recorder.ListSessions(c.dir)
	if locErr == nil && listErr == nil {
		for _, session := range sessions {
			opts := c.opts
			opts.SessionID = session
			var gotOut, wantOut bytes.Buffer
			got := verdictOf(&gotOut, verifyWholeRecorderFromResolvedSessionDir(&gotOut, location, session, c.keys, opts))
			want := verdictOf(&wantOut, legacyVerifyWholeRecorderFromResolvedSessionDir(&wantOut, location, session, c.keys, opts))
			if got != want {
				t.Fatalf("%s: session %s: streaming verdict differs\nstreaming: %+v\nin-memory: %+v", c.name, session, got, want)
			}
			verdicts = append(verdicts, got.err)
		}
	}
	files, err := filepath.Glob(filepath.Join(c.dir, "evidence-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		name := filepath.Base(path)
		var gotOut, wantOut bytes.Buffer
		got := verdictOf(&gotOut, verifyWholeRecorderFromFile(&gotOut, name, path, c.keys, c.opts))
		want := verdictOf(&wantOut, legacyVerifyWholeRecorderFromFile(&wantOut, name, path, c.keys, c.opts))
		if got != want {
			t.Fatalf("%s: file %s: streaming verdict differs\nstreaming: %+v\nin-memory: %+v", c.name, name, got, want)
		}
		verdicts = append(verdicts, got.err)
	}
	return verdicts
}

// recorderLineOp edits the JSONL lines of one recorder file.
type recorderLineOp struct {
	name   string
	rehash bool
	apply  func(lines []string) []string
}

// lineMutations returns the attacks applied at entry i: dropping it (a broken
// link), duplicating it (a fork), editing its detail (a tampered entry),
// swapping it with the next, and cutting the recorder there (a truncated
// tail). Each edit is tried with the outer hash chain left broken and, where
// an attacker could redo it, recomputed.
func lineMutations(i int) []recorderLineOp {
	drop := func(lines []string) []string {
		return append(append([]string(nil), lines[:i]...), lines[i+1:]...)
	}
	dup := func(lines []string) []string {
		out := append([]string(nil), lines[:i+1]...)
		out = append(out, lines[i])
		return append(out, lines[i+1:]...)
	}
	tamper := func(lines []string) []string {
		out := append([]string(nil), lines...)
		out[i] = tamperDetail(out[i])
		return out
	}
	swap := func(lines []string) []string {
		out := append([]string(nil), lines...)
		if i+1 < len(out) {
			out[i], out[i+1] = out[i+1], out[i]
		}
		return out
	}
	cut := func(lines []string) []string { return append([]string(nil), lines[:i]...) }
	return []recorderLineOp{
		{name: fmt.Sprintf("drop-%d", i), apply: drop},
		{name: fmt.Sprintf("drop-%d-rehash", i), rehash: true, apply: drop},
		{name: fmt.Sprintf("dup-%d-rehash", i), rehash: true, apply: dup},
		{name: fmt.Sprintf("tamper-%d", i), apply: tamper},
		{name: fmt.Sprintf("tamper-%d-rehash", i), rehash: true, apply: tamper},
		{name: fmt.Sprintf("swap-%d-rehash", i), rehash: true, apply: swap},
		{name: fmt.Sprintf("cut-%d", i), apply: cut},
	}
}

// tamperDetail changes one value inside an entry's detail without touching
// its stored hash.
func tamperDetail(line string) string {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		return line
	}
	detail := string(fields["detail"])
	switch {
	case strings.Contains(detail, `"allow"`):
		detail = strings.Replace(detail, `"allow"`, `"block"`, 1)
	case strings.Contains(detail, `"final_seq":`):
		detail = strings.Replace(detail, `"final_seq":`, `"final_seq":1`, 1)
	case strings.Contains(detail, `"signature":"`):
		detail = strings.Replace(detail, `"signature":"`, `"signature":"00`, 1)
	default:
		detail = strings.Replace(detail, `{`, `{"tampered":true,`, 1)
	}
	fields["detail"] = json.RawMessage(detail)
	out, err := json.Marshal(fields)
	if err != nil {
		return line
	}
	return string(out)
}

// relinkLines recomputes the outer recorder hash chain over lines, keeping
// every entry's detail bytes, the way anyone with write access alone can.
// Lines that do not parse are kept as they are.
func relinkLines(lines []string) []string {
	out := make([]string, len(lines))
	prev := recorder.GenesisHash
	for i, line := range lines {
		entry, err := recorder.ParseEntryLine([]byte(line))
		var fields map[string]json.RawMessage
		if err != nil || json.Unmarshal([]byte(line), &fields) != nil {
			out[i] = line
			continue
		}
		entry.PrevHash = prev
		entry.Hash = recorder.ComputeHash(entry)
		prev = entry.Hash
		fields["prev_hash"], _ = json.Marshal(entry.PrevHash)
		fields["hash"], _ = json.Marshal(entry.Hash)
		data, err := json.Marshal(fields)
		if err != nil {
			out[i] = line
			continue
		}
		out[i] = string(data)
	}
	return out
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

// copyRecorderDir copies every regular file of src into a fresh directory.
func copyRecorderDir(t *testing.T, src string) string {
	t.Helper()
	dst := physicalTempDir(t)
	des, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if !de.Type().IsRegular() {
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

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	data := strings.Join(lines, "\n")
	if len(lines) > 0 {
		data += "\n"
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// recorderSource is one directory of recorder files and the trust inputs
// worth trying on it.
type recorderSource struct {
	name         string
	dir          string
	keys         [][]string
	endorsements []receipt.RotationEndorsement
}

func readKeyFile(t *testing.T, path string) (string, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

// conformanceRecorderSources lists every corpus directory holding recorder
// shards, with the signer keys and endorsements the corpus ships beside it.
func conformanceRecorderSources(t *testing.T) []recorderSource {
	t.Helper()
	var sources []recorderSource
	err := filepath.WalkDir(conformanceTestdata, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || !d.IsDir() {
			return walkErr
		}
		shards, _ := filepath.Glob(filepath.Join(path, "evidence-*.jsonl"))
		if len(shards) == 0 {
			return nil
		}
		src := recorderSource{name: strings.TrimPrefix(path, conformanceTestdata+"/"), dir: path, keys: [][]string{nil}}
		var keys []string
		for _, dir := range []string{path, filepath.Dir(path), filepath.Dir(filepath.Dir(path))} {
			for _, name := range []string{"signer-key.hex", "rotated-signer-key.hex", "signer.pub"} {
				if k, ok := readKeyFile(t, filepath.Join(dir, name)); ok && !containsString(keys, k) {
					keys = append(keys, k)
				}
			}
		}
		for _, k := range keys {
			src.keys = append(src.keys, []string{k})
		}
		if len(keys) > 1 {
			src.keys = append(src.keys, keys)
		}
		endorsementFiles, _ := filepath.Glob(filepath.Join(path, "*endorsement*.json"))
		for _, f := range endorsementFiles {
			if e, loadErr := receipt.LoadRotationEndorsementFile(f); loadErr == nil {
				src.endorsements = append(src.endorsements, e)
			}
		}
		sources = append(sources, src)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) < 20 {
		t.Fatalf("conformance corpus yielded %d recorder directories; the parity matrix would be too thin", len(sources))
	}
	return sources
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// emitterRecorderSources builds recorders through the real recorder and
// emitter: one signing key with signed and with unsigned checkpoints, and an
// endorsed key rotation, each sealed by a transcript root.
func emitterRecorderSources(t *testing.T) []recorderSource {
	t.Helper()
	var sources []recorderSource
	for _, signed := range []bool{true, false} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		dir := physicalTempDir(t)
		emitIntoSigned(t, dir, priv, 5, 0, signed)
		appendTranscriptRootSigned(t, dir, priv, signed)
		sources = append(sources, recorderSource{
			name: fmt.Sprintf("emitter-single-key-signed-%v", signed),
			dir:  dir,
			keys: [][]string{nil, {hex.EncodeToString(pub)}},
		})
	}
	dir, pubA, privB, endorsementPath := buildEndorsedRotatedChainJSONL(t)
	appendTranscriptRoot(t, dir, privB)
	endorsement, err := receipt.LoadRotationEndorsementFile(endorsementPath)
	if err != nil {
		t.Fatal(err)
	}
	pubB := privB.Public().(ed25519.PublicKey)
	sources = append(sources, recorderSource{
		name:         "emitter-endorsed-rotation",
		dir:          dir,
		keys:         [][]string{nil, {hex.EncodeToString(pubA)}, {hex.EncodeToString(pubA), hex.EncodeToString(pubB)}},
		endorsements: []receipt.RotationEndorsement{endorsement},
	})
	return sources
}

// optionVariants are the verifier option sets tried on a source: every key
// set, with and without the waivers, and the source's endorsements under
// each pinned key set.
func optionVariants(src recorderSource) []wholeParityCase {
	var cases []wholeParityCase
	for _, keys := range src.keys {
		for _, waive := range []bool{false, true} {
			cases = append(cases, wholeParityCase{
				name: fmt.Sprintf("%s keys=%d waive=%v", src.name, len(keys), waive),
				dir:  src.dir,
				keys: keys,
				opts: verifyReceiptOptions{AllowUnpinned: waive, AllowUnanchoredSeal: waive},
			})
		}
		if len(keys) > 0 && len(src.endorsements) > 0 {
			cases = append(cases, wholeParityCase{
				name: fmt.Sprintf("%s keys=%d endorsed", src.name, len(keys)),
				dir:  src.dir,
				keys: keys,
				opts: verifyReceiptOptions{RotationEndorsements: src.endorsements},
			})
		}
	}
	return cases
}

// mutationOptionVariants narrows optionVariants for the mutation matrix to
// the sets that reach different checks: unpinned with every waiver, every
// signer key pinned without waivers, and the endorsed set when there is one.
func mutationOptionVariants(src recorderSource) []wholeParityCase {
	all := src.keys[len(src.keys)-1]
	cases := []wholeParityCase{
		{name: src.name + " unpinned waived", dir: src.dir, opts: verifyReceiptOptions{AllowUnpinned: true, AllowUnanchoredSeal: true}},
		{name: src.name + " pinned", dir: src.dir, keys: all},
	}
	if len(src.endorsements) > 0 && len(src.keys) > 1 {
		cases = append(cases, wholeParityCase{name: src.name + " endorsed", dir: src.dir, keys: src.keys[1], opts: verifyReceiptOptions{RotationEndorsements: src.endorsements}})
	}
	return cases
}

func TestWholeRecorderStreamingMatchesInMemoryOnCorpus(t *testing.T) {
	t.Parallel()
	sources := append(conformanceRecorderSources(t), emitterRecorderSources(t)...)
	var (
		mu       sync.Mutex
		failures = map[string]int{}
		valid    int
	)
	record := func(verdicts []string) {
		mu.Lock()
		defer mu.Unlock()
		for _, v := range verdicts {
			if v == "" {
				valid++
				continue
			}
			failures[firstClause(v)]++
		}
	}
	for _, src := range sources {
		for _, c := range optionVariants(src) {
			record(compareWholeRecorder(t, c))
		}
	}
	// The matrix must have exercised both verdicts and several failure
	// classes, or agreement proves little.
	if valid == 0 || len(failures) < 3 {
		t.Fatalf("parity matrix reached %d valid verdicts and failure classes %v", valid, failures)
	}
	t.Logf("corpus parity: %d valid verdicts, failure classes %v", valid, failures)
}

// firstClause names a failure by its leading clause, without the varying
// sequence numbers and hashes after it.
func firstClause(errText string) string {
	if i := strings.IndexAny(errText, ":("); i > 0 {
		return errText[:i]
	}
	return errText
}

func TestWholeRecorderStreamingMatchesInMemoryUnderMutation(t *testing.T) {
	t.Parallel()
	sources := emitterRecorderSources(t)
	// Two corpus recorders carry both receipt chains, decisions, a signed
	// checkpoint and a seal; mutate those as well.
	for _, src := range conformanceRecorderSources(t) {
		if src.name == "run-chains/valid" || src.name == "parity/rotated" {
			sources = append(sources, src)
		}
	}
	failures := map[string]int{}
	runs := 0
	for _, src := range sources {
		shards, err := filepath.Glob(filepath.Join(src.dir, "evidence-*.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		cases := mutationOptionVariants(src)
		for _, shard := range shards {
			lines := readLines(t, shard)
			for i := range lines {
				for _, op := range lineMutations(i) {
					mutated := op.apply(lines)
					if op.rehash {
						mutated = relinkLines(mutated)
					}
					dir := copyRecorderDir(t, src.dir)
					writeLines(t, filepath.Join(dir, filepath.Base(shard)), mutated)
					for _, c := range cases {
						c.name = fmt.Sprintf("%s %s %s", c.name, filepath.Base(shard), op.name)
						c.dir = dir
						for _, v := range compareWholeRecorder(t, c) {
							runs++
							if v != "" {
								failures[firstClause(v)]++
							}
						}
					}
				}
			}
		}
	}
	if len(failures) < 6 {
		t.Fatalf("mutation matrix reached only failure classes %v", failures)
	}
	t.Logf("mutation parity: %d verdicts, failure classes %v", runs, failures)
}

// TestWholeRecorderStreamingNamedAttacks pins the attacks the streaming
// change must keep refusing, each with the in-memory verifier's exact text.
func TestWholeRecorderStreamingNamedAttacks(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := physicalTempDir(t)
	emitIntoSigned(t, base, priv, 6, 0, true)
	appendTranscriptRootSigned(t, base, priv, true)
	keys := []string{hex.EncodeToString(pub)}
	// The emitter and the sealing run write separate shards. Join the
	// session into one shard so an attack can recompute the outer hash chain
	// across the whole session, as an attacker rewriting the files could.
	shards, err := filepath.Glob(filepath.Join(base, "evidence-*.jsonl"))
	if err != nil || len(shards) == 0 {
		t.Fatalf("fixture shards %v %v", shards, err)
	}
	sort.Slice(shards, func(i, j int) bool {
		_, si, _ := recorder.ParseEvidenceFilename(filepath.Base(shards[i]))
		_, sj, _ := recorder.ParseEvidenceFilename(filepath.Base(shards[j]))
		return si < sj
	})
	var lines []string
	for _, shard := range shards {
		lines = append(lines, readLines(t, shard)...)
		if err := os.Remove(shard); err != nil {
			t.Fatal(err)
		}
	}
	const shardName = "evidence-proxy-0.jsonl"
	writeLines(t, filepath.Join(base, shardName), lines)
	indexOf := func(typ string, nth int) int {
		seen := 0
		for i, line := range lines {
			if strings.Contains(line, `"type":"`+typ+`"`) {
				if seen == nth {
					return i
				}
				seen++
			}
		}
		t.Fatalf("no %s #%d in fixture", typ, nth)
		return -1
	}
	receipt2 := indexOf("action_receipt", 2)
	root := indexOf("transcript_root", 0)

	cases := []struct {
		name   string
		edit   func([]string) []string
		rehash bool
		want   string
	}{
		{"intact", func(l []string) []string { return l }, false, ""},
		{"broken link", func(l []string) []string {
			return append(append([]string(nil), l[:receipt2]...), l[receipt2+1:]...)
		}, true, "seq gap: expected 2, got 3"},
		{"tampered entry", func(l []string) []string {
			out := append([]string(nil), l...)
			out[receipt2] = tamperDetail(out[receipt2])
			return out
		}, false, "hash mismatch"},
		{"tampered entry with recomputed recorder chain", func(l []string) []string {
			out := append([]string(nil), l...)
			out[receipt2] = tamperDetail(out[receipt2])
			return out
		}, true, "signature"},
		{"missing seal", func(l []string) []string {
			return append([]string(nil), l[:root]...)
		}, false, "no transcript_root seal"},
		{"truncated tail", func(l []string) []string {
			out := append([]string(nil), l...)
			last := out[len(out)-1]
			out[len(out)-1] = last[:len(last)/2]
			return out
		}, false, "torn"},
		{"forked chain", func(l []string) []string {
			out := append([]string(nil), l[:receipt2+1]...)
			out = append(out, l[receipt2])
			return append(out, l[receipt2+1:]...)
		}, true, "seq gap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			edited := tc.edit(lines)
			if tc.rehash {
				edited = relinkLines(edited)
			}
			dir := copyRecorderDir(t, base)
			path := filepath.Join(dir, shardName)
			data := strings.Join(edited, "\n")
			if tc.name != "truncated tail" {
				data += "\n"
			}
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := verifyReceiptOptions{RequireSeal: true}
			location, err := recorder.ResolveEvidenceLocation(dir, "")
			if err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{"dir", "file"} {
				var gotOut, wantOut bytes.Buffer
				var got, want parityVerdict
				if mode == "dir" {
					got = verdictOf(&gotOut, verifyWholeRecorderFromResolvedSessionDir(&gotOut, location, "proxy", keys, opts))
					want = verdictOf(&wantOut, legacyVerifyWholeRecorderFromResolvedSessionDir(&wantOut, location, "proxy", keys, opts))
				} else {
					got = verdictOf(&gotOut, verifyWholeRecorderFromFile(&gotOut, shardName, path, keys, opts))
					want = verdictOf(&wantOut, legacyVerifyWholeRecorderFromFile(&wantOut, shardName, path, keys, opts))
				}
				if got != want {
					t.Fatalf("%s: streaming verdict differs\nstreaming: %+v\nin-memory: %+v", mode, got, want)
				}
				if tc.want == "" {
					if got.err != "" {
						t.Fatalf("%s: intact recorder failed: %s", mode, got.err)
					}
					continue
				}
				if got.err == "" || !strings.Contains(got.err+got.out, tc.want) {
					t.Fatalf("%s: verdict %q does not refuse with %q", mode, got.err, tc.want)
				}
			}
		})
	}
}

// liveHeapPeak samples the heap the garbage collector found live while fn
// runs. Collections are made frequent so the samples follow what fn retains
// rather than the garbage it has not yet freed.
func liveHeapPeak(t *testing.T, fn func()) uint64 {
	t.Helper()
	runtime.GC()
	oldPercent := debug.SetGCPercent(10)
	defer debug.SetGCPercent(oldPercent)
	sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	read := func() uint64 {
		metrics.Read(sample)
		return sample[0].Value.Uint64()
	}
	var peak atomic.Uint64
	peak.Store(read())
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if v := read(); v > peak.Load() {
					peak.Store(v)
				}
			}
		}
	}()
	fn()
	close(done)
	<-stopped
	if v := read(); v > peak.Load() {
		peak.Store(v)
	}
	return peak.Load()
}

// buildLongRecorder writes one sealed recorder of n action receipts through
// the real recorder and emitter, with a signed checkpoint every interval
// entries, and returns its directory and signer key.
func buildLongRecorder(t *testing.T, n int) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := physicalTempDir(t)
	emitIntoSigned(t, dir, priv, n, 0, true)
	appendTranscriptRootSigned(t, dir, priv, true)
	return dir, hex.EncodeToString(pub)
}

// TestWholeRecorderVerifyMemoryDoesNotGrowWithEntries verifies a short and a
// four-times-longer recorder through the full verify-receipt command and
// requires the longer one to retain no more than a fixed allowance beyond
// the shorter. Before verification streamed, every entry was held: about
// three kilobytes each here, so the longer run would retain tens of
// megabytes more.
func TestWholeRecorderVerifyMemoryDoesNotGrowWithEntries(t *testing.T) {
	if testing.Short() {
		t.Skip("builds two long recorders")
	}
	const short, long = 2000, 8000
	peaks := map[int]uint64{}
	for _, n := range []int{short, long} {
		dir, key := buildLongRecorder(t, n)
		var out string
		var verifyErr error
		peaks[n] = liveHeapPeak(t, func() {
			out, verifyErr = runVerifyReceipt(t, "--chain", dir, "--whole-recorder", "--require-seal", "--key", key)
		})
		if verifyErr != nil {
			t.Fatalf("n=%d: verify failed: %v\n%s", n, verifyErr, out)
		}
		if !strings.Contains(out, fmt.Sprintf("Receipts:  %d receipts verified", n+2)) {
			t.Fatalf("n=%d: verify did not cover every receipt:\n%s", n, out)
		}
	}
	const allowance = 4 << 20
	var growth uint64
	if peaks[long] > peaks[short] {
		growth = peaks[long] - peaks[short]
	}
	t.Logf("live heap peak: %d entries %d KiB, %d entries %d KiB, growth %d KiB", short, peaks[short]>>10, long, peaks[long]>>10, growth>>10)
	if growth > allowance {
		t.Fatalf("live heap grew %d KiB from %d to %d receipts; verification is retaining entries (allowance %d KiB)", growth>>10, short, long, allowance>>10)
	}
}

// TestAnchorWalkerHoldsOnlyOneReceiptGap pins the one buffer the streaming
// checkpoint check keeps: signed checkpoints the previous receipt's signer
// did not make wait for the next receipt, and are released there.
func TestAnchorWalkerHoldsOnlyOneReceiptGap(t *testing.T) {
	t.Parallel()
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyA, keyB := hex.EncodeToString(pubA), hex.EncodeToString(pubB)
	a := anchorWalker{anchor: checkpointAnchor{lastSignedIndex: -1}}
	seq := uint64(0)
	entry := func(typ string) recorder.Entry {
		e := recorder.Entry{Sequence: seq, Type: typ}
		seq++
		return e
	}
	checkpoint := func(priv ed25519.PrivateKey, prevHash string) recorder.Entry {
		e := entry("checkpoint")
		e.PrevHash = prevHash
		e.Detail = map[string]any{
			"first_seq": float64(e.Sequence - 1), "last_seq": float64(e.Sequence - 1), "entry_count": float64(1),
			"signature": hex.EncodeToString(ed25519.Sign(priv, []byte(prevHash))),
		}
		return e
	}
	i := 0
	add := func(e recorder.Entry, r *receipt.Receipt) {
		if r != nil {
			a.addReceipt(*r)
		}
		a.addEntry(i, e)
		i++
	}
	add(entry("action_receipt"), &receipt.Receipt{SignerKey: keyA})
	// Signed by the next writer before its first receipt: waits.
	add(checkpoint(privB, "h1"), nil)
	if len(a.pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(a.pending))
	}
	add(entry("action_receipt"), &receipt.Receipt{SignerKey: keyB})
	if len(a.pending) != 0 {
		t.Fatalf("pending after the next receipt = %d, want 0", len(a.pending))
	}
	// Signed by the current signer: verified at once.
	add(checkpoint(privB, "h2"), nil)
	if len(a.pending) != 0 {
		t.Fatalf("pending after an in-segment checkpoint = %d, want 0", len(a.pending))
	}
	// Signed by the retired key after the rotation: waits, then fails when
	// no different signer follows.
	add(entry("decision"), nil)
	add(checkpoint(privA, "h3"), nil)
	anchor, err := a.finish()
	if err == nil || !strings.Contains(err.Error(), "does not verify under the signer of its receipt segment") {
		t.Fatalf("retired-key checkpoint err = %v", err)
	}
	if anchor.signed != 2 {
		t.Fatalf("signed = %d, want 2", anchor.signed)
	}
}

// TestAnchorWalkerCapsPendingCheckpoints pins that one receipt gap cannot
// grow the waiting checkpoints without bound, and that reaching the cap fails
// verification rather than skipping the checkpoints past it.
func TestAnchorWalkerCapsPendingCheckpoints(t *testing.T) {
	t.Parallel()
	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyA, keyB := hex.EncodeToString(pubA), hex.EncodeToString(pubB)
	run := func(waiting int) (checkpointAnchor, int, error) {
		a := &anchorWalker{anchor: checkpointAnchor{lastSignedIndex: -1}}
		seq := uint64(0)
		i := 0
		peak := 0
		add := func(e recorder.Entry, r *receipt.Receipt) {
			if r != nil {
				a.addReceipt(*r)
			}
			a.addEntry(i, e)
			i++
			peak = max(peak, len(a.pending))
		}
		add(recorder.Entry{Sequence: seq, Type: "action_receipt"}, &receipt.Receipt{SignerKey: keyA})
		seq++
		for n := 0; n < waiting; n++ {
			add(recorder.Entry{Sequence: seq, Type: "decision"}, nil)
			seq++
			prevHash := fmt.Sprintf("h%d", n)
			sig := hex.EncodeToString(ed25519.Sign(privB, []byte(prevHash)))
			add(recorder.Entry{Sequence: seq, Type: "checkpoint", PrevHash: prevHash, Detail: map[string]any{
				"first_seq": float64(seq - 1), "last_seq": float64(seq - 1), "entry_count": float64(1), "signature": sig,
			}}, nil)
			seq++
		}
		add(recorder.Entry{Sequence: seq, Type: "action_receipt"}, &receipt.Receipt{SignerKey: keyB})
		anchor, err := a.finish()
		return anchor, peak, err
	}

	// Positive control: a gap exactly at the cap still verifies every
	// checkpoint once the next signer is known.
	anchor, peak, err := run(maxPendingCheckpoints)
	if err != nil {
		t.Fatalf("gap at the cap: %v", err)
	}
	if anchor.signed != maxPendingCheckpoints || peak != maxPendingCheckpoints {
		t.Fatalf("gap at the cap: signed %d peak %d, want %d", anchor.signed, peak, maxPendingCheckpoints)
	}

	// One past the cap fails closed and holds no more than the cap.
	_, peak, err = run(maxPendingCheckpoints + 50)
	if !errors.Is(err, errTooManyPendingCheckpoints) {
		t.Fatalf("flooded gap: err = %v, want errTooManyPendingCheckpoints", err)
	}
	if peak > maxPendingCheckpoints {
		t.Fatalf("flooded gap held %d pending checkpoints, cap %d", peak, maxPendingCheckpoints)
	}
}

// TestReceiptWindowMatchesInMemory pins the containment summary the stream
// builds against the slice helpers it replaced.
func TestReceiptWindowMatchesInMemory(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	open := &receipt.SessionControl{Kind: receipt.SessionControlOpen, Open: &receipt.SessionOpen{ContainedUID: "960", PostureCapsuleSHA256: "aa", PostureSignerKeyID: "bb"}}
	later := &receipt.SessionControl{Kind: receipt.SessionControlOpen, Open: &receipt.SessionOpen{ContainedUID: "961"}}
	var receipts []receipt.Receipt
	for _, step := range []struct {
		offset time.Duration
		ctrl   *receipt.SessionControl
	}{{5 * time.Second, nil}, {-time.Hour, open}, {time.Hour, nil}, {0, later}, {2 * time.Hour, nil}} {
		var r receipt.Receipt
		r.ActionRecord.Timestamp = base.Add(step.offset)
		r.ActionRecord.SessionControl = step.ctrl
		receipts = append(receipts, r)
	}
	for n := 0; n <= len(receipts); n++ {
		s := summarizeReceiptsForPosture(receipts[:n])
		from, to := legacyReceiptWindow(receipts[:n])
		if !s.from.Equal(from) || !s.to.Equal(to) {
			t.Fatalf("n=%d window (%v, %v), in-memory (%v, %v)", n, s.from, s.to, from, to)
		}
		if s.binding != legacyReceiptPostureBinding(receipts[:n]) {
			t.Fatalf("n=%d binding %+v, in-memory %+v", n, s.binding, legacyReceiptPostureBinding(receipts[:n]))
		}
	}
}
