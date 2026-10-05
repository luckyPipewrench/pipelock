// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// The walkers must return exactly what the slice verifiers return, for every
// prefix of every chain: a whole-recorder check reads a transcript_root's
// prefix result from the walker mid-stream, so a prefix that differs would
// change a seal verdict.

const walkConformanceTestdata = "../../sdk/conformance/testdata"

// corpusDirs lists every conformance directory holding recorder shards.
func corpusDirs(t *testing.T) []string {
	t.Helper()
	var dirs []string
	err := filepath.WalkDir(walkConformanceTestdata, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || !d.IsDir() {
			return walkErr
		}
		if shards, _ := filepath.Glob(filepath.Join(path, "evidence-*.jsonl")); len(shards) > 0 {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) < 20 {
		t.Fatalf("conformance corpus yielded %d recorder directories", len(dirs))
	}
	return dirs
}

// corpusKeys returns the signer keys the corpus ships beside dir.
func corpusKeys(dir string) []string {
	var keys []string
	for _, d := range []string{dir, filepath.Dir(dir), filepath.Dir(filepath.Dir(dir))} {
		for _, name := range []string{"signer-key.hex", "rotated-signer-key.hex", "signer.pub"} {
			data, err := os.ReadFile(filepath.Clean(filepath.Join(d, name)))
			if err != nil {
				continue
			}
			k := strings.TrimSpace(string(data))
			dup := false
			for _, have := range keys {
				dup = dup || have == k
			}
			if !dup {
				keys = append(keys, k)
			}
		}
	}
	return keys
}

func corpusEndorsements(dir string) []RotationEndorsement {
	files, _ := filepath.Glob(filepath.Join(dir, "*endorsement*.json"))
	var out []RotationEndorsement
	for _, f := range files {
		if e, err := LoadRotationEndorsementFile(f); err == nil {
			out = append(out, e)
		}
	}
	return out
}

// namedChain is one receipt chain under test.
type namedChain struct {
	name     string
	receipts []Receipt
	keys     []string
	session  string
	endorse  []RotationEndorsement
}

// receiptMutations returns the chain itself and, at every position, the chain
// with that receipt dropped, duplicated, swapped with the next, and edited
// after signing.
func receiptMutations(c namedChain) []namedChain {
	out := []namedChain{c}
	for i := range c.receipts {
		drop := append(append([]Receipt(nil), c.receipts[:i]...), c.receipts[i+1:]...)
		dup := append(append([]Receipt(nil), c.receipts[:i+1]...), c.receipts[i:]...)
		tamper := append([]Receipt(nil), c.receipts...)
		tamper[i].ActionRecord.Target += "/forged"
		variants := map[string][]Receipt{"drop": drop, "dup": dup, "tamper": tamper}
		if i+1 < len(c.receipts) {
			swap := append([]Receipt(nil), c.receipts...)
			swap[i], swap[i+1] = swap[i+1], swap[i]
			variants["swap"] = swap
		}
		for kind, rs := range variants {
			m := c
			m.name = fmt.Sprintf("%s %s-%d", c.name, kind, i)
			m.receipts = rs
			out = append(out, m)
		}
	}
	return out
}

func trustVariants(c namedChain) [][]string {
	out := [][]string{nil, {" "}, {strings.Repeat("ab", 32)}}
	for _, k := range c.keys {
		out = append(out, []string{k}, []string{k + " "})
	}
	if len(c.keys) > 1 {
		out = append(out, c.keys)
	}
	return out
}

// receiptChains gathers chains from the corpus and from the signing helpers:
// single key, rotated, session-bound lifecycle, and a chain that reaches the
// lifecycle-open fallback.
func receiptChains(t *testing.T) []namedChain {
	t.Helper()
	var chains []namedChain
	for _, dir := range corpusDirs(t) {
		sessions, err := recorder.ListSessions(dir)
		if err != nil {
			continue
		}
		for _, s := range sessions {
			rs, err := ExtractReceiptsFromSessionDir(dir, s)
			if err != nil || len(rs) == 0 {
				continue
			}
			chains = append(chains, namedChain{name: dir + " " + s, receipts: rs, keys: corpusKeys(dir), session: s, endorse: corpusEndorsements(dir)})
		}
	}
	pubA, privA := generateTestKey(t)
	pubB, privB := generateTestKey(t)
	keyA, keyB := hex.EncodeToString(pubA), hex.EncodeToString(pubB)
	chains = append(chains,
		namedChain{name: "single", receipts: buildChain(t, privA, 5), keys: []string{keyA}, session: "proxy"},
		namedChain{name: "rotated", receipts: buildRotatedChain(t, privA, privB, 3, 2), keys: []string{keyA, keyB}, session: "proxy"},
		namedChain{name: "session-control", receipts: buildValidSessionControlChain(t, privA), keys: []string{keyA}, session: "proxy"},
		namedChain{name: "stale-heartbeat", receipts: buildStaleSessionControlHeartbeatAfterRestart(t, privA), keys: []string{keyA}, session: "proxy"},
	)
	bound, boundaries := buildSessionBoundRotatedChain(t, privA, privB)
	chains = append(chains, namedChain{
		name: "session-bound-rotated", receipts: bound, keys: []string{keyA, keyB}, session: "proxy",
		endorse: []RotationEndorsement{endorsementForBoundary(t, bound, boundaries[0], privA)},
	})
	// A legacy genesis receipt, then receipts carrying a run nonce that no
	// session_open introduced: the strict walk fails lifecycle-open at the
	// second receipt and only the integrity walk decides the rest.
	base := time.Date(2026, 7, 6, 14, 0, 0, 0, time.UTC)
	noOpen := []Receipt{signChainReceipt(t, privA, 0, GenesisHash, base)}
	for i := 1; i < 4; i++ {
		noOpen = append(noOpen, signRunReceipt(t, privA, uint64(i), mustHash(t, noOpen[i-1]), "run-without-open", base.Add(time.Duration(i)*time.Second)))
	}
	chains = append(chains, namedChain{name: "lifecycle-open", receipts: noOpen, keys: []string{keyA}, session: "proxy"})
	return chains
}

func TestChainWalkerMatchesVerifyChainTrustedAtEveryPrefix(t *testing.T) {
	t.Parallel()
	kinds := map[string]int{}
	for _, base := range receiptChains(t) {
		for _, c := range receiptMutations(base) {
			for _, trusted := range trustVariants(c) {
				w := NewChainWalker(trusted)
				for k := 0; k <= len(c.receipts); k++ {
					if k > 0 {
						w.Add(c.receipts[k-1])
					}
					got := w.Result()
					want := VerifyChainTrusted(c.receipts[:k], trusted)
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("%s trusted=%q prefix %d:\nwalker: %+v\nslice:  %+v", c.name, trusted, k, got, want)
					}
					kinds[fmt.Sprintf("valid=%v kind=%s integrity=%v", got.Valid, got.FailureKind, got.IntegrityVerified)]++
				}
			}
		}
	}
	for _, need := range []string{
		"valid=true kind= integrity=true",
		"valid=false kind=integrity integrity=false",
		"valid=false kind=trust integrity=false",
		"valid=false kind=lifecycle integrity=false",
		"valid=false kind=lifecycle_missing_open integrity=true",
		"valid=false kind=integrity integrity=false",
	} {
		if kinds[need] == 0 {
			t.Fatalf("prefix matrix never reached %q; reached %v", need, kinds)
		}
	}
}

func TestEndorsedChainWalkerMatchesVerifyChainWithEndorsementsAtEveryPrefix(t *testing.T) {
	t.Parallel()
	valid := 0
	for _, base := range receiptChains(t) {
		for _, c := range receiptMutations(base) {
			endorsementSets := [][]RotationEndorsement{nil}
			if len(c.endorse) > 0 {
				endorsementSets = append(endorsementSets, c.endorse, append(append([]RotationEndorsement(nil), c.endorse...), c.endorse[0]))
			}
			roots := [][]string{nil, {" "}}
			if len(c.keys) > 0 {
				roots = append(roots, c.keys[:1], c.keys)
			}
			for _, session := range []string{c.session, "", "proxy.run.other"} {
				for _, roots := range roots {
					for _, endorsements := range endorsementSets {
						w := NewEndorsedChainWalker(session, endorsements, roots)
						for k := 0; k <= len(c.receipts); k++ {
							if k > 0 {
								w.Add(c.receipts[k-1])
							}
							got := w.Result()
							want := VerifyChainWithEndorsements(session, c.receipts[:k], endorsements, roots)
							if !reflect.DeepEqual(got, want) {
								t.Fatalf("%s session=%q roots=%q endorsements=%d prefix %d:\nwalker: %+v\nslice:  %+v", c.name, session, roots, len(endorsements), k, got, want)
							}
							if got.Valid && len(got.TrustBasis) > 1 {
								valid++
							}
						}
					}
				}
			}
		}
	}
	if valid == 0 {
		t.Fatal("endorsement matrix never verified an endorsed rotation")
	}
}

func TestEvidenceChainWalkerMatchesVerifyEvidenceChainTrusted(t *testing.T) {
	t.Parallel()
	checked := 0
	for _, dir := range corpusDirs(t) {
		sessions, err := recorder.ListSessions(dir)
		if err != nil {
			continue
		}
		keys := corpusKeys(dir)
		for _, s := range sessions {
			result, err := recorder.QuerySession(dir, s, nil)
			if err != nil {
				continue
			}
			evidence, err := contractreceipt.ExtractEvidenceReceiptsFromEntries(result.Entries)
			if err != nil || len(evidence) == 0 {
				continue
			}
			variants := [][]contractreceipt.EvidenceReceipt{evidence, nil}
			for i := range evidence {
				variants = append(variants,
					append(append([]contractreceipt.EvidenceReceipt(nil), evidence[:i]...), evidence[i+1:]...),
					append(append([]contractreceipt.EvidenceReceipt(nil), evidence[:i+1]...), evidence[i:]...))
			}
			trustSets := [][]string{nil, {strings.Repeat("ab", 32)}}
			for _, k := range keys {
				trustSets = append(trustSets, []string{k}, []string{strings.ToUpper(k) + " "})
			}
			for _, rs := range variants {
				for _, trusted := range trustSets {
					w := NewEvidenceChainWalker(trusted, contractreceipt.ChainVerifyOptions{})
					for k := 0; k <= len(rs); k++ {
						if k > 0 {
							w.Add(rs[k-1])
						}
						got := w.Result()
						want := VerifyEvidenceChainTrusted(rs[:k], trusted, contractreceipt.ChainVerifyOptions{})
						if !reflect.DeepEqual(got, want) {
							t.Fatalf("%s %s trusted=%q prefix %d:\nwalker: %+v\nslice:  %+v", dir, s, trusted, k, got, want)
						}
						if w.Count() != k {
							t.Fatalf("Count = %d, want %d", w.Count(), k)
						}
						checked++
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no evidence receipt chains in the corpus")
	}
}

func TestWholeRecorderWalkerMatchesVerifyWholeRecorderEntries(t *testing.T) {
	t.Parallel()
	failures := map[string]int{}
	for _, dir := range corpusDirs(t) {
		sessions, err := recorder.ListSessions(dir)
		if err != nil {
			continue
		}
		for _, s := range sessions {
			result, err := recorder.QuerySession(dir, s, nil)
			if err != nil || len(result.Entries) == 0 {
				continue
			}
			entries := result.Entries
			variants := [][]recorder.Entry{entries}
			for i := range entries {
				drop := append(append([]recorder.Entry(nil), entries[:i]...), entries[i+1:]...)
				foreign := append([]recorder.Entry(nil), entries...)
				foreign[i].SessionID += "-other"
				unknown := append([]recorder.Entry(nil), entries...)
				unknown[i].Type = "unknown_type"
				badReceipt := append([]recorder.Entry(nil), entries...)
				badReceipt[i].RawDetail = json.RawMessage(`{"version":1}`)
				if len(entries[i].RawDetail) > 1 && entries[i].RawDetail[0] == '{' {
					// Well-formed JSON the strict receipt decoder refuses.
					badReceipt[i].RawDetail = append(json.RawMessage(`{"unknown_signed_field":1,`), entries[i].RawDetail[1:]...)
				}
				variants = append(variants, drop, foreign, unknown, badReceipt,
					relinkEntries(append([]recorder.Entry(nil), drop...)),
					relinkEntries(append([]recorder.Entry(nil), badReceipt...)))
			}
			for _, es := range variants {
				var w WholeRecorderWalker
				var got []Receipt
				for _, e := range es {
					if r, ok := w.Add(e); ok {
						got = append(got, r)
					}
				}
				want, wantErr := VerifyWholeRecorderEntries(es)
				gotErr := w.Err()
				if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
					t.Fatalf("%s %s: walker err %v, slice err %v", dir, s, gotErr, wantErr)
				}
				if wantErr != nil {
					failures[strings.SplitN(wantErr.Error(), ":", 2)[0]]++
					continue
				}
				if w.EntryCount() != want.EntryCount || !reflect.DeepEqual(got, want.Receipts) {
					t.Fatalf("%s %s: walker returned %d receipts over %d entries, slice %d over %d", dir, s, len(got), w.EntryCount(), len(want.Receipts), want.EntryCount)
				}
			}
		}
	}
	if len(failures) < 3 {
		t.Fatalf("whole-recorder matrix reached only %v", failures)
	}
}

// baseOptionVariants are the VerifyBase option sets tried on a directory.
func baseOptionVariants(dir string) []BaseVerifyOptions {
	keys := corpusKeys(dir)
	endorsements := corpusEndorsements(dir)
	opts := []BaseVerifyOptions{{}, {LinksOnly: true}}
	for _, k := range keys {
		opts = append(opts, BaseVerifyOptions{TrustedKeys: []string{k}})
		if len(endorsements) > 0 {
			opts = append(opts, BaseVerifyOptions{TrustedKeys: []string{k}, Endorsements: endorsements})
		}
	}
	if len(keys) > 1 {
		opts = append(opts, BaseVerifyOptions{TrustedKeys: keys})
	}
	return opts
}

func compareVerifyBase(t *testing.T, label, dir string) int {
	t.Helper()
	bases, err := ContinuityBases(dir)
	if err != nil {
		bases = nil
	}
	if !containsBase(bases, "proxy") {
		bases = append(bases, "proxy")
	}
	compared := 0
	for _, base := range bases {
		for _, opts := range baseOptionVariants(dir) {
			got, gotErr := VerifyBase(dir, base, opts)
			want, wantErr := legacyVerifyBase(dir, base, opts)
			if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(got, want) {
				t.Fatalf("%s base %s opts %+v:\nstreaming: %+v %v\nin-memory: %+v %v", label, base, opts, got, gotErr, want, wantErr)
			}
			compared++
		}
	}
	return compared
}

func containsBase(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestVerifyBaseStreamingMatchesInMemoryOnCorpus(t *testing.T) {
	t.Parallel()
	compared := 0
	for _, dir := range corpusDirs(t) {
		compared += compareVerifyBase(t, dir, dir)
	}
	if compared < 50 {
		t.Fatalf("compared only %d VerifyBase reports", compared)
	}
}

// copyShardDir copies dir's regular files into a fresh directory.
func copyShardDir(t *testing.T, dir string) string {
	t.Helper()
	dst := t.TempDir()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if !de.Type().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, de.Name())))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, de.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// relinkShardLines recomputes the outer hash chain over lines, keeping each
// entry's detail bytes.
func relinkShardLines(lines []string) []string {
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
		data, _ := json.Marshal(fields)
		out[i] = string(data)
	}
	return out
}

func TestVerifyBaseStreamingMatchesInMemoryUnderMutation(t *testing.T) {
	t.Parallel()
	findings := map[string]int{}
	for _, dir := range corpusDirs(t) {
		switch {
		case strings.HasSuffix(dir, "run-chains/valid"), strings.HasSuffix(dir, "run-chains/key-rotated"),
			strings.HasSuffix(dir, "run-chains/link-appended"), strings.HasSuffix(dir, "parity/rotated"):
		default:
			continue
		}
		shards, _ := filepath.Glob(filepath.Join(dir, "evidence-*.jsonl"))
		for _, shard := range shards {
			raw, err := os.ReadFile(filepath.Clean(shard))
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
			for i := range lines {
				for _, op := range []struct {
					name   string
					rehash bool
					edit   []string
				}{
					{"drop", true, append(append([]string(nil), lines[:i]...), lines[i+1:]...)},
					{"dup", true, append(append(append([]string(nil), lines[:i+1]...), lines[i]), lines[i+1:]...)},
					{"cut", false, append([]string(nil), lines[:i]...)},
					{"tamper", false, tamperShardLine(lines, i)},
				} {
					edited := op.edit
					if op.rehash {
						edited = relinkShardLines(edited)
					}
					mutated := copyShardDir(t, dir)
					data := strings.Join(edited, "\n")
					if len(edited) > 0 {
						data += "\n"
					}
					if err := os.WriteFile(filepath.Join(mutated, filepath.Base(shard)), []byte(data), 0o600); err != nil {
						t.Fatal(err)
					}
					compareVerifyBase(t, fmt.Sprintf("%s %s %s-%d", dir, filepath.Base(shard), op.name, i), mutated)
					if report, err := VerifyBase(mutated, "proxy", BaseVerifyOptions{TrustedKeys: corpusKeys(dir)}); err == nil {
						for _, f := range report.Findings {
							findings[f.Kind]++
						}
					}
				}
			}
		}
	}
	if len(findings) < 3 {
		t.Fatalf("mutation matrix reached only finding kinds %v", findings)
	}
}

func tamperShardLine(lines []string, i int) []string {
	out := append([]string(nil), lines...)
	out[i] = strings.Replace(out[i], `"allow"`, `"block"`, 1)
	if out[i] == lines[i] {
		out[i] = strings.Replace(out[i], `"detail":{`, `"detail":{"tampered":true,`, 1)
	}
	return out
}

// TestVerifyBaseSecondReadMustSeeTheFirstReadsEntries pins the binding between
// the read that loads a chain and the later read that verifies it under an
// endorsement-dependent trust set. Cutting the shard back to an earlier,
// still validly signed receipt between the reads leaves a prefix that
// verifies on its own; without the binding the chain would pass with the
// first read's tail, which the second read never verified.
func TestVerifyBaseSecondReadMustSeeTheFirstReadsEntries(t *testing.T) {
	t.Parallel()
	src := filepath.Join(walkConformanceTestdata, "run-chains", "valid")
	keys := corpusKeys(src)
	for _, edit := range []bool{false, true} {
		dir := copyShardDir(t, src)
		ix, err := indexRecorderFiles(dir)
		if err != nil {
			t.Fatal(err)
		}
		sessions := ix.sessions()
		if len(sessions) == 0 {
			t.Fatal("fixture has no sessions")
		}
		var findings []BaseFinding
		add := func(kind, session, detail string) {
			findings = append(findings, BaseFinding{Kind: kind, Session: session, Detail: detail})
		}
		d := &baseChainData{chain: BaseChain{Session: sessions[0]}}
		loadBaseChain(ix, d, baseLoadOptions{}, nil, add)
		if d.verified || d.chain.Error != "" {
			t.Fatalf("load: verified=%v error=%q", d.verified, d.chain.Error)
		}
		if edit {
			files, err := ix.files(sessions[0])
			if err != nil || len(files) == 0 {
				t.Fatalf("files %v %v", files, err)
			}
			raw, err := os.ReadFile(filepath.Clean(files[0]))
			if err != nil {
				t.Fatal(err)
			}
			// Keep the lines through the third action receipt.
			lines := strings.SplitAfter(string(raw), "\n")
			kept, receipts := 0, 0
			for kept < len(lines) && receipts < 3 {
				if strings.Contains(lines[kept], `"type":"action_receipt"`) {
					receipts++
				}
				kept++
			}
			if receipts < 3 || kept >= len(lines) {
				t.Fatal("fixture too short to cut")
			}
			if err := os.WriteFile(files[0], []byte(strings.Join(lines[:kept], "")), 0o600); err != nil {
				t.Fatal(err)
			}
			// Positive control: the cut prefix verifies on its own.
			cut, err := ExtractReceiptsFromSessionDir(dir, sessions[0])
			if err != nil {
				t.Fatal(err)
			}
			if res := VerifyChainTrusted(cut, keys[:1]); !res.Valid {
				t.Fatalf("cut prefix does not verify on its own: %s", res.Error)
			}
		}
		verifyBaseChain(&evidenceReread{dir: dir}, ix, d, keys[:1], nil, false, add, add)
		changed := len(findings) > 0 && strings.Contains(findings[0].Detail, "evidence changed between verification reads")
		if edit && (!changed || d.chain.Valid) {
			t.Fatalf("edited between reads: valid=%v findings=%+v", d.chain.Valid, findings)
		}
		if !edit && (len(findings) != 0 || !d.chain.Valid) {
			t.Fatalf("unchanged: valid=%v findings=%+v", d.chain.Valid, findings)
		}
	}
}

// relinkEntries recomputes the outer hash chain over entries.
func relinkEntries(es []recorder.Entry) []recorder.Entry {
	prev := recorder.GenesisHash
	for i := range es {
		es[i].PrevHash = prev
		es[i].Hash = recorder.ComputeHash(es[i])
		prev = es[i].Hash
	}
	return es
}
