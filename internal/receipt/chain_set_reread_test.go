// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A rotation endorsement makes VerifyBase read every chain twice: once to
// load it and once to verify it under the trust its predecessor decided. The
// second read verifies the receipts; the first read checked the outer hash
// chain. These tests change the evidence between the two reads and require
// the verdict to fail closed whenever the second read did not see exactly
// the bytes, files, and shard set the first read verified.

const rereadTargetShard = "evidence-proxy.run.03b13ee13e01e7f770480f62ea42f1fe-0.jsonl"

// verifyBaseWithMutation runs VerifyBase over a copy of the valid run-chain
// fixture with a non-matching endorsement, so every chain is read twice, and
// applies mutate to the copy between the reads. Tests using it do not run in
// parallel because the seam is package state.
func verifyBaseWithMutation(t *testing.T, mutate func(t *testing.T, dir string)) BaseReport {
	t.Helper()
	src := filepath.Join(walkConformanceTestdata, "run-chains", "valid")
	keys := corpusKeys(src)
	dir := copyShardDir(t, src)
	called := false
	prev := betweenVerificationReads
	betweenVerificationReads = func(d string) {
		if d != dir || mutate == nil {
			return
		}
		called = true
		mutate(t, dir)
	}
	t.Cleanup(func() { betweenVerificationReads = prev })
	report, err := VerifyBase(dir, "proxy", BaseVerifyOptions{
		TrustedKeys:  keys,
		Endorsements: []RotationEndorsement{{Version: 1, SessionID: "proxy.run.does-not-exist"}},
	})
	if err != nil {
		t.Fatalf("VerifyBase: %v", err)
	}
	if mutate != nil && !called {
		t.Fatal("mutation seam was not reached")
	}
	return report
}

func readShardLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return strings.SplitAfter(string(raw), "\n")
}

// editFirstLine rewrites the first line's field value to a same-length
// replacement, in place, so size and inode stay the same and only the bytes
// differ.
func editFirstLine(t *testing.T, path, field string) {
	t.Helper()
	lines := readShardLines(t, path)
	key := `"` + field + `":"`
	i := strings.Index(lines[0], key)
	if i < 0 {
		t.Fatalf("first line has no %s", field)
	}
	at := i + len(key)
	b := []byte(lines[0])
	if b[at] == '0' {
		b[at] = '1'
	} else {
		b[at] = '0'
	}
	lines[0] = string(b)
	writeInPlace(t, path, strings.Join(lines, ""))
}

func writeInPlace(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyBaseRereadUnchangedPasses(t *testing.T) {
	report := verifyBaseWithMutation(t, func(*testing.T, string) {})
	if !report.Healthy() {
		t.Fatalf("unchanged directory: findings %+v", report.Findings)
	}
	for _, c := range report.Chains {
		if !c.Valid {
			t.Fatalf("unchanged directory: chain %s invalid: %s", c.Session, c.Error)
		}
	}
}

func TestVerifyBaseRereadFailsClosedOnChange(t *testing.T) {
	const (
		refused  = "evidence refused"
		bytesDif = "evidence changed between verification reads: shard bytes differ"
		replaced = "evidence changed between verification reads: shard file replaced"
		setDif   = "evidence changed between verification reads: shard set differs"
	)
	cases := []struct {
		name   string
		want   string
		mutate func(t *testing.T, dir string)
	}{
		{"symlink swap with prev_hash edit", refused, func(t *testing.T, dir string) {
			target := filepath.Join(dir, rereadTargetShard)
			elsewhere := filepath.Join(t.TempDir(), rereadTargetShard)
			lines := readShardLines(t, target)
			if err := os.WriteFile(elsewhere, []byte(strings.Join(lines, "")), 0o600); err != nil {
				t.Fatal(err)
			}
			editFirstLine(t, elsewhere, "prev_hash")
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, target); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink swap plus added shard", setDif, func(t *testing.T, dir string) {
			target := filepath.Join(dir, rereadTargetShard)
			elsewhere := filepath.Join(t.TempDir(), rereadTargetShard)
			data, err := os.ReadFile(filepath.Clean(target))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(elsewhere, data, 0o600); err != nil {
				t.Fatal(err)
			}
			editFirstLine(t, elsewhere, "prev_hash")
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, target); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, strings.Replace(rereadTargetShard, "-0.jsonl", "-1.jsonl", 1)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"prev_hash edit in place", bytesDif, func(t *testing.T, dir string) {
			editFirstLine(t, filepath.Join(dir, rereadTargetShard), "prev_hash")
		}},
		{"timestamp edit in place", bytesDif, func(t *testing.T, dir string) {
			editFirstLine(t, filepath.Join(dir, rereadTargetShard), "ts")
		}},
		{"summary edit in place", bytesDif, func(t *testing.T, dir string) {
			path := filepath.Join(dir, rereadTargetShard)
			lines := readShardLines(t, path)
			i := strings.Index(lines[0], `"summary":"`)
			if i < 0 || lines[0][i+len(`"summary":"`)] == '"' {
				t.Fatal("first line has no non-empty summary")
			}
			at := i + len(`"summary":"`)
			b := []byte(lines[0])
			if b[at] == 'X' {
				b[at] = 'Y'
			} else {
				b[at] = 'X'
			}
			lines[0] = string(b)
			writeInPlace(t, path, strings.Join(lines, ""))
		}},
		{"shard added", setDif, func(t *testing.T, dir string) {
			name := strings.Replace(rereadTargetShard, "-0.jsonl", "-5000.jsonl", 1)
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"shard removed", setDif, func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, rereadTargetShard)); err != nil {
				t.Fatal(err)
			}
		}},
		{"shard grown", bytesDif, func(t *testing.T, dir string) {
			path := filepath.Join(dir, rereadTargetShard)
			lines := readShardLines(t, path)
			f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(lines[len(lines)-2]); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		{"byte-identical file replaced", replaced, func(t *testing.T, dir string) {
			path := filepath.Join(dir, rereadTargetShard)
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			tmp := path + ".tmp"
			if err := os.WriteFile(tmp, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, path); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := verifyBaseWithMutation(t, tc.mutate)
			if report.Healthy() {
				t.Fatalf("evidence changed between reads but the report is healthy: %+v", report.Chains)
			}
			found := false
			for _, f := range report.Findings {
				found = found || (f.Kind == FindingCorruptChain && strings.Contains(f.Detail, tc.want))
			}
			if !found {
				t.Fatalf("want a corrupt_chain finding containing %q, got %+v", tc.want, report.Findings)
			}
			for _, c := range report.Chains {
				if c.Session == "proxy.run.03b13ee13e01e7f770480f62ea42f1fe" && c.Valid {
					t.Fatalf("changed chain reported valid: %+v", c)
				}
			}
		})
	}
}

// verifyBaseWithWalkHook runs VerifyBase over a copy of the valid run-chain
// fixture and calls hook after each shard a verification read walks, with
// the shard's path and how many times that path has been walked so far.
// endorsed selects the two-read path; otherwise each chain is read once.
// Tests using it do not run in parallel because the seams are package state.
func verifyBaseWithWalkHook(t *testing.T, endorsed bool, hook func(t *testing.T, dir, path string, visit int)) BaseReport {
	t.Helper()
	src := filepath.Join(walkConformanceTestdata, "run-chains", "valid")
	keys := corpusKeys(src)
	dir := copyShardDir(t, src)
	visits := make(map[string]int)
	prev := duringEvidenceWalk
	duringEvidenceWalk = func(path string) {
		if filepath.Dir(path) != filepath.Clean(dir) {
			return
		}
		visits[path]++
		hook(t, dir, path, visits[path])
	}
	t.Cleanup(func() { duringEvidenceWalk = prev })
	opts := BaseVerifyOptions{TrustedKeys: keys}
	if endorsed {
		opts.Endorsements = []RotationEndorsement{{Version: 1, SessionID: "proxy.run.does-not-exist"}}
	}
	report, err := VerifyBase(dir, "proxy", opts)
	if err != nil {
		t.Fatalf("VerifyBase: %v", err)
	}
	return report
}

// addBrokenShard writes a later shard of the target chain that does not
// parse, so any read that opened it would fail.
func addBrokenShard(t *testing.T, dir string) {
	t.Helper()
	name := strings.Replace(rereadTargetShard, "-0.jsonl", "-5000.jsonl", 1)
	if err := os.WriteFile(filepath.Join(dir, name), []byte("{not a recorder entry}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func requireChangedDuring(t *testing.T, report BaseReport, want string) {
	t.Helper()
	if report.Healthy() {
		t.Fatalf("evidence changed during verification but the report is healthy: %+v", report.Chains)
	}
	full := "evidence changed during verification: " + want
	found := false
	for _, f := range report.Findings {
		found = found || (f.Kind == FindingCorruptChain && f.Session == "proxy.run.03b13ee13e01e7f770480f62ea42f1fe" && strings.Contains(f.Detail, full))
	}
	if !found {
		t.Fatalf("want a corrupt_chain finding containing %q, got %+v", full, report.Findings)
	}
	for _, c := range report.Chains {
		if c.Session == "proxy.run.03b13ee13e01e7f770480f62ea42f1fe" && c.Valid {
			t.Fatalf("changed chain reported valid: %+v", c)
		}
	}
}

func TestVerifyBaseWalkHookUnchangedPasses(t *testing.T) {
	for _, endorsed := range []bool{false, true} {
		walked := 0
		report := verifyBaseWithWalkHook(t, endorsed, func(*testing.T, string, string, int) { walked++ })
		if walked == 0 {
			t.Fatalf("endorsed=%v: walk seam was not reached", endorsed)
		}
		if !report.Healthy() {
			t.Fatalf("endorsed=%v: unchanged directory: findings %+v", endorsed, report.Findings)
		}
		for _, c := range report.Chains {
			if !c.Valid {
				t.Fatalf("endorsed=%v: unchanged directory: chain %s invalid: %s", endorsed, c.Session, c.Error)
			}
		}
	}
}

// A shard created while a chain's only read is in progress is never opened
// by that read; the report must not stay healthy.
func TestVerifyBaseShardAddedDuringSingleReadFailsClosed(t *testing.T) {
	fired := false
	report := verifyBaseWithWalkHook(t, false, func(t *testing.T, dir, path string, visit int) {
		if filepath.Base(path) == rereadTargetShard && visit == 1 {
			fired = true
			addBrokenShard(t, dir)
		}
	})
	if !fired {
		t.Fatal("hook did not fire during the single read")
	}
	requireChangedDuring(t, report, "shard set differs")
}

// A shard created while the second, endorsed read is in progress was listed
// by neither read.
func TestVerifyBaseShardAddedDuringSecondReadFailsClosed(t *testing.T) {
	fired := false
	report := verifyBaseWithWalkHook(t, true, func(t *testing.T, dir, path string, visit int) {
		if filepath.Base(path) == rereadTargetShard && visit == 2 {
			fired = true
			addBrokenShard(t, dir)
		}
	})
	if !fired {
		t.Fatal("hook did not fire during the second read")
	}
	requireChangedDuring(t, report, "shard set differs")
}

// A shard grown or replaced after the single read finished with it, while
// verification is still running, differs from what that read verified.
func TestVerifyBaseShardChangedDuringSingleReadFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		want   string
		mutate func(t *testing.T, path string)
	}{
		{"grown", "shard size changed", func(t *testing.T, path string) {
			lines := readShardLines(t, path)
			f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(lines[len(lines)-2]); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		{"replaced", "shard file replaced", func(t *testing.T, path string) {
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			tmp := path + ".tmp"
			if err := os.WriteFile(tmp, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, path); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := verifyBaseWithWalkHook(t, false, func(t *testing.T, _, path string, visit int) {
				if filepath.Base(path) == rereadTargetShard && visit == 1 {
					tc.mutate(t, path)
				}
			})
			requireChangedDuring(t, report, tc.want)
		})
	}
}

// After every read has finished, the directory is listed once more: a shard
// added then, on the single-read path, still fails the report.
func TestVerifyBaseShardAddedAfterReadsFailsClosed(t *testing.T) {
	src := filepath.Join(walkConformanceTestdata, "run-chains", "valid")
	keys := corpusKeys(src)
	dir := copyShardDir(t, src)
	called := false
	prev := betweenVerificationReads
	betweenVerificationReads = func(d string) {
		if d == dir {
			called = true
			addBrokenShard(t, dir)
		}
	}
	t.Cleanup(func() { betweenVerificationReads = prev })
	report, err := VerifyBase(dir, "proxy", BaseVerifyOptions{TrustedKeys: keys})
	if err != nil {
		t.Fatalf("VerifyBase: %v", err)
	}
	if !called {
		t.Fatal("seam after the reads was not reached")
	}
	requireChangedDuring(t, report, "shard set differs")
}

// A new chain of the base that appears during verification was never read.
func TestVerifyBaseChainAddedDuringReadFailsClosed(t *testing.T) {
	const added = "proxy.run.ffffffffffffffffffffffffffffffff"
	fired := false
	report := verifyBaseWithWalkHook(t, false, func(t *testing.T, dir, path string, visit int) {
		if filepath.Base(path) == rereadTargetShard && visit == 1 {
			fired = true
			if err := os.WriteFile(filepath.Join(dir, "evidence-"+added+"-0.jsonl"), []byte("{not a recorder entry}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	})
	if !fired {
		t.Fatal("hook did not fire")
	}
	found := false
	for _, f := range report.Findings {
		found = found || (f.Kind == FindingCorruptChain && f.Session == added && strings.Contains(f.Detail, "evidence changed during verification: shard set differs"))
	}
	if !found {
		t.Fatalf("want a finding for the added chain, got %+v", report.Findings)
	}
}

// Links-only mode is the doctor's check of live recorders; a shard that
// grows while it reads is not a finding there.
func TestVerifyBaseLinksOnlyToleratesGrowth(t *testing.T) {
	src := filepath.Join(walkConformanceTestdata, "run-chains", "valid")
	dir := copyShardDir(t, src)
	grew := false
	prev := duringEvidenceWalk
	duringEvidenceWalk = func(path string) {
		if grew || filepath.Dir(path) != filepath.Clean(dir) {
			return
		}
		grew = true
		lines := readShardLines(t, path)
		f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(lines[len(lines)-2]); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { duringEvidenceWalk = prev })
	before, err := VerifyBase(copyShardDir(t, src), "proxy", BaseVerifyOptions{LinksOnly: true})
	if err != nil {
		t.Fatalf("VerifyBase: %v", err)
	}
	report, err := VerifyBase(dir, "proxy", BaseVerifyOptions{LinksOnly: true})
	if err != nil {
		t.Fatalf("VerifyBase: %v", err)
	}
	if !grew {
		t.Fatal("links-only mode read no shard; the growth was never applied")
	}
	for _, f := range report.Findings {
		if strings.Contains(f.Detail, "evidence changed during verification") {
			t.Fatalf("links-only mode refused a growing shard: %+v (baseline %+v)", f, before.Findings)
		}
	}
}
