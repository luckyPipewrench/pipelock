// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
	"github.com/luckyPipewrench/pipelock/internal/svidsidecar"
)

// This file is the GO arm of the four-language AARP conformance gate. It runs the
// Go reference verifier over every fixture in testdata/aarp-corpus and asserts:
//
//   - "appraise" envelope fixtures verify and emit ComparableAppraisal bytes that
//     match the committed <name>.appraisal.json exactly;
//   - "appraise" chain fixtures link and emit matching ComparableChain bytes;
//   - "fatal" fixtures reject (Unmarshal/Verify error, or a broken chain).
//
// The TypeScript, Rust, and Python verifiers are run over the SAME corpus by
// aarp-corpus-gate.sh; this test is the Go member of that set and runs in the
// standard `test` CI job, so a Go-side regression is caught even when the bash
// gate job is skipped by path filters.

type aarpExpect struct {
	FixtureID   string `json:"fixture_id"`
	Category    string `json:"category"`
	InputFormat string `json:"input_format"`
	Verdict     string `json:"verdict"`
}

// aarpCorpusVerifyOptions reconstructs the pinned trust the corpus was generated
// against, from the same deterministic seeds, so the Go arm needs no external
// trust file at run time.
func aarpCorpusVerifyOptions() aarp.VerifyOptions {
	signerPub, _ := keyFromSeed(seedSigner)
	issuerPub, _ := keyFromSeed(seedIssuer)
	return corpusVerifyOptions(signerPub, issuerPub)
}

func TestAARPCorpus(t *testing.T) {
	t.Parallel()
	opts := aarpCorpusVerifyOptions()

	var checked int
	for _, category := range []string{catGolden, catMalicious, catEdge, catChain, catSVID, catKillSuite} {
		dir := filepath.Join(aarpCorpusDir, category)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read corpus dir %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".expect.json") {
				continue
			}
			base := strings.TrimSuffix(name, ".expect.json")
			t.Run(category+"/"+base, func(t *testing.T) {
				t.Parallel()
				runAARPCorpusFixture(t, dir, base, opts)
			})
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no AARP fixtures found; corpus generation is broken (run -update-aarp)")
	}
}

func runAARPCorpusFixture(t *testing.T, dir, base string, opts aarp.VerifyOptions) {
	t.Helper()
	exp := readAARPExpect(t, filepath.Join(dir, base+".expect.json"))

	if exp.InputFormat == "chain" {
		runAARPChainFixture(t, dir, base, exp)
		return
	}

	// SVID fixtures carry a sidecar and are appraised through AppraiseWithSVID.
	// They are always verdictAppraise; the committed appraisal encodes whether the
	// workload-identity claims attach (no inflation on the hostile fixtures).
	sidecarPath := filepath.Join(dir, base+".svid.json")
	if _, statErr := os.Stat(sidecarPath); statErr == nil {
		runAARPSVIDFixture(t, dir, base, sidecarPath, exp, opts)
		return
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		// A real filesystem error (e.g. permissions) must fail loudly, not be
		// silently treated as "no sidecar" and fall through to the envelope path.
		t.Fatalf("stat sidecar %s: %v", sidecarPath, statErr)
	}

	body := readFixture(t, filepath.Join(dir, base+".aarp.json"))
	env, err := aarp.Unmarshal(body)
	if err != nil {
		if exp.Verdict == verdictFatal {
			return // expected: fatal at parse time
		}
		t.Fatalf("appraise fixture %s failed to unmarshal: %v", base, err)
	}
	ap, err := aarp.Verify(env, opts)
	if err != nil {
		if exp.Verdict == verdictFatal {
			return // expected: fatal at verify time
		}
		t.Fatalf("appraise fixture %s failed to verify: %v", base, err)
	}
	if exp.Verdict == verdictFatal {
		t.Fatalf("fatal fixture %s unexpectedly appraised: %+v", base, ap)
	}

	got, err := aarp.ComparableAppraisal(ap)
	if err != nil {
		t.Fatalf("comparable appraisal %s: %v", base, err)
	}
	want := readFixture(t, filepath.Join(dir, base+".appraisal.json"))
	assertComparableMatch(t, base, got, want)
}

func runAARPChainFixture(t *testing.T, dir, base string, exp aarpExpect) {
	t.Helper()
	body := readFixture(t, filepath.Join(dir, base+".aarp.jsonl"))
	envs, parseErr := parseChainLines(body)
	if parseErr != nil {
		if exp.Verdict == verdictFatal {
			return
		}
		t.Fatalf("chain fixture %s failed to parse: %v", base, parseErr)
	}

	linked := aarp.VerifyChain(envs) == nil
	if exp.Verdict == verdictFatal {
		if linked {
			t.Fatalf("fatal chain fixture %s unexpectedly linked", base)
		}
		return
	}
	if !linked {
		t.Fatalf("appraise chain fixture %s did not link", base)
	}
	got, err := aarp.ComparableChain(envs)
	if err != nil {
		t.Fatalf("comparable chain %s: %v", base, err)
	}
	want := readFixture(t, filepath.Join(dir, base+".appraisal.json"))
	assertComparableMatch(t, base, got, want)
}

// runAARPSVIDFixture appraises an SVID fixture through the Go reference
// AppraiseWithSVID (envelope + sidecar) and asserts its ComparableAppraisal bytes
// match the committed appraisal. The sidecar is loaded from its on-disk wire form
// — the same bytes the four-language gate feeds every verifier via --svid.
func runAARPSVIDFixture(t *testing.T, dir, base, sidecarPath string, exp aarpExpect, opts aarp.VerifyOptions) {
	t.Helper()
	// SVID attacks are never envelope-fatal: a failed/absent binding withholds the
	// workload-identity claims, it never rejects the envelope. So every SVID
	// fixture must be labeled appraise; a fatal label is a corpus authoring bug.
	if exp.Verdict != verdictAppraise {
		t.Fatalf("svid fixture %s has verdict %q; SVID fixtures are always %q (an attack withholds claims, never fails the envelope)", base, exp.Verdict, verdictAppraise)
	}
	sc, err := svidsidecar.Parse(readFixture(t, sidecarPath))
	if err != nil {
		t.Fatalf("parse svid sidecar %s: %v", base, err)
	}
	body := readFixture(t, filepath.Join(dir, base+".aarp.json"))
	got := svidComparableBytes(t, body, sc, opts)
	want := readFixture(t, filepath.Join(dir, base+".appraisal.json"))
	assertComparableMatch(t, base, got, want)
}

// parseChainLines unmarshals one envelope per non-empty line. A parse error on
// any line is the chain-fatal signal (a malformed envelope in the stream).
func parseChainLines(body []byte) ([]aarp.Envelope, error) {
	var envs []aarp.Envelope
	for _, line := range bytes.Split(bytes.TrimSpace(body), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		e, err := aarp.Unmarshal(line)
		if err != nil {
			return nil, err
		}
		envs = append(envs, e)
	}
	return envs, nil
}

// assertComparableMatch compares got vs the committed appraisal bytes, tolerating
// only a single trailing newline difference (the committed files end in \n).
func assertComparableMatch(t *testing.T, base string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(bytes.TrimRight(got, "\n"), bytes.TrimRight(want, "\n")) {
		t.Errorf("comparable mismatch for %s:\n got: %s\nwant: %s", base,
			bytes.TrimRight(got, "\n"), bytes.TrimRight(want, "\n"))
	}
}

func readAARPExpect(t *testing.T, path string) aarpExpect {
	t.Helper()
	var exp aarpExpect
	unmarshalJSONFile(t, path, &exp)
	return exp
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return data
}

func unmarshalJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	data := readFixture(t, path)
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
}
