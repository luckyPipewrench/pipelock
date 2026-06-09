// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
	"github.com/luckyPipewrench/pipelock/internal/svidsidecar"
)

const (
	killSuiteAARPSuffix      = ".aarp.json"
	killSuiteAppraisalSuffix = ".appraisal.json"
	killSuiteExpectSuffix    = ".expect.json"
	killSuiteSVIDSuffix      = ".svid.json"
)

// This file is the Evidence Theater Kill Suite GATE. It is distinct from the
// four-language byte-match conformance test (TestAARPCorpus): that test proves
// every verifier emits identical bytes for a fixture; THIS test proves the bytes
// say the right thing — that for every hostile fixture the appraiser does NOT
// emit a verified claim broader than the evidence supports, and that it actively
// names the over-read it is refusing.
//
// The gate annotations live in each <name>.expect.json and are hand-authored, so
// the gate is independent of the generated .appraisal.json golden. If a future
// appraiser change inflated an over-broad claim into verified_claims, the golden
// would regenerate to "pass" the byte-match — but this gate, asserting a
// human-written must_not_verify, would still fail. That independence is the whole
// point: it is the tripwire a regeneration cannot launder past.

// killSuiteExpect is the kill-suite expect.json, including the hand-authored gate
// annotations. The base metadata mirrors aarpExpect; the gate fields are the
// security contract.
type killSuiteExpect struct {
	FixtureID              string   `json:"fixture_id"`
	Category               string   `json:"category"`
	InputFormat            string   `json:"input_format"`
	Verdict                string   `json:"verdict"`
	OverclaimNarrative     string   `json:"overclaim_narrative"`
	MustVerify             []string `json:"must_verify"`
	MustNotVerify          []string `json:"must_not_verify"`
	ExpectedOverclaimRisks []string `json:"expected_overclaim_risks"`
	ExpectedDoesNotAssert  []string `json:"expected_does_not_assert"`
	PipelockShaped         bool     `json:"pipelock_shaped"`
}

func TestKillSuiteOverclaimGate(t *testing.T) {
	t.Parallel()
	opts := aarpCorpusVerifyOptions()
	dir := filepath.Join(aarpCorpusDir, catKillSuite)

	files := readKillSuiteFiles(t, dir)
	assertKillSuiteComplete(t, files)
	if t.Failed() {
		return
	}

	var total, pipelockDowngrades int
	for _, base := range sortedKeys(files.expects) {
		exp := readKillSuiteExpect(t, filepath.Join(dir, base+killSuiteExpectSuffix))
		total++
		// A Pipelock-shaped fixture counts as a downgrade demonstration when it
		// actually refuses something: it forbids an over-broad verified claim or
		// raises an overclaim risk. A clean valid receipt with neither is a control,
		// not a downgrade.
		if exp.PipelockShaped && (len(exp.MustNotVerify) > 0 || len(exp.ExpectedOverclaimRisks) > 0) {
			pipelockDowngrades++
		}
		t.Run(base, func(t *testing.T) {
			t.Parallel()
			assertKillSuiteDowngrade(t, dir, base, exp, opts)
		})
	}

	if total == 0 {
		t.Fatal("no kill-suite fixtures found; corpus generation is broken (run -update-aarp)")
	}
	// The Evidence Theater Kill Suite contract (v2.7 spec done-state #5): at least
	// 20 hostile fixtures, of which at least 5 downgrade Pipelock-shaped evidence.
	// These thresholds are load-bearing — dropping below either silently weakens the
	// public proof, so the gate fails rather than letting the corpus shrink.
	const (
		minKillSuiteFixtures  = 20
		minPipelockDowngrades = 5
	)
	if total < minKillSuiteFixtures {
		t.Errorf("kill suite has %d fixtures; the contract requires at least %d hostile fixtures", total, minKillSuiteFixtures)
	}
	if pipelockDowngrades < minPipelockDowngrades {
		t.Errorf("kill suite downgrades %d Pipelock-shaped fixtures; the contract requires at least %d (Pipelock must prove it downgrades its own strongest evidence)", pipelockDowngrades, minPipelockDowngrades)
	}
}

// assertKillSuiteDowngrade appraises one kill-suite fixture with the Go reference
// verifier and enforces the hand-authored downgrade contract: no forbidden claim
// verifies, every expected overclaim risk is raised, and every expected
// does_not_assert negative is present.
func assertKillSuiteDowngrade(t *testing.T, dir, base string, exp killSuiteExpect, opts aarp.VerifyOptions) {
	t.Helper()
	// Kill-suite fixtures are always appraised: an overclaim withholds claims, it
	// never makes the envelope fatal. A fatal-labeled kill-suite fixture is an
	// authoring bug (there would be no appraisal to check the downgrade against).
	if exp.Verdict != verdictAppraise {
		t.Fatalf("kill-suite fixture %s has verdict %q; kill-suite fixtures are always %q", base, exp.Verdict, verdictAppraise)
	}

	ap := appraiseKillSuiteFixture(t, dir, base, opts)

	verified := toSet(ap.VerifiedClaims)
	// The genuine narrow facts MUST verify: a downgrade only means something when
	// real evidence is present and the broad reading is still refused. Asserting
	// this independently of the golden catches a "verifies nothing" regression that
	// would otherwise satisfy must_not_verify trivially.
	for _, claim := range exp.MustVerify {
		if _, ok := verified[claim]; !ok {
			t.Errorf("LOST EVIDENCE in %s: expected verified claim %q is absent; the fixture no longer demonstrates a downgrade of valid evidence.\n  verified_claims: %v",
				base, claim, ap.VerifiedClaims)
		}
	}
	for _, claim := range exp.MustNotVerify {
		if _, ok := verified[claim]; ok {
			t.Errorf("OVERCLAIM in %s: the appraiser emitted verified claim %q, which the evidence does not support.\n  narrative under test: %s\n  verified_claims: %v",
				base, claim, exp.OverclaimNarrative, ap.VerifiedClaims)
		}
	}

	risks := toSet(ap.OverclaimRisks)
	for _, want := range exp.ExpectedOverclaimRisks {
		if _, ok := risks[want]; !ok {
			t.Errorf("MISSING DOWNGRADE in %s: expected overclaim risk %q not raised.\n  overclaim_risks: %v", base, want, ap.OverclaimRisks)
		}
	}

	dna := toSet(ap.DoesNotAssert)
	for _, want := range exp.ExpectedDoesNotAssert {
		if _, ok := dna[want]; !ok {
			t.Errorf("MISSING NEGATIVE in %s: expected does_not_assert %q not present.\n  does_not_assert: %v", base, want, ap.DoesNotAssert)
		}
	}
}

// appraiseKillSuiteFixture appraises a kill-suite fixture (single envelope, with
// an optional SVID sidecar) through the Go reference verifier and returns the
// Appraisal. Kill-suite fixtures are never chains.
func appraiseKillSuiteFixture(t *testing.T, dir, base string, opts aarp.VerifyOptions) *aarp.Appraisal {
	t.Helper()
	body := readFixture(t, filepath.Join(dir, base+killSuiteAARPSuffix))
	env, err := aarp.Unmarshal(body)
	if err != nil {
		t.Fatalf("kill-suite fixture %s failed to unmarshal: %v", base, err)
	}

	sidecarPath := filepath.Join(dir, base+killSuiteSVIDSuffix)
	_, statErr := os.Stat(sidecarPath)
	// A real filesystem error (e.g. permissions) must fail loudly, not be silently
	// treated as "no sidecar" and fall through to the envelope path — that would
	// drop the SVID claims and could mask a downgrade the fixture exists to prove.
	if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("stat svid sidecar %s: %v", sidecarPath, statErr)
	}
	if statErr == nil {
		sc, err := svidsidecar.Parse(readFixture(t, sidecarPath))
		if err != nil {
			t.Fatalf("parse svid sidecar %s: %v", base, err)
		}
		svidOpts, err := sc.Options()
		if err != nil {
			t.Fatalf("svid sidecar verify block %s: %v", base, err)
		}
		ev := sc.Evidence
		ap, err := aarp.AppraiseWithSVID(env, &ev, opts, svidOpts)
		if err != nil {
			t.Fatalf("kill-suite svid fixture %s failed to appraise: %v", base, err)
		}
		return ap
	}

	ap, err := aarp.Verify(env, opts)
	if err != nil {
		t.Fatalf("kill-suite fixture %s failed to appraise: %v", base, err)
	}
	return ap
}

func readKillSuiteExpect(t *testing.T, path string) killSuiteExpect {
	t.Helper()
	var exp killSuiteExpect
	unmarshalJSONFile(t, path, &exp)
	return exp
}

type killSuiteFiles struct {
	envelopes  map[string]struct{}
	expects    map[string]struct{}
	appraisals map[string]struct{}
	sidecars   map[string]struct{}
}

func readKillSuiteFiles(t *testing.T, dir string) killSuiteFiles {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read kill-suite dir %s: %v (run -update-aarp)", dir, err)
	}

	files := killSuiteFiles{
		envelopes:  make(map[string]struct{}),
		expects:    make(map[string]struct{}),
		appraisals: make(map[string]struct{}),
		sidecars:   make(map[string]struct{}),
	}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case strings.HasSuffix(name, killSuiteAARPSuffix):
			files.envelopes[strings.TrimSuffix(name, killSuiteAARPSuffix)] = struct{}{}
		case strings.HasSuffix(name, killSuiteExpectSuffix):
			files.expects[strings.TrimSuffix(name, killSuiteExpectSuffix)] = struct{}{}
		case strings.HasSuffix(name, killSuiteAppraisalSuffix):
			files.appraisals[strings.TrimSuffix(name, killSuiteAppraisalSuffix)] = struct{}{}
		case strings.HasSuffix(name, killSuiteSVIDSuffix):
			files.sidecars[strings.TrimSuffix(name, killSuiteSVIDSuffix)] = struct{}{}
		}
	}
	return files
}

func assertKillSuiteComplete(t *testing.T, files killSuiteFiles) {
	t.Helper()
	for _, base := range sortedKeys(files.envelopes) {
		if _, ok := files.expects[base]; !ok {
			t.Errorf("kill-suite envelope %s is missing %s", base+killSuiteAARPSuffix, base+killSuiteExpectSuffix)
		}
		if _, ok := files.appraisals[base]; !ok {
			t.Errorf("kill-suite envelope %s is missing %s", base+killSuiteAARPSuffix, base+killSuiteAppraisalSuffix)
		}
	}
	for _, base := range sortedKeys(files.expects) {
		if _, ok := files.envelopes[base]; !ok {
			t.Errorf("kill-suite expectation %s has no matching %s", base+killSuiteExpectSuffix, base+killSuiteAARPSuffix)
		}
		if _, ok := files.appraisals[base]; !ok {
			t.Errorf("kill-suite expectation %s is missing %s", base+killSuiteExpectSuffix, base+killSuiteAppraisalSuffix)
		}
	}
	for _, base := range sortedKeys(files.appraisals) {
		if _, ok := files.envelopes[base]; !ok {
			t.Errorf("kill-suite appraisal %s has no matching %s", base+killSuiteAppraisalSuffix, base+killSuiteAARPSuffix)
		}
		if _, ok := files.expects[base]; !ok {
			t.Errorf("kill-suite appraisal %s has no matching %s", base+killSuiteAppraisalSuffix, base+killSuiteExpectSuffix)
		}
	}
	for _, base := range sortedKeys(files.sidecars) {
		if _, ok := files.envelopes[base]; !ok {
			t.Errorf("kill-suite SVID sidecar %s has no matching %s", base+killSuiteSVIDSuffix, base+killSuiteAARPSuffix)
		}
		if _, ok := files.expects[base]; !ok {
			t.Errorf("kill-suite SVID sidecar %s has no matching %s", base+killSuiteSVIDSuffix, base+killSuiteExpectSuffix)
		}
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// toSet builds a lookup set from a string slice.
func toSet(xs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		out[x] = struct{}{}
	}
	return out
}
