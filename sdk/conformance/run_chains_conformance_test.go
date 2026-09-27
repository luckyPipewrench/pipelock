// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// Run-chain fixtures are evidence directories written by real pipelock runs
// (see testdata/run-chains/generate.sh). Each variant directory carries an
// expect.json derived from the Go reference, receipt.VerifyBase, and every
// verifier's directory mode must reach the same verdict on it.
const (
	runChainsDir       = "testdata/run-chains"
	runChainsBase      = "proxy"
	runChainExpectFile = "expect.json"
	// runChainGoOnlyFinding is found from the recorder file's own entry hash
	// chain. Only the Go verifiers check that chain; the SDK verifiers check
	// the receipt chain inside it.
	runChainGoOnlyFinding = receipt.FindingOuterChainBroken
)

var runChainVariants = []string{
	"valid",
	"tampered-predecessor",
	"tampered-successor",
	"link-edited",
	"link-deleted",
	"double-successor",
	"link-wrong-tail",
	"link-appended",
	"key-rotated",
}

// runChainCase is one verification of a variant under one trust input. The
// key-rotated variant is checked three ways, because whether a restart that
// changed signing keys is trusted depends on what the verifier is given.
type runChainCase struct {
	variant    string
	expectFile string
	bothKeys   bool
	endorse    bool
}

func runChainCases() []runChainCase {
	cases := make([]runChainCase, 0, len(runChainVariants)+2)
	for _, v := range runChainVariants {
		cases = append(cases, runChainCase{variant: v, expectFile: runChainExpectFile})
	}
	return append(cases,
		runChainCase{variant: "key-rotated", expectFile: "expect-both-keys.json", bothKeys: true},
		runChainCase{variant: "key-rotated", expectFile: "expect-endorsed.json", endorse: true},
	)
}

type runChainExpect struct {
	Note     string               `json:"note"`
	Valid    bool                 `json:"valid"`
	Healthy  bool                 `json:"healthy"`
	Chains   []runChainExpectRun  `json:"chains"`
	Linked   []runChainExpectLink `json:"linked"`
	Unlinked []string             `json:"unlinked"`
	Findings []runChainExpectFind `json:"findings"`
}

type runChainExpectRun struct {
	Session string `json:"session"`
	Valid   bool   `json:"valid"`
}

type runChainExpectLink struct {
	Session            string `json:"session"`
	PredecessorSession string `json:"predecessor_session"`
	PredecessorTailSeq uint64 `json:"predecessor_tail_seq"`
	Trust              string `json:"trust"`
}

type runChainExpectFind struct {
	Kind    string `json:"kind"`
	Session string `json:"session"`
}

func runChainKeyFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(runChainsDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return strings.TrimSpace(string(data))
}

func runChainOptions(t *testing.T, c runChainCase) receipt.BaseVerifyOptions {
	t.Helper()
	opts := receipt.BaseVerifyOptions{TrustedKeys: []string{runChainKeyFile(t, "signer-key.hex")}}
	if c.bothKeys {
		opts.TrustedKeys = append(opts.TrustedKeys, runChainKeyFile(t, "rotated-signer-key.hex"))
	}
	if c.endorse {
		var e receipt.RotationEndorsement
		if err := json.Unmarshal([]byte(runChainKeyFile(t, filepath.Join(c.variant, "rotation-endorsement.json"))), &e); err != nil {
			t.Fatalf("decode endorsement: %v", err)
		}
		opts.Endorsements = []receipt.RotationEndorsement{e}
	}
	return opts
}

func runChainExpectFor(t *testing.T, c runChainCase) runChainExpect {
	t.Helper()
	dir := filepath.Join(runChainsDir, c.variant)
	report, err := receipt.VerifyBase(dir, runChainsBase, runChainOptions(t, c))
	if err != nil {
		t.Fatalf("VerifyBase %s: %v", dir, err)
	}
	exp := runChainExpect{
		Note:     "Generated from the Go reference (receipt.VerifyBase). outer_chain_broken comes from the recorder entry hash chain, which only the Go verifiers check.",
		Healthy:  report.Healthy(),
		Valid:    report.Healthy(),
		Linked:   []runChainExpectLink{},
		Unlinked: report.Unlinked(),
		Findings: []runChainExpectFind{},
	}
	if exp.Unlinked == nil {
		exp.Unlinked = []string{}
	}
	for _, c := range report.Chains {
		exp.Chains = append(exp.Chains, runChainExpectRun{Session: c.Session, Valid: c.Valid})
		if !c.Valid {
			exp.Valid = false
		}
		if c.Link != nil {
			exp.Linked = append(exp.Linked, runChainExpectLink{
				Session:            c.Session,
				PredecessorSession: c.Link.PredecessorSession,
				PredecessorTailSeq: c.Link.PredecessorTailSeq,
				Trust:              c.LinkTrust,
			})
		}
	}
	for _, f := range report.Findings {
		exp.Findings = append(exp.Findings, runChainExpectFind{Kind: f.Kind, Session: f.Session})
	}
	sort.Slice(exp.Findings, func(i, j int) bool {
		if exp.Findings[i].Kind != exp.Findings[j].Kind {
			return exp.Findings[i].Kind < exp.Findings[j].Kind
		}
		return exp.Findings[i].Session < exp.Findings[j].Session
	})
	return exp
}

// TestRunChainFixturesMatchGoReference fails when a fixture's expect.json no
// longer states what the Go reference concludes about that directory.
func TestRunChainFixturesMatchGoReference(t *testing.T) {
	for _, c := range runChainCases() {
		t.Run(c.variant+"/"+c.expectFile, func(t *testing.T) {
			got, err := json.MarshalIndent(runChainExpectFor(t, c), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join(runChainsDir, c.variant, c.expectFile))
			if err != nil {
				t.Fatalf("read expect: %v", err)
			}
			if !bytes.Equal(bytes.TrimSpace(want), got) {
				t.Fatalf("%s/%s is stale; regenerate with PIPELOCK_RUN_CHAIN_FIXTURES=1\nwant:\n%s\ngot:\n%s", c.variant, c.expectFile, want, got)
			}
		})
	}
}

// TestRunChainFixturesCoverEveryVerdict keeps the fixture set meaningful: it
// must hold passing and failing directories and each targeted finding kind.
func TestRunChainFixturesCoverEveryVerdict(t *testing.T) {
	want := map[string]string{
		"valid":                "",
		"link-deleted":         "",
		"tampered-predecessor": receipt.FindingCorruptChain,
		"tampered-successor":   receipt.FindingCorruptChain,
		"link-edited":          receipt.FindingInvalidLink,
		"double-successor":     receipt.FindingDoubleSuccessor,
		"link-wrong-tail":      receipt.FindingLinkTailMismatch,
		"link-appended":        receipt.FindingAppendedAfterLink,
		"key-rotated":          receipt.FindingUntrustedSuccessorKey,
	}
	for v, kind := range want {
		exp := runChainExpectFor(t, runChainCase{variant: v})
		if kind == "" {
			if !exp.Valid {
				t.Errorf("%s: want valid, got findings %+v", v, exp.Findings)
			}
			continue
		}
		if exp.Valid {
			t.Errorf("%s: want invalid", v)
		}
		found := false
		for _, f := range exp.Findings {
			found = found || f.Kind == kind
		}
		if !found {
			t.Errorf("%s: want finding %s, got %+v", v, kind, exp.Findings)
		}
	}
}

// TestGenerateRunChainFixtures writes the re-signed link variants and every
// expect.json. It runs only when PIPELOCK_RUN_CHAIN_FIXTURES=1, after
// generate.sh has produced the directories from a real pipelock binary.
func TestGenerateRunChainFixtures(t *testing.T) {
	if os.Getenv("PIPELOCK_RUN_CHAIN_FIXTURES") != "1" {
		t.Skip("set PIPELOCK_RUN_CHAIN_FIXTURES=1 to regenerate run-chain fixtures")
	}
	priv, err := signing.LoadPrivateKeyFile(filepath.Join(runChainsDir, "signing-key.test-only"))
	if err != nil {
		t.Fatalf("load test signing key: %v", err)
	}
	validDir := filepath.Join(runChainsDir, "valid")
	matches, err := filepath.Glob(filepath.Join(validDir, receipt.ChainLinkFilePrefix+"*"+receipt.ChainLinkFileSuffix))
	if err != nil || len(matches) != 1 {
		t.Fatalf("valid variant must hold exactly one link file: %v %v", matches, err)
	}
	var link receipt.ChainLink
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &link); err != nil {
		t.Fatal(err)
	}
	pred, err := receipt.ExtractReceiptsFromSessionDir(validDir, link.PredecessorSession)
	if err != nil || len(pred) < 2 {
		t.Fatalf("predecessor receipts: %d %v", len(pred), err)
	}

	// link-wrong-tail names a tail hash the predecessor never had.
	wrong := sha256.Sum256([]byte("not the predecessor tail"))
	writeResignedLinkVariant(t, "link-wrong-tail", validDir, link, link.PredecessorTailSeq, hex.EncodeToString(wrong[:]), priv)

	// link-appended names the predecessor's second-to-last receipt, as if
	// the predecessor kept writing after the successor linked it.
	earlier := pred[len(pred)-2]
	earlierHash, err := receipt.ReceiptHash(earlier)
	if err != nil {
		t.Fatal(err)
	}
	writeResignedLinkVariant(t, "link-appended", validDir, link, earlier.ActionRecord.ChainSeq, earlierHash, priv)

	for _, c := range runChainCases() {
		body, err := json.MarshalIndent(runChainExpectFor(t, c), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(runChainsDir, c.variant, c.expectFile), append(body, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func writeResignedLinkVariant(t *testing.T, name, validDir string, link receipt.ChainLink, seq uint64, hash string, priv []byte) {
	t.Helper()
	dst := filepath.Join(runChainsDir, name)
	if err := os.RemoveAll(dst); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o750); err != nil {
		t.Fatal(err)
	}
	shards, err := filepath.Glob(filepath.Join(validDir, "evidence-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range shards {
		data, readErr := os.ReadFile(filepath.Clean(s))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if writeErr := os.WriteFile(filepath.Join(dst, filepath.Base(s)), data, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	link.PredecessorTailSeq = seq
	link.PredecessorTailHash = hash
	signed, err := receipt.SignChainLink(link, priv)
	if err != nil {
		t.Fatalf("sign link: %v", err)
	}
	body, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, receipt.ChainLinkFileName(link.PredecessorSession)), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
