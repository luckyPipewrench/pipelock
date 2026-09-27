// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// The run-chain conformance fixture is real Go-written evidence: two process
// runs of base "proxy", each holding an ActionReceipt v1 chain and an
// EvidenceReceipt v2 chain, joined by a signed restart link.
const (
	fixtureRunChainsDir = "../../sdk/conformance/testdata/run-chains"
	fixtureRun1         = "proxy.run.03b13ee13e01e7f770480f62ea42f1fe"
	fixtureRun2         = "proxy.run.f7b327337534352a514bd0a256b1d1c0"
	fixtureReplayRun    = "proxy.run.00000000000000000000000000000000"
)

func fixtureSignerKey(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureRunChainsDir, "signer-key.hex"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// copyRunChainFixture copies the valid two-run fixture into a fresh directory.
func copyRunChainFixture(t *testing.T) string {
	t.Helper()
	src := filepath.Join(fixtureRunChainsDir, "valid")
	dst := t.TempDir()
	des, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if de.IsDir() || de.Name() == "expect.json" {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(src, de.Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if writeErr := os.WriteFile(filepath.Join(dst, de.Name()), data, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	return dst
}

func runFile(dir, session string) string {
	return filepath.Join(dir, "evidence-"+session+"-0.jsonl")
}

// evidenceLine is one recorder JSONL line with its detail kept as raw bytes,
// so an edit changes only what the test means to change.
type evidenceLine struct {
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

// rewriteEvidence applies edit to every line of path (returning false drops
// the line). With rehash it then recomputes the recorder entry hash chain,
// which needs no signing key: it models an attacker with write access only.
func rewriteEvidence(t *testing.T, path string, rehash bool, edit func(l *evidenceLine) bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var lines []evidenceLine
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var l evidenceLine
		if err := json.Unmarshal(raw, &l); err != nil {
			t.Fatal(err)
		}
		if edit(&l) {
			lines = append(lines, l)
		}
	}
	var out bytes.Buffer
	prev := recorder.GenesisHash
	for _, l := range lines {
		if rehash {
			l.PrevHash = prev
			l.Hash = recorder.ComputeHash(recorder.Entry{
				Version: l.Version, Sequence: l.Sequence, Timestamp: l.Timestamp, SessionID: l.SessionID,
				ChainKind: l.ChainKind, WriterInstanceID: l.WriterInstanceID, TraceID: l.TraceID,
				Type: l.Type, EventKind: l.EventKind, Transport: l.Transport, Summary: l.Summary,
				RawDetail: l.Detail, RawRef: l.RawRef, PrevHash: prev,
			})
			prev = l.Hash
		}
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

// forgeFirstEvidenceReceipt edits a signed field of the first v2 receipt, so
// its signature no longer verifies, and reports whether it found one.
func forgeFirstEvidenceReceipt(l *evidenceLine, done *bool) bool {
	if *done || l.Type != contractreceipt.EvidenceEntryType {
		return true
	}
	forged := bytes.Replace(l.Detail, []byte(`"actor":"`), []byte(`"actor":"x`), 1)
	if !bytes.Equal(forged, l.Detail) {
		l.Detail = forged
		*done = true
	}
	return true
}

func chainOf(t *testing.T, r BaseReport, session string) BaseChain {
	t.Helper()
	for _, c := range r.Chains {
		if c.Session == session {
			return c
		}
	}
	t.Fatalf("no chain %s in report", session)
	return BaseChain{}
}

func requireFinding(t *testing.T, r BaseReport, kind, session, detailPart string) {
	t.Helper()
	for _, f := range r.Findings {
		if f.Kind == kind && f.Session == session && strings.Contains(f.Detail, detailPart) {
			return
		}
	}
	t.Fatalf("want finding %s on %s containing %q, got %+v", kind, session, detailPart, r.Findings)
}

func TestVerifyBase_CleanFixtureVerifiesBothChains(t *testing.T) {
	dir := copyRunChainFixture(t)
	for name, keys := range map[string][]string{"pinned": {fixtureSignerKey(t)}, "unpinned": nil} {
		t.Run(name, func(t *testing.T) {
			r := mustVerifyBase(t, dir, BaseVerifyOptions{TrustedKeys: keys})
			if !r.Healthy() {
				t.Fatalf("clean fixture findings: %+v", r.Findings)
			}
			for _, s := range []string{fixtureRun1, fixtureRun2} {
				c := chainOf(t, r, s)
				if !c.Valid || c.Receipts == 0 || c.EvidenceReceipts == 0 {
					t.Fatalf("%s: valid=%v receipts=%d evidence=%d", s, c.Valid, c.Receipts, c.EvidenceReceipts)
				}
			}
		})
	}
}

// A forged EvidenceReceipt v2 with the recorder hash chain recomputed leaves
// every ActionReceipt v1 intact. The base check must still fail the run.
func TestVerifyBase_ForgedEvidenceReceiptFailsRun(t *testing.T) {
	for name, keys := range map[string]func(*testing.T) []string{
		"pinned":   func(t *testing.T) []string { return []string{fixtureSignerKey(t)} },
		"unpinned": func(*testing.T) []string { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			dir := copyRunChainFixture(t)
			done := false
			rewriteEvidence(t, runFile(dir, fixtureRun2), true, func(l *evidenceLine) bool { return forgeFirstEvidenceReceipt(l, &done) })
			if !done {
				t.Fatal("fixture has no evidence receipt to forge")
			}
			r := mustVerifyBase(t, dir, BaseVerifyOptions{TrustedKeys: keys(t)})
			requireFinding(t, r, FindingCorruptChain, fixtureRun2, "evidence receipt chain")
			if chainOf(t, r, fixtureRun2).Valid {
				t.Fatal("run with a forged v2 receipt reported valid")
			}
			if !chainOf(t, r, fixtureRun1).Valid {
				t.Fatal("untouched run reported invalid")
			}
		})
	}
}

// A run whose file holds only EvidenceReceipt v2 entries is verified as a v2
// chain, never passed as a chain with nothing to check.
func TestVerifyBase_EvidenceOnlyChainIsVerified(t *testing.T) {
	strip := func(l *evidenceLine) bool { return l.Type != recorderEntryType }
	t.Run("honest", func(t *testing.T) {
		dir := copyRunChainFixture(t)
		rewriteEvidence(t, runFile(dir, fixtureRun2), true, strip)
		r := mustVerifyBase(t, dir, BaseVerifyOptions{TrustedKeys: []string{fixtureSignerKey(t)}})
		c := chainOf(t, r, fixtureRun2)
		if !c.Valid || c.Receipts != 0 || c.EvidenceReceipts == 0 {
			t.Fatalf("v2-only run: valid=%v receipts=%d evidence=%d findings=%+v", c.Valid, c.Receipts, c.EvidenceReceipts, r.Findings)
		}
	})
	t.Run("forged", func(t *testing.T) {
		dir := copyRunChainFixture(t)
		done := false
		rewriteEvidence(t, runFile(dir, fixtureRun2), true, func(l *evidenceLine) bool {
			return strip(l) && forgeFirstEvidenceReceipt(l, &done)
		})
		r := mustVerifyBase(t, dir, BaseVerifyOptions{TrustedKeys: []string{fixtureSignerKey(t)}})
		requireFinding(t, r, FindingCorruptChain, fixtureRun2, "evidence receipt chain")
	})
}

// A v2 chain signed by a key outside the trusted set fails even when its own
// signatures verify.
func TestVerifyBase_EvidenceChainSignerMustBeTrusted(t *testing.T) {
	dir := copyRunChainFixture(t)
	other := strings.Repeat("ab", 32)
	r := mustVerifyBase(t, dir, BaseVerifyOptions{TrustedKeys: []string{other}})
	if r.Healthy() {
		t.Fatal("base verified under a key that signed nothing")
	}
	res := VerifyEvidenceChainTrusted(evidenceOf(t, dir, fixtureRun1), []string{other}, contractreceipt.ChainVerifyOptions{})
	if res.Valid || !strings.Contains(res.Error, "not in the trusted key set") {
		t.Fatalf("untrusted v2 signer: valid=%v error=%q", res.Valid, res.Error)
	}
	res = VerifyEvidenceChainTrusted(evidenceOf(t, dir, fixtureRun1), []string{other, strings.ToUpper(fixtureSignerKey(t))}, contractreceipt.ChainVerifyOptions{})
	if !res.Valid || !res.SignaturesVerified {
		t.Fatalf("trusted v2 signer in a multi-key set: valid=%v error=%q", res.Valid, res.Error)
	}
}

func evidenceOf(t *testing.T, dir, session string) []contractreceipt.EvidenceReceipt {
	t.Helper()
	entries, err := readSessionEntries(dir, session)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := contractreceipt.ExtractEvidenceReceiptsFromEntries(entries)
	if err != nil || len(ev) == 0 {
		t.Fatalf("extract evidence receipts: %v (n=%d)", err, len(ev))
	}
	return ev
}

// A file named for one run that holds another run's entries is not that
// run's evidence.
func TestVerifyBase_EntrySessionMismatchIsCorrupt(t *testing.T) {
	dir := copyRunChainFixture(t)
	data, err := os.ReadFile(runFile(dir, fixtureRun1))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runFile(dir, fixtureReplayRun), data, 0o600); err != nil {
		t.Fatal(err)
	}
	r := mustVerifyBase(t, dir, BaseVerifyOptions{TrustedKeys: []string{fixtureSignerKey(t)}})
	requireFinding(t, r, FindingCorruptChain, fixtureReplayRun, "does not match requested session")
	if chainOf(t, r, fixtureReplayRun).Valid {
		t.Fatal("misfiled run reported valid")
	}
}

// Replaying a run under a new session name, with session_id rewritten and the
// hash chain recomputed, passes every per-chain check. The signed run nonce it
// shares with the original is what gives it away.
func TestVerifyBase_DuplicateRunNonce(t *testing.T) {
	dir := copyRunChainFixture(t)
	data, err := os.ReadFile(runFile(dir, fixtureRun1))
	if err != nil {
		t.Fatal(err)
	}
	replay := runFile(dir, fixtureReplayRun)
	if err := os.WriteFile(replay, data, 0o600); err != nil {
		t.Fatal(err)
	}
	rewriteEvidence(t, replay, true, func(l *evidenceLine) bool {
		l.SessionID = fixtureReplayRun
		return true
	})
	r := mustVerifyBase(t, dir, BaseVerifyOptions{TrustedKeys: []string{fixtureSignerKey(t)}})
	if !chainOf(t, r, fixtureReplayRun).Valid {
		t.Fatalf("replayed chain should verify on its own; findings %+v", r.Findings)
	}
	// Either chain may carry the finding; it must name both.
	named := false
	for _, f := range r.Findings {
		pair := f.Session + " " + f.Detail
		if f.Kind == FindingDuplicateRunNonce && strings.Contains(pair, fixtureReplayRun) && strings.Contains(pair, fixtureRun1) {
			named = true
		}
	}
	if !named {
		t.Fatalf("duplicate_run_nonce must name both chains: %+v", r.Findings)
	}
	if n := findingKinds(r)[FindingDuplicateRunNonce]; n != 1 {
		t.Fatalf("want exactly one duplicate_run_nonce finding, got %d", n)
	}
	// Links-only mode (the evidence doctor) does not judge run identity.
	lo := mustVerifyBase(t, dir, BaseVerifyOptions{LinksOnly: true})
	if findingKinds(lo)[FindingDuplicateRunNonce] != 0 {
		t.Fatal("links-only mode reported a run nonce finding")
	}
}

func TestRunNonces(t *testing.T) {
	rs := []Receipt{
		{ActionRecord: ActionRecord{RunNonce: "b"}},
		{ActionRecord: ActionRecord{RunNonce: "a"}},
		{ActionRecord: ActionRecord{RunNonce: "b"}},
		{ActionRecord: ActionRecord{}},
	}
	got := runNonces(rs)
	if strings.Join(got, ",") != "a,b" {
		t.Fatalf("runNonces = %v", got)
	}
	if len(runNonces(nil)) != 0 {
		t.Fatal("no receipts, no nonce")
	}
}

func TestCheckRecorderFile(t *testing.T) {
	dir := copyRunChainFixture(t)
	entries, err := recorder.ReadEntries(runFile(dir, fixtureRun1))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckRecorderFile(filepath.Base(runFile(dir, fixtureRun1)), entries); err != nil {
		t.Fatalf("honest file: %v", err)
	}
	if err := CheckRecorderFile("receipts.jsonl", entries); err != nil {
		t.Fatalf("a name claiming no session is not checked for one: %v", err)
	}
	err = CheckRecorderFile(filepath.Base(runFile(dir, fixtureReplayRun)), entries)
	if err == nil || !strings.Contains(err.Error(), "does not match requested session") {
		t.Fatalf("misfiled entries: %v", err)
	}
	broken := append([]recorder.Entry(nil), entries...)
	broken[2].Summary += "x"
	err = CheckRecorderFile(filepath.Base(runFile(dir, fixtureRun1)), broken)
	if err == nil || !strings.Contains(err.Error(), "recorder entry hash chain") {
		t.Fatalf("edited entry: %v", err)
	}
}

func TestEvidenceChainPinRejectsMalformedDeclaredKey(t *testing.T) {
	ev := []contractreceipt.EvidenceReceipt{{Signature: contractreceipt.SignatureProof{SignerKeyID: "zz"}}}
	if _, err := EvidenceChainPin(ev, []string{"zz"}); err == nil {
		t.Fatal("a non-hex trusted key must not pin")
	}
	if res := VerifyEvidenceChainTrusted(ev, nil, contractreceipt.ChainVerifyOptions{}); res.Valid {
		t.Fatal("unpinned chain with a malformed declared signer verified")
	}
	if pin, err := EvidenceChainPin(nil, []string{"ab"}); pin != nil || err != nil {
		t.Fatal("empty chain pins nothing")
	}
}
