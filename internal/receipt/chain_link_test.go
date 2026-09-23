// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type testRun struct {
	rec     *recorder.Recorder
	e       *Emitter
	session string
}

// startRun opens a recorder in dir, acquires a fresh run session exactly as
// production does, and builds an emitter on it.
func startRun(t *testing.T, dir string, priv ed25519.PrivateKey) testRun {
	t.Helper()
	rec := newTestRecorder(t, dir, priv)
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatalf("AcquireRunSession: %v", err)
	}
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor, Session: session, Notices: io.Discard})
	if err := e.InitError(); err != nil {
		t.Fatalf("InitError: %v", err)
	}
	return testRun{rec: rec, e: e, session: session}
}

func (r testRun) openAndEmit(t *testing.T, n int) {
	t.Helper()
	if err := r.e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	for i := 0; i < n; i++ {
		emitOne(t, r.e)
	}
}

func (r testRun) close(t *testing.T) {
	t.Helper()
	if err := r.rec.Close(); err != nil {
		t.Fatalf("close recorder: %v", err)
	}
}

func sessionReceipts(t *testing.T, dir, session string) []Receipt {
	t.Helper()
	entries, err := readSessionEntries(dir, session)
	if err != nil {
		t.Fatalf("readSessionEntries: %v", err)
	}
	var out []Receipt
	for _, entry := range entries {
		if entry.Type != recorderEntryType {
			continue
		}
		r, err := receiptFromEntry(entry)
		if err != nil {
			t.Fatalf("receiptFromEntry: %v", err)
		}
		out = append(out, *r)
	}
	return out
}

func findingKinds(r BaseReport) map[string]int {
	out := map[string]int{}
	for _, f := range r.Findings {
		out[f.Kind]++
	}
	return out
}

func mustVerifyBase(t *testing.T, dir string, opts BaseVerifyOptions) BaseReport {
	t.Helper()
	r, err := VerifyBase(dir, recorder.DefaultSessionBase, opts)
	if err != nil {
		t.Fatalf("VerifyBase: %v", err)
	}
	return r
}

// TestResume_SameKeyValidTail_ResumesUnchanged was rewritten deliberately.
// It used to assert implicit continuity: a second process reopened the SAME
// session and extended its chain from seq 2. That is the behavior that forks
// when two processes share a session. A restart now owns a fresh run chain
// starting at genesis, and continuity to the first run is an explicit signed
// chain_link naming its exact tail.
func TestResume_SameKeyValidTail_ResumesUnchanged(t *testing.T) {
	dir := t.TempDir()
	pub, priv := generateTestKey(t)

	a := startRun(t, dir, priv)
	a.openAndEmit(t, 2)
	a.close(t)
	aReceipts := sessionReceipts(t, dir, a.session)
	aTail := aReceipts[len(aReceipts)-1]

	b := startRun(t, dir, priv)
	if b.e.chainSeq != 0 || b.e.hasPriorTail {
		t.Fatalf("restart must start a fresh chain at genesis, got seq %d prior=%v", b.e.chainSeq, b.e.hasPriorTail)
	}
	link := b.e.ChainLink()
	if link == nil {
		t.Fatal("restart must record a chain_link to the finished run")
	}
	if link.PredecessorSession != a.session || link.PredecessorTailSeq != aTail.ActionRecord.ChainSeq || link.PredecessorTailHash != mustHash(t, aTail) {
		t.Fatalf("link %+v does not name A's exact tail (seq %d)", link, aTail.ActionRecord.ChainSeq)
	}
	if link.PredecessorSignerKey != hex.EncodeToString(pub) || link.SuccessorSignerKey != hex.EncodeToString(pub) {
		t.Fatalf("link keys = %s -> %s", link.PredecessorSignerKey, link.SuccessorSignerKey)
	}
	b.openAndEmit(t, 1)
	b.close(t)

	bReceipts := sessionReceipts(t, dir, b.session)
	for i, r := range bReceipts {
		if r.ActionRecord.ChainSeq != uint64(i) || r.ActionRecord.KeyTransition != nil {
			t.Fatalf("B receipt %d: seq %d transition %v", i, r.ActionRecord.ChainSeq, r.ActionRecord.KeyTransition)
		}
	}
	report := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if !report.Healthy() || report.LinkCount() != 1 {
		t.Fatalf("base report: healthy=%v links=%d findings=%+v", report.Healthy(), report.LinkCount(), report.Findings)
	}
}

// TestEmitter_EmitSessionOpenRestartLinksPriorTail was rewritten deliberately.
// It used to assert that a restart's session_open carried prior_chain_head.
// A run chain now opens with an ordinary bound genesis session_open with NO
// prior tail (a genesis open with a prior tail is rejected by every verifier),
// and the link to the prior run lives in a signed chain_link recorder entry.
func TestEmitter_EmitSessionOpenRestartLinksPriorTail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pub, priv := generateTestKey(t)

	a := startRun(t, dir, priv)
	a.openAndEmit(t, 1)
	a.close(t)

	b := startRun(t, dir, priv)
	b.openAndEmit(t, 0)
	b.close(t)

	bReceipts := sessionReceipts(t, dir, b.session)
	open := bReceipts[0].ActionRecord.SessionControl.Open
	if open == nil || open.PriorChainHead != "" || open.PriorChainSeq != 0 || open.GenesisHash == "" {
		t.Fatalf("restart session_open must be a bound genesis with no prior tail: %+v", open)
	}
	if b.e.ChainLink() == nil || b.e.ChainLink().PredecessorSession != a.session {
		t.Fatal("restart must link to the prior run through chain_link")
	}
	// Deployed-verifier compatibility: the UNCHANGED single-chain path accepts
	// the run chain with no link awareness.
	if res := VerifyChainTrusted(bReceipts, []string{hex.EncodeToString(pub)}); !res.Valid {
		t.Fatalf("VerifyChainTrusted on run chain: %s", res.Error)
	}
	extracted, err := ExtractReceiptsFromSessionDir(dir, b.session)
	if err != nil {
		t.Fatalf("ExtractReceiptsFromSessionDir: %v", err)
	}
	if res := VerifyChain(extracted, hex.EncodeToString(pub)); !res.Valid {
		t.Fatalf("VerifyChain on extracted run chain: %s", res.Error)
	}
}

func TestChainLink_FirstRunStartsUnlinked(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a := startRun(t, dir, priv)
	defer a.close(t)
	if a.e.ChainLink() != nil {
		t.Fatal("first run has nothing to link")
	}
}

func TestChainLink_LivePredecessorNotClaimed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a := startRun(t, dir, priv)
	a.openAndEmit(t, 1)
	b := startRun(t, dir, priv) // A is still live
	if b.e.ChainLink() != nil {
		t.Fatal("a live writer's chain must not be claimed")
	}
	a.close(t)
	b.close(t)
}

func TestChainLink_CorruptPredecessorSkippedLoudly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	seedTamperedTail(t, dir, priv)

	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	var notices bytes.Buffer
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, Principal: testPrincipal, Actor: testActor, Session: session, Notices: &notices})
	if err := e.InitError(); err != nil {
		t.Fatalf("a corrupt predecessor must not brick the new run: %v", err)
	}
	if e.ChainLink() != nil {
		t.Fatal("a corrupt predecessor tail must not be linked")
	}
	if !strings.Contains(notices.String(), "corrupt tail") {
		t.Fatalf("expected a loud corrupt-tail notice, got %q", notices.String())
	}
	emitOne(t, e)
}

// seedTamperedTail writes a legacy "proxy" chain whose last receipt has a
// broken signature.
func seedTamperedTail(t *testing.T, dir string, priv ed25519.PrivateKey) {
	t.Helper()
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, Principal: testPrincipal, Actor: testActor})
	emitOne(t, e)
	_ = rec.Close()
	files, err := recorderFiles(dir, recorder.DefaultSessionBase)
	if err != nil || len(files) == 0 {
		t.Fatalf("legacy files: %v", err)
	}
	data, err := os.ReadFile(files[len(files)-1])
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(data, []byte(`"verdict":"block"`), []byte(`"verdict":"allow"`), 1)
	if bytes.Equal(tampered, data) {
		t.Fatal("tamper anchor not found")
	}
	if err := os.WriteFile(files[len(files)-1], tampered, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestChainLink_ConcurrentRestartAtMostOneSuccessor(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)

	// Three runs live at once leave three dead, unclaimed chains.
	dead := make([]testRun, 3)
	for i := range dead {
		dead[i] = startRun(t, dir, priv)
		dead[i].openAndEmit(t, 1)
	}
	for _, r := range dead {
		r.close(t)
	}

	// Five new runs race to claim them.
	var wg sync.WaitGroup
	runs := make([]testRun, 5)
	for i := range runs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			runs[i] = startRun(t, dir, priv)
		}(i)
	}
	wg.Wait()
	claimed := map[string]int{}
	for _, r := range runs {
		if l := r.e.ChainLink(); l != nil {
			claimed[l.PredecessorSession]++
		}
		r.openAndEmit(t, 1)
		r.close(t)
	}
	if len(claimed) != 3 {
		t.Fatalf("every dead chain should be claimed once, got %v", claimed)
	}
	for p, n := range claimed {
		if n != 1 {
			t.Fatalf("predecessor %s claimed %d times", p, n)
		}
	}
	report := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if !report.Healthy() || report.LinkCount() != 3 || len(report.Chains) != 8 {
		t.Fatalf("healthy=%v links=%d chains=%d findings=%+v", report.Healthy(), report.LinkCount(), len(report.Chains), report.Findings)
	}
}

func TestChainLink_MixedVersionLegacyWriter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)

	// An older binary records "proxy" without acquiring a run session.
	legacyRec := newTestRecorder(t, dir, priv)
	legacy := NewEmitter(EmitterConfig{Recorder: legacyRec, PrivKey: priv, Principal: testPrincipal, Actor: testActor})
	emitOne(t, legacy)
	run := startRun(t, dir, priv) // legacy is live: not claimable
	if run.e.ChainLink() != nil {
		t.Fatal("a live legacy writer must not be claimed")
	}
	run.openAndEmit(t, 2)
	emitOne(t, legacy)
	if err := legacyRec.Close(); err != nil {
		t.Fatal(err)
	}
	legacyBefore := sessionReceipts(t, dir, recorder.DefaultSessionBase)

	next := startRun(t, dir, priv) // run is still live, legacy is gone
	if l := next.e.ChainLink(); l == nil || l.PredecessorSession != recorder.DefaultSessionBase {
		t.Fatalf("a run may link to the finished legacy chain, got %+v", next.e.ChainLink())
	}
	next.openAndEmit(t, 1)
	run.close(t)
	next.close(t)
	if got := sessionReceipts(t, dir, recorder.DefaultSessionBase); len(got) != len(legacyBefore) {
		t.Fatalf("run writers appended to the legacy session: %d -> %d", len(legacyBefore), len(got))
	}
	report := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if !report.Healthy() {
		t.Fatalf("findings: %+v", report.Findings)
	}
}

func TestChainLink_LegacyForkReportedRunChainsClean(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	// Two older-binary writers share "proxy" and fork it.
	r1 := newTestRecorder(t, dir, priv)
	r2 := newTestRecorder(t, dir, priv)
	e1 := NewEmitter(EmitterConfig{Recorder: r1, PrivKey: priv, Principal: testPrincipal, Actor: testActor})
	e2 := NewEmitter(EmitterConfig{Recorder: r2, PrivKey: priv, Principal: testPrincipal, Actor: testActor})
	run := startRun(t, dir, priv)
	emitOne(t, e1)
	emitOne(t, e2)
	run.openAndEmit(t, 2)
	emitOne(t, e1)
	_ = r1.Close()
	_ = r2.Close()
	run.close(t)

	report := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if report.Healthy() {
		t.Fatal("a forked legacy chain must be reported")
	}
	for _, f := range report.Findings {
		if f.Session != recorder.DefaultSessionBase {
			t.Fatalf("run chain %s must never be part of a fork: %+v", f.Session, f)
		}
	}
}

func TestChainLink_KeyChangeTrust(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pubA, privA := generateTestKey(t)
	pubB, privB := generateTestKey(t)
	a := startRun(t, dir, privA)
	a.openAndEmit(t, 1)
	a.close(t)
	b := startRun(t, dir, privB)
	b.openAndEmit(t, 1)
	b.close(t)
	link := b.e.ChainLink()
	if link == nil {
		t.Fatal("B must link to A")
	}

	if r := mustVerifyBase(t, dir, BaseVerifyOptions{}); findingKinds(r)[FindingUntrustedSuccessorKey] != 1 {
		t.Fatalf("new key without trust or endorsement must be untrusted: %+v", r.Findings)
	}
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{TrustedKeys: []string{hex.EncodeToString(pubA)}}); r.Healthy() {
		t.Fatal("pinning only A must not trust B's chain")
	}
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{TrustedKeys: []string{hex.EncodeToString(pubA), hex.EncodeToString(pubB)}}); !r.Healthy() {
		t.Fatalf("both keys pinned: %+v", r.Findings)
	}
	endorse := func(seq uint64, hash string) RotationEndorsement {
		e, err := SignRotationEndorsement(RotationEndorsement{
			SessionID: a.session, PriorFinalSeq: seq, PriorTailHash: hash,
			NewSignerKey: hex.EncodeToString(pubB), RotatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}, privA)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	good := endorse(link.PredecessorTailSeq, link.PredecessorTailHash)
	r := mustVerifyBase(t, dir, BaseVerifyOptions{TrustedKeys: []string{hex.EncodeToString(pubA)}, Endorsements: []RotationEndorsement{good}})
	if !r.Healthy() {
		t.Fatalf("endorsed successor must be trusted: %+v", r.Findings)
	}
	for _, c := range r.Chains {
		if c.Session == b.session && c.LinkTrust != LinkTrustEndorsed {
			t.Fatalf("link trust = %q, want endorsed", c.LinkTrust)
		}
	}
	wrong := endorse(link.PredecessorTailSeq+1, link.PredecessorTailHash)
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{TrustedKeys: []string{hex.EncodeToString(pubA)}, Endorsements: []RotationEndorsement{wrong}}); r.Healthy() {
		t.Fatal("an endorsement binding a different tail must not trust B")
	}
	if err := VerifyCrossChainEndorsement(good, *link); err != nil {
		t.Fatalf("VerifyCrossChainEndorsement: %v", err)
	}
}

// linkedPair builds A -> B and returns both runs (closed).
func linkedPair(t *testing.T, dir string, priv ed25519.PrivateKey) (testRun, testRun) {
	t.Helper()
	a := startRun(t, dir, priv)
	a.openAndEmit(t, 2)
	a.close(t)
	b := startRun(t, dir, priv)
	b.openAndEmit(t, 1)
	b.close(t)
	if b.e.ChainLink() == nil {
		t.Fatal("B must link to A")
	}
	return a, b
}

func rewriteSessionFile(t *testing.T, dir, session string, edit func(lines [][]byte) [][]byte) {
	t.Helper()
	files, err := recorderFiles(dir, session)
	if err != nil || len(files) == 0 {
		t.Fatalf("files for %s: %v", session, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	out := bytes.Join(edit(lines), []byte("\n"))
	if err := os.WriteFile(files[0], append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func linkLineIndex(t *testing.T, lines [][]byte) int {
	t.Helper()
	for i, l := range lines {
		if bytes.Contains(l, []byte(`"type":"chain_link"`)) {
			return i
		}
	}
	t.Fatal("chain_link line not found")
	return -1
}

func TestChainLink_TamperDeleteLinkBreaksOuterChain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	_, b := linkedPair(t, dir, priv)
	rewriteSessionFile(t, dir, b.session, func(lines [][]byte) [][]byte {
		i := linkLineIndex(t, lines)
		return append(lines[:i:i], lines[i+1:]...)
	})
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{}); findingKinds(r)[FindingOuterChainBroken] == 0 {
		t.Fatalf("deleting the link entry must break the outer chain: %+v", r.Findings)
	}
}

// The recorder hash is unkeyed. A reader with write access to evidence can
// remove the first link and recompute the remaining envelope hashes while
// leaving the signed receipts untouched. This is a design reproduction, not
// an assertion that the current verifier should reject the resulting chain.
func TestChainLink_DeletionAndOuterRehashLooksUnlinked(t *testing.T) {
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	_, successor := linkedPair(t, dir, priv)
	before := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if !before.Healthy() || before.LinkCount() != 1 {
		t.Fatalf("positive control: healthy linked pair required: %+v", before)
	}
	rewriteSessionFile(t, dir, successor.session, func(lines [][]byte) [][]byte {
		link := linkLineIndex(t, lines)
		lines = append(lines[:link:link], lines[link+1:]...)
		prev := recorder.GenesisHash
		for i, line := range lines {
			var entry recorder.Entry
			if err := json.Unmarshal(line, &entry); err != nil {
				t.Fatal(err)
			}
			entry.Sequence = uint64(i)
			entry.PrevHash = prev
			entry.Hash = recorder.ComputeHash(entry)
			prev = entry.Hash
			var err error
			lines[i], err = json.Marshal(entry)
			if err != nil {
				t.Fatal(err)
			}
		}
		return lines
	})
	after := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if !after.Healthy() || after.LinkCount() != 0 {
		t.Fatalf("expected deletion to launder into an unlinked healthy pair; findings=%+v links=%d", after.Findings, after.LinkCount())
	}
}

func TestChainLink_TamperAlterLinkFailsSignature(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	_, b := linkedPair(t, dir, priv)
	rewriteSessionFile(t, dir, b.session, func(lines [][]byte) [][]byte {
		i := linkLineIndex(t, lines)
		lines[i] = bytes.Replace(lines[i], []byte(`"predecessor_tail_seq":2`), []byte(`"predecessor_tail_seq":1`), 1)
		return lines
	})
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{}); findingKinds(r)[FindingInvalidLink] == 0 {
		t.Fatalf("an altered link must fail its signature: %+v", r.Findings)
	}
	if _, err := UnmarshalChainLink([]byte(`{}`)); err == nil {
		t.Fatal("an empty link must not parse")
	}
}

// forgeRun records a successor-signed link naming pred's tail with the given
// hash as the first entry of a new run session, then emits one receipt.
func forgeRun(t *testing.T, dir string, priv ed25519.PrivateKey, pred string, seq uint64, hash, predKey string) {
	t.Helper()
	rec := newTestRecorder(t, dir, priv)
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	link, err := SignChainLink(ChainLink{
		PredecessorSession: pred, PredecessorTailSeq: seq, PredecessorTailHash: hash,
		PredecessorSignerKey: predKey, SuccessorSession: session,
		LinkedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(link)
	if err := rec.RecordDurable(recorder.Entry{SessionID: session, Type: ChainLinkEntryType, Detail: json.RawMessage(body)}); err != nil {
		t.Fatal(err)
	}
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, Principal: testPrincipal, Actor: testActor, Session: session, Notices: io.Discard})
	emitOne(t, e)
	_ = rec.Close()
}

func TestChainLink_ForgedSecondSuccessorIsFork(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a, b := linkedPair(t, dir, priv)
	l := b.e.ChainLink()
	forgeRun(t, dir, priv, a.session, l.PredecessorTailSeq, l.PredecessorTailHash, l.PredecessorSignerKey)
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{}); findingKinds(r)[FindingDoubleSuccessor] != 1 {
		t.Fatalf("two successors of one tail must be a fork finding: %+v", r.Findings)
	}
}

func TestChainLink_WrongTailIsMismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a := startRun(t, dir, priv)
	a.openAndEmit(t, 1)
	a.close(t)
	tail := sessionReceipts(t, dir, a.session)
	forgeRun(t, dir, priv, a.session, tail[len(tail)-1].ActionRecord.ChainSeq, strings.Repeat("ab", 32), tail[0].SignerKey)
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{}); findingKinds(r)[FindingLinkTailMismatch] != 1 {
		t.Fatalf("a link naming the wrong tail must be a mismatch: %+v", r.Findings)
	}
	forgeRun(t, dir, priv, recorder.DefaultSessionBase+".run."+strings.Repeat("0", 32), 0, strings.Repeat("ab", 32), tail[0].SignerKey)
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{}); findingKinds(r)[FindingDanglingLink] != 1 {
		t.Fatalf("a link to a missing chain must be dangling: %+v", r.Findings)
	}
}

func TestChainLink_AppendAfterLinkIsFinding(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a, _ := linkedPair(t, dir, priv)
	// Reopen A's own session (as a tamper or a misbehaving writer would) and
	// extend it past the linked tail.
	rec := newTestRecorder(t, dir, priv)
	if err := rec.AcquireSession(a.session); err != nil {
		t.Fatal(err)
	}
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, Principal: testPrincipal, Actor: testActor, Session: a.session, Notices: io.Discard})
	emitOne(t, e)
	_ = rec.Close()
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{}); findingKinds(r)[FindingAppendedAfterLink] != 1 {
		t.Fatalf("appending to a linked predecessor must be a finding: %+v", r.Findings)
	}
}

func TestChainLink_ForeignSessionOnAcquiredRecorderErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	defer func() { _ = rec.Close() }()
	if _, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase); err != nil {
		t.Fatal(err)
	}
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, Principal: testPrincipal, Actor: testActor})
	if err := e.Emit(EmitOpts{ActionID: NewActionID(), Target: testTarget, Verdict: "block", Transport: testTransport}); err == nil {
		t.Fatal("an emitter on a foreign session must be refused by the acquired recorder")
	}
}

func TestChainLink_SignVerifyValidation(t *testing.T) {
	t.Parallel()
	pub, priv := generateTestKey(t)
	base := ChainLink{
		PredecessorSession: "proxy", PredecessorTailSeq: 3, PredecessorTailHash: strings.Repeat("cd", 32),
		PredecessorSignerKey: hex.EncodeToString(pub), SuccessorSession: "proxy.run." + strings.Repeat("1", 32),
		LinkedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if _, err := SignChainLink(base, priv[:10]); err == nil {
		t.Fatal("short key must be refused")
	}
	bad := []func(l *ChainLink){
		func(l *ChainLink) { l.PredecessorSession = "" },
		func(l *ChainLink) { l.SuccessorSession = l.PredecessorSession },
		func(l *ChainLink) { l.PredecessorSignerKey = "zz" },
		func(l *ChainLink) { l.PredecessorTailHash = "zz" },
		func(l *ChainLink) { l.LinkedAt = "yesterday" },
	}
	for i, mutate := range bad {
		l := base
		mutate(&l)
		if _, err := SignChainLink(l, priv); err == nil {
			t.Fatalf("case %d: invalid link must be refused", i)
		}
	}
	signed, err := SignChainLink(base, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChainLink(signed); err != nil {
		t.Fatalf("VerifyChainLink: %v", err)
	}
	for i, sig := range []string{"", "nope", signaturePrefix + "zz", signaturePrefix + strings.Repeat("00", 64)} {
		l := signed
		l.Signature = sig
		if VerifyChainLink(l) == nil {
			t.Fatalf("signature case %d must fail", i)
		}
	}
	body, _ := json.Marshal(signed)
	if _, err := UnmarshalChainLink(append(body, []byte(`{}`)...)); err == nil {
		t.Fatal("trailing tokens must be refused")
	}
	if _, err := UnmarshalChainLink([]byte(`{"version":1,"version":1}`)); err == nil {
		t.Fatal("duplicate keys must be refused")
	}
	if _, ok := RunSessionBase("proxy"); ok {
		t.Fatal("plain session is not a run session")
	}
}

const (
	helperDirEnv  = "PIPELOCK_CHAIN_HELPER_DIR"
	helperKeyEnv  = "PIPELOCK_CHAIN_HELPER_KEY"
	helperIDEnv   = "PIPELOCK_CHAIN_HELPER_ID"
	helperNEnv    = "PIPELOCK_CHAIN_HELPER_N"
	helperProcs   = 12
	helperPerProc = 5
)

// TestChainLinkHelperProcess is re-executed as a separate OS process by
// TestChainLink_TwelveProcessesShareOneDirectory. It records a run chain,
// announces it is live, and keeps emitting only after every sibling has
// announced, so all twelve demonstrably make progress at the same time.
func TestChainLinkHelperProcess(t *testing.T) {
	dir := os.Getenv(helperDirEnv)
	if dir == "" {
		t.Skip("helper process only")
	}
	keyBytes, err := hex.DecodeString(os.Getenv(helperKeyEnv))
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.PrivateKey(keyBytes)
	n, _ := strconv.Atoi(os.Getenv(helperNEnv))
	r := startRun(t, dir, priv)
	r.openAndEmit(t, 1)
	ready := filepath.Join(filepath.Dir(dir), "ready")
	if err := os.WriteFile(filepath.Join(ready, os.Getenv(helperIDEnv)), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		des, _ := os.ReadDir(ready)
		if len(des) >= n {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("siblings never became live")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i := 0; i < helperPerProc; i++ {
		emitOne(t, r.e)
	}
	r.close(t)
}

func TestChainLink_TwelveProcessesShareOneDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "evidence")
	if err := os.MkdirAll(filepath.Join(root, "ready"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, priv := generateTestKey(t)
	var wg sync.WaitGroup
	errs := make([]error, helperProcs)
	outs := make([][]byte, helperProcs)
	for i := 0; i < helperProcs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestChainLinkHelperProcess$", "-test.count=1") //nolint:gosec // re-exec of this test binary
			cmd.Env = append(os.Environ(), helperDirEnv+"="+dir, helperKeyEnv+"="+hex.EncodeToString(priv),
				helperIDEnv+"="+strconv.Itoa(i), helperNEnv+"="+strconv.Itoa(helperProcs))
			outs[i], errs[i] = cmd.CombinedOutput()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("helper %d: %v\n%s", i, err, outs[i])
		}
		if !bytes.Contains(outs[i], []byte("PASS")) || bytes.Contains(outs[i], []byte("no tests to run")) {
			t.Fatalf("helper %d did not run the helper test:\n%s", i, outs[i])
		}
	}
	sessions, err := ResolveBaseSessions(dir, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != helperProcs {
		t.Fatalf("run chains = %d, want %d: %v", len(sessions), helperProcs, sessions)
	}
	for _, s := range sessions {
		receipts := sessionReceipts(t, dir, s)
		seen := map[uint64]bool{}
		for _, r := range receipts {
			if seen[r.ActionRecord.ChainSeq] {
				t.Fatalf("%s: duplicate chain_seq %d", s, r.ActionRecord.ChainSeq)
			}
			seen[r.ActionRecord.ChainSeq] = true
		}
		if len(receipts) != helperPerProc+2 {
			t.Fatalf("%s: %d receipts, want %d", s, len(receipts), helperPerProc+2)
		}
		if res := VerifyChainTrusted(receipts, []string{hex.EncodeToString(pub)}); !res.Valid {
			t.Fatalf("%s: %s", s, res.Error)
		}
	}
	report := mustVerifyBase(t, dir, BaseVerifyOptions{TrustedKeys: []string{hex.EncodeToString(pub)}})
	if !report.Healthy() || report.LinkCount() != 0 {
		t.Fatalf("concurrent live runs must neither fork nor link each other: links=%d findings=%+v", report.LinkCount(), report.Findings)
	}
}
