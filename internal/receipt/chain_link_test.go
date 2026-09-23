// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
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

// linkFiles returns the link file names in dir.
func linkFiles(t *testing.T, dir string) []string {
	t.Helper()
	names, err := chainLinkFileNames(dir)
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// assertNoLinkInChain proves the successor's chain file holds only entry types
// the shipped verifiers already accept: no link entry ever enters the chain.
func assertNoLinkInChain(t *testing.T, dir, session string) {
	t.Helper()
	entries, err := readSessionEntries(dir, session)
	if err != nil {
		t.Fatal(err)
	}
	for i, entry := range entries {
		if entry.Type != recorderEntryType && !knownRecorderEntryType(entry.Type) {
			t.Fatalf("%s entry %d has type %q outside the shipped taxonomy", session, i, entry.Type)
		}
		if strings.Contains(entry.Type, "link") {
			t.Fatalf("%s entry %d is a link entry %q", session, i, entry.Type)
		}
	}
}

// TestResume_SameKeyValidTail_ResumesUnchanged was rewritten deliberately.
// It used to assert implicit continuity: a second process reopened the SAME
// session and extended its chain from seq 2. That is the behavior that forks
// when two processes share a session. A restart now owns a fresh run chain
// starting at genesis, and continuity to the first run is an explicit signed
// link file naming its exact tail.
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
	if b.e.ChainLink() != nil {
		t.Fatal("the link is published at the first receipt, not at construction")
	}
	b.openAndEmit(t, 1)
	b.close(t)
	link := b.e.ChainLink()
	if link == nil {
		t.Fatal("restart must publish a link to the finished run")
	}
	if link.PredecessorSession != a.session || link.PredecessorTailSeq != aTail.ActionRecord.ChainSeq || link.PredecessorTailHash != mustHash(t, aTail) {
		t.Fatalf("link %+v does not name A's exact tail (seq %d)", link, aTail.ActionRecord.ChainSeq)
	}
	if link.PredecessorSignerKey != hex.EncodeToString(pub) || link.SuccessorSignerKey != hex.EncodeToString(pub) {
		t.Fatalf("link keys = %s -> %s", link.PredecessorSignerKey, link.SuccessorSignerKey)
	}

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
	if got := report.Unlinked(); !slices.Equal(got, []string{a.session}) {
		t.Fatalf("only the first run is unlinked, got %v", got)
	}
}

// TestEmitter_EmitSessionOpenRestartLinksPriorTail was rewritten deliberately.
// It used to assert that a restart's session_open carried prior_chain_head.
// A run chain now opens with an ordinary bound genesis session_open with NO
// prior tail (a genesis open with a prior tail is rejected by every verifier),
// and the link to the prior run lives in a signed file beside the chain.
func TestEmitter_EmitSessionOpenRestartLinksPriorTail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pub, priv := generateTestKey(t)

	a := startRun(t, dir, priv)
	a.openAndEmit(t, 1)
	a.close(t)
	aReceipts := sessionReceipts(t, dir, a.session)
	aTail := aReceipts[len(aReceipts)-1]

	b := startRun(t, dir, priv)
	b.openAndEmit(t, 0)
	b.close(t)

	bReceipts := sessionReceipts(t, dir, b.session)
	open := bReceipts[0].ActionRecord.SessionControl.Open
	if open == nil || open.PriorChainHead != "" || open.PriorChainSeq != 0 || open.GenesisHash == "" {
		t.Fatalf("restart session_open must be a bound genesis with no prior tail: %+v", open)
	}
	assertNoLinkInChain(t, dir, b.session)

	// The link file is named for the predecessor and names its exact tail.
	link, err := readChainLinkFile(filepath.Join(dir, ChainLinkFileName(a.session)))
	if err != nil {
		t.Fatalf("reading link file: %v", err)
	}
	if link.PredecessorSession != a.session || link.SuccessorSession != b.session ||
		link.PredecessorTailSeq != aTail.ActionRecord.ChainSeq || link.PredecessorTailHash != mustHash(t, aTail) {
		t.Fatalf("link file %+v does not name A's exact tail", link)
	}
	info, err := os.Stat(filepath.Join(dir, ChainLinkFileName(a.session)))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("link file mode: %v %v", info, err)
	}

	// Shipped-verifier compatibility: the UNCHANGED extraction and
	// single-chain paths accept the run chain with no link awareness.
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
	files, err := recorderFiles(dir, b.session)
	if err != nil || len(files) == 0 {
		t.Fatalf("run chain files: %v", err)
	}
	for _, f := range files {
		if _, err := ExtractReceipts(f); err != nil {
			t.Fatalf("ExtractReceipts(%s): %v", filepath.Base(f), err)
		}
	}
}

func TestChainLink_FirstRunStartsUnlinked(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a := startRun(t, dir, priv)
	a.openAndEmit(t, 1)
	a.close(t)
	if a.e.ChainLink() != nil || len(linkFiles(t, dir)) != 0 {
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
	b.openAndEmit(t, 1)
	if b.e.ChainLink() != nil || len(linkFiles(t, dir)) != 0 {
		t.Fatal("a live writer's chain must not be claimed")
	}
	a.close(t)
	b.close(t)
}

// A process that builds its emitter and exits before its first receipt must
// not leave a link naming a successor that never wrote anything.
func TestChainLink_NoLinkBeforeFirstReceipt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a := startRun(t, dir, priv)
	a.openAndEmit(t, 1)
	a.close(t)
	b := startRun(t, dir, priv)
	b.close(t)
	if len(linkFiles(t, dir)) != 0 {
		t.Fatal("no link may be published before the first receipt")
	}
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{}); !r.Healthy() {
		t.Fatalf("an emitter that never emitted must leave no finding: %+v", r.Findings)
	}
}

func TestChainLink_RejectedFirstReceiptLeavesNoClaim(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a := startRun(t, dir, priv)
	a.openAndEmit(t, 1)
	a.close(t)
	b := startRun(t, dir, priv)
	if err := b.e.Emit(EmitOpts{ActionID: NewActionID(), PolicyHash: "invalid"}); err == nil {
		t.Fatal("invalid policy hash must reject the first receipt")
	}
	if links := linkFiles(t, dir); len(links) != 0 {
		t.Fatalf("rejected first receipt claimed a predecessor: %v", links)
	}
	if receipts := sessionReceipts(t, dir, b.session); len(receipts) != 0 {
		t.Fatalf("rejected first receipt wrote %d receipts", len(receipts))
	}
	if err := b.e.EmitSessionOpen(); err != nil {
		t.Fatalf("valid first receipt after rejection: %v", err)
	}
	if links := linkFiles(t, dir); len(links) != 1 {
		t.Fatalf("successful first receipt should claim the predecessor, got %v", links)
	}
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
	emitOne(t, e)
	if e.ChainLink() != nil || len(linkFiles(t, dir)) != 0 {
		t.Fatal("a corrupt predecessor tail must not be linked")
	}
	if !strings.Contains(notices.String(), "corrupt tail") {
		t.Fatalf("expected a loud corrupt-tail notice, got %q", notices.String())
	}
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

	// Three runs live at once leave three dead, unlinked chains.
	dead := make([]testRun, 3)
	for i := range dead {
		dead[i] = startRun(t, dir, priv)
		dead[i].openAndEmit(t, 1)
	}
	for _, r := range dead {
		r.close(t)
	}

	// Five new runs race to continue them, all live at once.
	var wg sync.WaitGroup
	runs := make([]testRun, 5)
	runErrors := make([]error, len(runs))
	for i := range runs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
			if err != nil {
				runErrors[i] = fmt.Errorf("recorder.New: %w", err)
				return
			}
			session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
			if err != nil {
				runErrors[i] = fmt.Errorf("AcquireRunSession: %w", err)
				_ = rec.Close()
				return
			}
			e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor, Session: session, Notices: io.Discard})
			if err := e.InitError(); err != nil {
				runErrors[i] = fmt.Errorf("InitError: %w", err)
				_ = rec.Close()
				return
			}
			if err := e.EmitSessionOpen(); err != nil {
				runErrors[i] = fmt.Errorf("EmitSessionOpen: %w", err)
				_ = rec.Close()
				return
			}
			if err := e.Emit(EmitOpts{ActionID: NewActionID(), Target: testTarget, Verdict: config.ActionBlock, Transport: testTransport, Method: http.MethodGet}); err != nil {
				runErrors[i] = fmt.Errorf("Emit: %w", err)
				_ = rec.Close()
				return
			}
			runs[i] = testRun{rec: rec, e: e, session: session}
		}(i)
	}
	wg.Wait()
	for i, err := range runErrors {
		if err != nil {
			for _, r := range runs {
				if r.rec != nil {
					_ = r.rec.Close()
				}
			}
			t.Fatalf("run %d setup: %v", i, err)
		}
	}
	claimed := map[string]int{}
	for _, r := range runs {
		if l := r.e.ChainLink(); l != nil {
			claimed[l.PredecessorSession]++
		}
		r.close(t)
	}
	if len(claimed) != 3 {
		t.Fatalf("every dead chain should be continued once, got %v", claimed)
	}
	for p, n := range claimed {
		if n != 1 {
			t.Fatalf("predecessor %s continued %d times", p, n)
		}
	}
	if got := linkFiles(t, dir); len(got) != 3 {
		t.Fatalf("link files = %v, want 3", got)
	}
	report := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if !report.Healthy() || report.LinkCount() != 3 || len(report.Chains) != 8 || len(report.Unlinked()) != 5 {
		t.Fatalf("healthy=%v links=%d chains=%d unlinked=%v findings=%+v", report.Healthy(), report.LinkCount(), len(report.Chains), report.Unlinked(), report.Findings)
	}
}

func TestChainLink_RotationDoesNotExposeLiveRunAsPredecessor(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000, MaxEntriesPerFile: 1}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor, Session: session, Notices: io.Discard})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	if rec.SessionID() != session {
		t.Fatal("run session changed during rotation")
	}
	files, err := recorderFiles(dir, session)
	if err != nil || len(files) == 0 {
		t.Fatalf("predecessor files: %v", err)
	}
	if gone, err := recorder.EvidenceWriterGone(files[len(files)-1]); err != nil || !gone {
		t.Fatalf("old shard probe should expose rotation gap: gone=%v err=%v", gone, err)
	}
	if gone, err := recorder.EvidenceRunWriterGone(dir, session); err != nil || gone {
		t.Fatalf("run presence must survive rotation: gone=%v err=%v", gone, err)
	}
	other := startRun(t, dir, priv)
	other.openAndEmit(t, 1)
	if other.e.ChainLink() != nil {
		t.Fatal("live rotating run was claimed")
	}
	other.close(t)
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if gone, err := recorder.EvidenceRunWriterGone(dir, session); err != nil || !gone {
		t.Fatalf("closed run should be claimable: gone=%v err=%v", gone, err)
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
	run := startRun(t, dir, priv)
	run.openAndEmit(t, 2) // legacy is live: not claimable
	if run.e.ChainLink() != nil {
		t.Fatal("a live legacy writer must not be claimed")
	}
	emitOne(t, legacy)
	if err := legacyRec.Close(); err != nil {
		t.Fatal(err)
	}
	legacyBefore := sessionReceipts(t, dir, recorder.DefaultSessionBase)

	next := startRun(t, dir, priv) // run is still live, legacy is gone
	next.openAndEmit(t, 1)
	if l := next.e.ChainLink(); l == nil || l.PredecessorSession != recorder.DefaultSessionBase {
		t.Fatalf("a run may link to the finished legacy chain, got %+v", next.e.ChainLink())
	}
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
	// Links-only mode (the doctor) does not judge key trust.
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{LinksOnly: true}); !r.Healthy() || r.LinkCount() != 1 {
		t.Fatalf("links-only must not flag an honest key change: %+v", r.Findings)
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
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{Endorsements: []RotationEndorsement{good}}); !r.Healthy() {
		t.Fatalf("unpinned cross-chain endorsement must authorize structural continuity: %+v", r.Findings)
	}
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

// TestChainLink_DeletedLinkFileLeavesSuccessorUnlinked replaces the two
// in-chain tests (TestChainLink_TamperDeleteLinkBreaksOuterChain and
// TestChainLink_DeletionAndOuterRehashLooksUnlinked). It pins the documented
// limit: deleting a link file is NOT detected. The successor must then be
// reported UNLINKED, and must never be presented as a finding-free linked
// pair.
func TestChainLink_DeletedLinkFileLeavesSuccessorUnlinked(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a, b := linkedPair(t, dir, priv)
	before := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if !before.Healthy() || before.LinkCount() != 1 || slices.Contains(before.Unlinked(), b.session) {
		t.Fatalf("positive control: a healthy linked pair is required: %+v", before)
	}
	if err := os.Remove(filepath.Join(dir, ChainLinkFileName(a.session))); err != nil {
		t.Fatal(err)
	}
	after := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if after.LinkCount() != 0 {
		t.Fatalf("a deleted link must not still count as linked: %+v", after)
	}
	if !slices.Contains(after.Unlinked(), b.session) || !slices.Contains(after.Unlinked(), a.session) {
		t.Fatalf("both runs must be reported unlinked after deletion, got %v", after.Unlinked())
	}
	if !after.Healthy() {
		t.Fatalf("deletion is the documented undetected limit, not a finding: %+v", after.Findings)
	}
}

// writeLinkFile writes raw bytes as a link file under name.
func writeLinkFile(t *testing.T, dir, name string, body []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestChainLink_AlteredLinkFieldFailsSignature replaces
// TestChainLink_TamperAlterLinkFailsSignature (which edited the in-chain
// entry). Every signed field is altered in the sidecar in turn.
func TestChainLink_AlteredLinkFieldFailsSignature(t *testing.T) {
	t.Parallel()
	fields := map[string]any{
		"predecessor_tail_seq":   float64(1),
		"predecessor_tail_hash":  strings.Repeat("ab", 32),
		"predecessor_signer_key": strings.Repeat("11", 32),
		"successor_session":      recorder.DefaultSessionBase + ".run." + strings.Repeat("e", 32),
		"successor_signer_key":   strings.Repeat("22", 32),
		"linked_at":              "2020-01-01T00:00:00Z",
		"signature":              signaturePrefix + strings.Repeat("00", 64),
	}
	for field, value := range fields {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			_, priv := generateTestKey(t)
			a, b := linkedPair(t, dir, priv)
			name := ChainLinkFileName(a.session)
			raw, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name)))
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			if m[field] == value {
				t.Fatalf("mutation of %s is a no-op", field)
			}
			m[field] = value
			altered, _ := json.Marshal(m)
			writeLinkFile(t, dir, name, altered)
			r := mustVerifyBase(t, dir, BaseVerifyOptions{})
			if findingKinds(r)[FindingInvalidLink] == 0 {
				t.Fatalf("altering %s must fail the link: %+v", field, r.Findings)
			}
			if r.LinkCount() != 0 || !slices.Contains(r.Unlinked(), b.session) {
				t.Fatalf("an invalid link must not link B: links=%d unlinked=%v", r.LinkCount(), r.Unlinked())
			}
		})
	}
}

func TestChainLink_RenamedLinkFileIsFinding(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a, b := linkedPair(t, dir, priv)
	other := recorder.DefaultSessionBase + ".run." + strings.Repeat("c", 32)
	if err := os.Rename(filepath.Join(dir, ChainLinkFileName(a.session)), filepath.Join(dir, ChainLinkFileName(other))); err != nil {
		t.Fatal(err)
	}
	r := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if findingKinds(r)[FindingLinkNameMismatch] != 1 {
		t.Fatalf("a link file published under another predecessor's name must be a finding: %+v", r.Findings)
	}
	for _, f := range r.Findings {
		if f.Kind == FindingLinkNameMismatch && f.Session != other {
			t.Fatalf("finding must name the file's claimed predecessor %q, got %+v", other, f)
		}
	}
	_ = b
}

// forgeLink signs a link with priv and writes it under name.
func forgeLink(t *testing.T, dir, name string, l ChainLink, priv ed25519.PrivateKey) {
	t.Helper()
	l.LinkedAt = time.Now().UTC().Format(time.RFC3339Nano)
	signed, err := SignChainLink(l, priv)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(signed)
	writeLinkFile(t, dir, name, body)
}

func TestChainLink_WrongTailIsMismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a := startRun(t, dir, priv)
	a.openAndEmit(t, 1)
	a.close(t)
	tail := sessionReceipts(t, dir, a.session)
	c := startRun(t, dir, priv)
	// The forged file takes A's name first, so C's own publish finds A taken.
	forgeLink(t, dir, ChainLinkFileName(a.session), ChainLink{
		PredecessorSession: a.session, PredecessorTailSeq: tail[len(tail)-1].ActionRecord.ChainSeq,
		PredecessorTailHash: strings.Repeat("ab", 32), PredecessorSignerKey: tail[0].SignerKey, SuccessorSession: c.session,
	}, priv)
	c.openAndEmit(t, 0)
	c.close(t)
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{}); findingKinds(r)[FindingLinkTailMismatch] != 1 {
		t.Fatalf("a link naming the wrong tail must be a mismatch: %+v", r.Findings)
	}
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{LinksOnly: true}); findingKinds(r)[FindingLinkTailMismatch] != 1 {
		t.Fatalf("links-only must catch a wrong tail too: %+v", r.Findings)
	}
}

func TestChainLink_DanglingLinks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a := startRun(t, dir, priv)
	a.openAndEmit(t, 1)
	a.close(t)
	tail := sessionReceipts(t, dir, a.session)
	key := tail[0].SignerKey
	missing := recorder.DefaultSessionBase + ".run." + strings.Repeat("0", 32)

	// Predecessor absent: the successor exists (A), the predecessor does not.
	forgeLink(t, dir, ChainLinkFileName(missing), ChainLink{
		PredecessorSession: missing, PredecessorTailHash: strings.Repeat("ab", 32), PredecessorSignerKey: key, SuccessorSession: a.session,
	}, priv)
	r := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if findingKinds(r)[FindingDanglingLink] != 1 {
		t.Fatalf("a link to a missing predecessor must be dangling: %+v", r.Findings)
	}
	if err := os.Remove(filepath.Join(dir, ChainLinkFileName(missing))); err != nil {
		t.Fatal(err)
	}

	// Successor absent: the predecessor (A) exists, the successor never wrote.
	forgeLink(t, dir, ChainLinkFileName(a.session), ChainLink{
		PredecessorSession: a.session, PredecessorTailSeq: tail[len(tail)-1].ActionRecord.ChainSeq,
		PredecessorTailHash: mustHash(t, tail[len(tail)-1]), PredecessorSignerKey: key, SuccessorSession: missing,
	}, priv)
	r = mustVerifyBase(t, dir, BaseVerifyOptions{})
	if findingKinds(r)[FindingDanglingLink] != 1 {
		t.Fatalf("a link to a missing successor must be dangling: %+v", r.Findings)
	}
	if r = mustVerifyBase(t, dir, BaseVerifyOptions{LinksOnly: true}); findingKinds(r)[FindingDanglingLink] != 1 {
		t.Fatalf("links-only must report a dangling successor: %+v", r.Findings)
	}
}

func TestChainLink_SecondLinkForOnePredecessorIsDoubleSuccessor(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a, b := linkedPair(t, dir, priv)
	l := b.e.ChainLink()
	c := startRun(t, dir, priv)
	c.openAndEmit(t, 0) // C continues B, the only gone and unlinked chain
	c.close(t)
	// A second link for A, published under another name.
	forgeLink(t, dir, ChainLinkFileName(recorder.DefaultSessionBase+".run."+strings.Repeat("f", 32)), ChainLink{
		PredecessorSession: a.session, PredecessorTailSeq: l.PredecessorTailSeq, PredecessorTailHash: l.PredecessorTailHash,
		PredecessorSignerKey: l.PredecessorSignerKey, SuccessorSession: c.session,
	}, priv)
	r := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if findingKinds(r)[FindingDoubleSuccessor] != 1 {
		t.Fatalf("two links naming one predecessor must be a double successor: %+v", r.Findings)
	}
	if r = mustVerifyBase(t, dir, BaseVerifyOptions{LinksOnly: true}); findingKinds(r)[FindingDoubleSuccessor] != 1 {
		t.Fatalf("links-only must report a double successor: %+v", r.Findings)
	}
}

func TestChainLink_MalformedLinkFileIsFinding(t *testing.T) {
	t.Parallel()
	cases := map[string]func(t *testing.T, dir, name string){
		"truncated": func(t *testing.T, dir, name string) {
			raw, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name)))
			if err != nil {
				t.Fatal(err)
			}
			writeLinkFile(t, dir, name, raw[:len(raw)/2])
		},
		"garbage": func(t *testing.T, dir, name string) { writeLinkFile(t, dir, name, []byte("\x00not json\xff")) },
		"empty":   func(t *testing.T, dir, name string) { writeLinkFile(t, dir, name, nil) },
		"oversized": func(t *testing.T, dir, name string) {
			writeLinkFile(t, dir, name, bytes.Repeat([]byte(" "), maxChainLinkFileBytes+1))
		},
		"directory": func(t *testing.T, dir, name string) {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, name), 0o750); err != nil {
				t.Fatal(err)
			}
		},
	}
	for label, mutate := range cases {
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			_, priv := generateTestKey(t)
			a, b := linkedPair(t, dir, priv)
			mutate(t, dir, ChainLinkFileName(a.session))
			for _, linksOnly := range []bool{false, true} {
				r := mustVerifyBase(t, dir, BaseVerifyOptions{LinksOnly: linksOnly})
				if findingKinds(r)[FindingInvalidLink] != 1 {
					t.Fatalf("linksOnly=%v: a %s link file must be a finding: %+v", linksOnly, label, r.Findings)
				}
				if slices.Contains(r.Unlinked(), a.session) && !slices.Contains(r.Unlinked(), b.session) {
					t.Fatalf("B must not count as linked through a malformed file")
				}
			}
		})
	}
}

// A symlinked link file is never followed: it is a finding.
func TestChainLink_SymlinkedLinkFileIsFinding(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a, _ := linkedPair(t, dir, priv)
	name := ChainLinkFileName(a.session)
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.Rename(filepath.Join(dir, name), target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	r := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if findingKinds(r)[FindingInvalidLink] != 1 || r.LinkCount() != 0 {
		t.Fatalf("a symlinked link file must be a finding and link nothing: %+v", r.Findings)
	}
}

// The link path must not inherit the capped query-path ceiling: a directory
// past it still links on restart and verifies completely.
func TestChainLink_WorksPastEvidenceReadCeiling(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	for i := 0; i <= recorder.MaxEvidenceReadDirectoryEntries; i++ {
		writeLinkFile(t, dir, fmt.Sprintf("unrelated-%04d.txt", i), nil)
	}
	if _, err := recorder.ListSessions(dir); err == nil {
		t.Fatal("positive control: the capped listing must refuse this directory")
	}
	_, b := linkedPair(t, dir, priv)
	r := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if !r.Healthy() || r.LinkCount() != 1 || slices.Contains(r.Unlinked(), b.session) {
		t.Fatalf("past the ceiling: links=%d findings=%+v", r.LinkCount(), r.Findings)
	}
	if bases, err := ContinuityBases(dir); err != nil || len(bases) != 1 {
		t.Fatalf("ContinuityBases past the ceiling: %v %v", bases, err)
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
	for _, linksOnly := range []bool{false, true} {
		if r := mustVerifyBase(t, dir, BaseVerifyOptions{LinksOnly: linksOnly}); findingKinds(r)[FindingAppendedAfterLink] != 1 {
			t.Fatalf("linksOnly=%v: appending to a linked predecessor must be a finding: %+v", linksOnly, r.Findings)
		}
	}
}

func TestChainLink_LinksOnlyCorruptPredecessorTail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a, _ := linkedPair(t, dir, priv)
	files, err := recorderFiles(dir, a.session)
	if err != nil || len(files) == 0 {
		t.Fatal(err)
	}
	data, err := os.ReadFile(files[len(files)-1])
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	last := -1
	for i, line := range lines {
		if bytes.Contains(line, []byte(`"verdict":"block"`)) {
			last = i
		}
	}
	if last < 0 {
		t.Fatal("tamper anchor not found")
	}
	tampered := bytes.Replace(lines[last], []byte(`"verdict":"block"`), []byte(`"verdict":"allow"`), 1)
	lines[last] = tampered
	if err := os.WriteFile(files[len(files)-1], append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{LinksOnly: true}); findingKinds(r)[FindingPredecessorUnverified] != 1 {
		t.Fatalf("a predecessor with a forged tail must not verify a link: %+v", r.Findings)
	}
}

// Exclusive publish: many concurrent publishers of one name produce exactly
// one complete link file and leave no temp file behind.
func TestChainLink_PublishIsExclusive(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const n = 32
	name := ChainLinkFileName("proxy.run." + strings.Repeat("a", 32))
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			body := bytes.Repeat([]byte{byte('A' + i%26)}, 4096)
			errs[i] = publishChainLinkFile(dir, name, append(body, byte('0'+i%10)))
		}(i)
	}
	close(start)
	wg.Wait()
	won := 0
	for i, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, errLinkNameTaken):
			t.Fatalf("publisher %d: %v", i, err)
		}
	}
	if won != 1 {
		t.Fatalf("exactly one publisher must win, got %d", won)
	}
	got, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4097 || !bytes.Equal(got[:4096], bytes.Repeat(got[:1], 4096)) {
		t.Fatalf("published file is not one complete body (len %d)", len(got))
	}
	des, _ := os.ReadDir(dir)
	if len(des) != 1 {
		names := make([]string, 0, len(des))
		for _, de := range des {
			names = append(names, de.Name())
		}
		t.Fatalf("temp files left behind: %v", names)
	}
}

// A temp file left by a crash before os.Link never appears as a link.
func TestChainLink_LeftoverTempFileIsNotALink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a := startRun(t, dir, priv)
	a.openAndEmit(t, 1)
	a.close(t)
	tail := sessionReceipts(t, dir, a.session)
	c := startRun(t, dir, priv)
	signed, err := SignChainLink(ChainLink{
		PredecessorSession: a.session, PredecessorTailSeq: tail[len(tail)-1].ActionRecord.ChainSeq,
		PredecessorTailHash: mustHash(t, tail[len(tail)-1]), PredecessorSignerKey: tail[0].SignerKey,
		SuccessorSession: c.session, LinkedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(signed)
	writeLinkFile(t, dir, ".chain-link-123456.tmp", body)
	if bases, err := ContinuityBases(dir); err != nil || !slices.Equal(bases, []string{recorder.DefaultSessionBase}) {
		t.Fatalf("ContinuityBases = %v, %v", bases, err)
	}
	r := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if !r.Healthy() || r.LinkCount() != 0 {
		t.Fatalf("a leftover temp file must be neither a link nor a finding: links=%d findings=%+v", r.LinkCount(), r.Findings)
	}
	// The leftover does not block a real publish either.
	c.openAndEmit(t, 0)
	c.close(t)
	if l := c.e.ChainLink(); l == nil || l.PredecessorSession != a.session {
		t.Fatalf("a real publish must still succeed past a leftover temp file: %+v", l)
	}
}

// A publish failure other than EEXIST starts the run unlinked, says why, and
// leaves neither a link nor a temp file. Not parallel: it swaps linkFile.
func TestChainLink_LinkFailureStartsUnlinked(t *testing.T) {
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a := startRun(t, dir, priv)
	a.openAndEmit(t, 1)
	a.close(t)

	orig := linkFile
	linkFile = func(string, string) error { return &os.LinkError{Op: "link", Err: syscall.EPERM} }
	t.Cleanup(func() { linkFile = orig })

	rec := newTestRecorder(t, dir, priv)
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	var notices bytes.Buffer
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, Principal: testPrincipal, Actor: testActor, Session: session, Notices: &notices})
	emitOne(t, e)
	_ = rec.Close()
	if e.ChainLink() != nil {
		t.Fatal("a failed publish must leave the run unlinked")
	}
	if !strings.Contains(notices.String(), "starts unlinked") || !strings.Contains(notices.String(), "publishing chain link") {
		t.Fatalf("the failure must be logged, got %q", notices.String())
	}
	des, _ := os.ReadDir(dir)
	for _, de := range des {
		if strings.Contains(de.Name(), "chain-link") {
			t.Fatalf("no link or temp file may remain: %s", de.Name())
		}
	}
}

func TestChainLink_PublishErrorPaths(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "absent")
	if err := publishChainLinkFile(missing, "chain-link-x.json", []byte("{}")); err == nil {
		t.Fatal("publishing into a missing directory must fail")
	}
	if err := syncDir(missing); err == nil {
		t.Fatal("syncing a missing directory must fail")
	}
	if _, err := readChainLinkFiles(missing); err == nil {
		t.Fatal("listing a missing directory must fail")
	}
	if _, err := ContinuityBases(missing); err == nil {
		t.Fatal("ContinuityBases on a missing directory must fail")
	}
	if _, err := VerifyBase(missing, recorder.DefaultSessionBase, BaseVerifyOptions{}); err == nil {
		t.Fatal("VerifyBase on a missing directory must fail")
	}
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := writeSyncClose(f, []byte("x")); err == nil {
		t.Fatal("writing a closed file must fail")
	}
	for _, name := range []string{"chain-link-.json", "chain-link-x", "evidence-x.jsonl", ".chain-link-x.tmp"} {
		if _, ok := chainLinkFilePredecessor(name); ok {
			t.Fatalf("%q must not parse as a link file name", name)
		}
	}
}

func TestChainLink_EmptyAndUnreadableTail(t *testing.T) {
	t.Parallel()
	tail, err := sessionReceiptTail(nil)
	if err != nil || tail != nil {
		t.Fatalf("empty shard set: tail=%v, err=%v; want nil, nil", tail, err)
	}
	if pred, ok := claimableTail(nil, "proxy", io.Discard); ok || pred.session != "" {
		t.Fatalf("empty chain was claimable: %+v, %v", pred, ok)
	}
	missing := filepath.Join(t.TempDir(), "missing.jsonl")
	if _, err := sessionReceiptTail([]string{missing}); err == nil || !strings.Contains(err.Error(), "reading evidence file") {
		t.Fatalf("missing shard: err=%v; want read error", err)
	}
}

func TestChainLink_ReadFileRefusesMissingAndOversized(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := readChainLinkFile(filepath.Join(dir, "missing.json")); err == nil || !strings.Contains(err.Error(), "stat chain link file") {
		t.Fatalf("missing link: err=%v; want stat error", err)
	}
	path := filepath.Join(dir, "oversized.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxChainLinkFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readChainLinkFile(path); err == nil || !strings.Contains(err.Error(), "chain link file exceeds") {
		t.Fatalf("oversized link: err=%v; want size refusal", err)
	}
}

func TestChainLink_ReadSessionEntriesMissingDirectory(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing")
	entries, err := readSessionEntries(missing, "proxy")
	if err == nil || len(entries) != 0 || !strings.Contains(err.Error(), "reading evidence directory") {
		t.Fatalf("missing directory: entries=%v, err=%v; want no entries and directory error", entries, err)
	}
}

func TestChainLink_ContinuityBases(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	// A legacy-only base has no continuity to report.
	legacyRec := newTestRecorder(t, dir, priv)
	emitOne(t, NewEmitter(EmitterConfig{Recorder: legacyRec, PrivKey: priv, Principal: testPrincipal, Actor: testActor}))
	_ = legacyRec.Close()
	if bases, err := ContinuityBases(dir); err != nil || len(bases) != 0 {
		t.Fatalf("legacy-only: %v %v", bases, err)
	}
	// A link file naming another base's predecessor surfaces that base.
	writeLinkFile(t, dir, ChainLinkFileName("other"), []byte("x"))
	writeLinkFile(t, dir, ChainLinkFileName("third.run."+strings.Repeat("1", 32)), []byte("x"))
	a := startRun(t, dir, priv)
	a.openAndEmit(t, 0)
	a.close(t)
	bases, err := ContinuityBases(dir)
	if err != nil || !slices.Equal(bases, []string{"other", recorder.DefaultSessionBase, "third"}) {
		t.Fatalf("ContinuityBases = %v, %v", bases, err)
	}
	// A malformed link file for another base is that base's finding, not this one's.
	if r := mustVerifyBase(t, dir, BaseVerifyOptions{}); !r.Healthy() {
		t.Fatalf("another base's link file must not affect this base: %+v", r.Findings)
	}
	r, err := VerifyBase(dir, "other", BaseVerifyOptions{})
	if err != nil || findingKinds(r)[FindingInvalidLink] != 1 {
		t.Fatalf("other base: %+v %v", r.Findings, err)
	}
}

func TestChainLink_CrossBaseAndDuplicateSuccessorLinks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a, b := linkedPair(t, dir, priv)
	l := b.e.ChainLink()
	// A link whose successor is not a run chain of the base (the legacy name).
	forgeLink(t, dir, ChainLinkFileName(recorder.DefaultSessionBase+".run."+strings.Repeat("9", 32)), ChainLink{
		PredecessorSession: recorder.DefaultSessionBase + ".run." + strings.Repeat("9", 32), PredecessorTailHash: l.PredecessorTailHash,
		PredecessorSignerKey: l.PredecessorSignerKey, SuccessorSession: recorder.DefaultSessionBase,
	}, priv)
	// A link naming B as successor of a second predecessor (A is its first).
	forgeLink(t, dir, ChainLinkFileName(recorder.DefaultSessionBase+".run."+strings.Repeat("8", 32)), ChainLink{
		PredecessorSession: recorder.DefaultSessionBase + ".run." + strings.Repeat("8", 32), PredecessorTailHash: l.PredecessorTailHash,
		PredecessorSignerKey: l.PredecessorSignerKey, SuccessorSession: b.session,
	}, priv)
	// A link whose predecessor belongs to another base but whose successor is ours.
	forgeLink(t, dir, ChainLinkFileName("other.run."+strings.Repeat("7", 32)), ChainLink{
		PredecessorSession: "other.run." + strings.Repeat("7", 32), PredecessorTailHash: l.PredecessorTailHash,
		PredecessorSignerKey: l.PredecessorSignerKey, SuccessorSession: a.session,
	}, priv)
	r := mustVerifyBase(t, dir, BaseVerifyOptions{})
	if findingKinds(r)[FindingInvalidLink] != 3 {
		t.Fatalf("want 3 invalid_link findings: %+v", r.Findings)
	}
}

func TestChainLink_CrossChainEndorsementMismatches(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	pubB, _ := generateTestKey(t)
	link := ChainLink{
		PredecessorSession: "proxy.run." + strings.Repeat("a", 32), PredecessorTailSeq: 4,
		PredecessorTailHash: strings.Repeat("cd", 32), PredecessorSignerKey: hex.EncodeToString(pubA),
		SuccessorSignerKey: hex.EncodeToString(pubB),
	}
	endorse := func(mut func(e *RotationEndorsement)) RotationEndorsement {
		e := RotationEndorsement{
			SessionID: link.PredecessorSession, PriorFinalSeq: link.PredecessorTailSeq, PriorTailHash: link.PredecessorTailHash,
			NewSignerKey: link.SuccessorSignerKey, RotatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}
		mut(&e)
		signed, err := SignRotationEndorsement(e, privA)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	if err := VerifyCrossChainEndorsement(endorse(func(*RotationEndorsement) {}), link); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	for name, mut := range map[string]func(e *RotationEndorsement){
		"session": func(e *RotationEndorsement) { e.SessionID = "proxy" },
		"new key": func(e *RotationEndorsement) { e.NewSignerKey = strings.Repeat("3a", 32) },
		"seq":     func(e *RotationEndorsement) { e.PriorFinalSeq++ },
		"hash":    func(e *RotationEndorsement) { e.PriorTailHash = strings.Repeat("ef", 32) },
	} {
		if VerifyCrossChainEndorsement(endorse(mut), link) == nil {
			t.Fatalf("%s mismatch must be refused", name)
		}
	}
	otherPrior := link
	otherPrior.PredecessorSignerKey = hex.EncodeToString(pubB)
	if VerifyCrossChainEndorsement(endorse(func(*RotationEndorsement) {}), otherPrior) == nil {
		t.Fatal("a prior key mismatch must be refused")
	}
	bad := endorse(func(*RotationEndorsement) {})
	bad.RotatedAt = "2000-01-01T00:00:00Z"
	if VerifyCrossChainEndorsement(bad, link) == nil {
		t.Fatal("an endorsement altered after signing must be refused")
	}
}

// An unreadable predecessor chain is skipped loudly at startup and is a
// corrupt_chain finding when a link names it.
func TestChainLink_UnreadablePredecessorChain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := generateTestKey(t)
	a := startRun(t, dir, priv)
	a.openAndEmit(t, 1)
	a.close(t)
	files, err := recorderFiles(dir, a.session)
	if err != nil || len(files) != 1 {
		t.Fatalf("files: %v %v", files, err)
	}
	good, err := os.ReadFile(filepath.Clean(files[0]))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files[0], []byte("{not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := newTestRecorder(t, dir, priv)
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	var notices bytes.Buffer
	e := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: priv, Principal: testPrincipal, Actor: testActor, Session: session, Notices: &notices})
	emitOne(t, e)
	_ = rec.Close()
	if e.ChainLink() != nil || !strings.Contains(notices.String(), "reading its tail") {
		t.Fatalf("an unreadable predecessor must be skipped loudly: link=%v notices=%q", e.ChainLink(), notices.String())
	}
	if e.Session() != session {
		t.Fatalf("Session() = %q, want %q", e.Session(), session)
	}
	// Restore A, link to it by hand, then break A again: the link now names
	// an unreadable chain, which must be a finding in both modes.
	if err := os.WriteFile(files[0], good, 0o600); err != nil {
		t.Fatal(err)
	}
	tail := sessionReceipts(t, dir, a.session)
	forgeLink(t, dir, ChainLinkFileName(a.session), ChainLink{
		PredecessorSession: a.session, PredecessorTailSeq: tail[len(tail)-1].ActionRecord.ChainSeq,
		PredecessorTailHash: mustHash(t, tail[len(tail)-1]), PredecessorSignerKey: tail[0].SignerKey, SuccessorSession: session,
	}, priv)
	if err := os.WriteFile(files[0], []byte("{not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, linksOnly := range []bool{false, true} {
		r := mustVerifyBase(t, dir, BaseVerifyOptions{LinksOnly: linksOnly})
		if findingKinds(r)[FindingCorruptChain] != 1 || findingKinds(r)[FindingPredecessorUnverified] != 1 {
			t.Fatalf("linksOnly=%v: %+v", linksOnly, r.Findings)
		}
	}
	if _, err := ResolveBaseSessions(filepath.Join(dir, "absent"), recorder.DefaultSessionBase); err == nil {
		t.Fatal("ResolveBaseSessions on a missing directory must fail")
	}
	var nilEmitter *Emitter
	if nilEmitter.Session() != "" || nilEmitter.ChainLink() != nil {
		t.Fatal("nil emitter accessors must be safe")
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
	if _, err := UnmarshalChainLink([]byte(`{}`)); err == nil {
		t.Fatal("an empty link must not parse")
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
	testwait.For(t, 60*time.Second, func() bool {
		des, _ := os.ReadDir(ready)
		return len(des) >= n
	}, "siblings never became live")
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
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestChainLinkHelperProcess$", "-test.count=1") // #nosec G204,G702 -- controlled re-exec of this test binary.
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
	if !report.Healthy() || report.LinkCount() != 0 || len(report.Unlinked()) != helperProcs {
		t.Fatalf("concurrent live runs must neither fork nor link each other: links=%d unlinked=%d findings=%+v", report.LinkCount(), len(report.Unlinked()), report.Findings)
	}
}

// TestChainLinkFileNameIsRecorderOwned is the parity check between the name
// this package publishes and the recorder's definition of the files it owns.
// The recorder cannot import this package, so without this test the two could
// drift and a writer guarded by IsRecorderOwnedFile would overwrite a link.
func TestChainLinkFileNameIsRecorderOwned(t *testing.T) {
	t.Parallel()
	name := ChainLinkFileName("proxy.run.00112233445566778899aabbccddeeff")
	if !recorder.IsRecorderOwnedFile(name) {
		t.Fatalf("recorder.IsRecorderOwnedFile(%q) = false; the link would be unprotected", name)
	}
}
