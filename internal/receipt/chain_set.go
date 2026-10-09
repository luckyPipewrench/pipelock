// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// Base finding kinds. Any finding makes a base report unhealthy.
const (
	FindingCorruptChain          = "corrupt_chain"
	FindingOuterChainBroken      = "outer_chain_broken"
	FindingInvalidLink           = "invalid_link"
	FindingLinkNameMismatch      = "link_name_mismatch"
	FindingDanglingLink          = "dangling_link"
	FindingPredecessorUnverified = "predecessor_unverified"
	FindingLinkTailMismatch      = "link_tail_mismatch"
	FindingAppendedAfterLink     = "appended_after_link"
	FindingDoubleSuccessor       = "double_successor"
	FindingUntrustedSuccessorKey = "untrusted_successor_key"
)

// Link trust bases for a verified link.
const (
	LinkTrustSameKey    = "same_key"
	LinkTrustTrustedKey = "trusted_key"
	LinkTrustEndorsed   = "endorsed"
)

// BaseVerifyOptions configures VerifyBase.
// In-chain endorsements require a pinned root key; cross-chain endorsements
// are reported as continuity claims and do not create provenance on their own.
type BaseVerifyOptions struct {
	// TrustedKeys pins signer keys (hex). Empty means trust-on-first-use per
	// chain; an in-chain key change remains untrusted in that mode.
	TrustedKeys []string
	// Endorsements authorize a successor key across a link when signed by the
	// predecessor key and bound to the predecessor session and exact tail.
	Endorsements []RotationEndorsement
	// LinksOnly checks link files structurally and skips whole-chain
	// signature verification and key trust. The link's own signature and the
	// predecessor tail receipt's own signature are still verified, and the
	// tail must match exactly. Only chains a link file names are read. This
	// is the evidence doctor's mode: the doctor takes no trusted keys, so
	// judging key trust there would flag every honest key change.
	LinksOnly bool
	// ExcludeReceiptGroupSessions leaves gated shard runs to the signed group
	// verifier instead of classifying each shard as an independent restart.
	ExcludeReceiptGroupSessions bool
}

// BaseChain is one chain of a base: a run session or the legacy base session.
// Valid describes that chain; LinkTrust separately describes its predecessor.
type BaseChain struct {
	Session  string
	Legacy   bool
	Receipts int
	// EvidenceReceipts counts the chain's EvidenceReceipt v2 receipts. A run
	// that holds both chains is valid only when both verify.
	EvidenceReceipts int
	FinalSeq         uint64
	TailHash         string
	SignerKey        string
	Link             *ChainLink
	RecoverySeal     *RecoverySeal
	LinkFile         string
	LinkTrust        string
	Valid            bool
	Error            string
}

// BaseFinding is one problem found while verifying a base.
type BaseFinding struct {
	Kind    string
	Session string
	Detail  string
	// EvidenceChanged is set only by the verifier itself when the evidence
	// changed while it was being verified, never derived from Detail text.
	EvidenceChanged bool `json:"-"`
}

// BaseReport is the verification result for every chain of one base.
// A deleted link file leaves a successor unlinked, not a finding.
type BaseReport struct {
	Base     string
	Chains   []BaseChain
	Findings []BaseFinding
}

// Healthy reports whether every chain verified and every link file held.
// It says nothing about unlinked runs; see Unlinked.
func (r BaseReport) Healthy() bool { return len(r.Findings) == 0 }

// EvidenceChangedDuringVerification reports whether any finding says the
// evidence directory changed while it was being verified. Such a report says
// nothing about the evidence itself: the verifier cannot tell what it would
// have found had the recorder held still.
func (r BaseReport) EvidenceChangedDuringVerification() bool {
	for _, f := range r.Findings {
		if f.EvidenceChanged {
			return true
		}
	}
	return false
}

// LinkCount returns the number of chains with a verified-in-place link file.
func (r BaseReport) LinkCount() int {
	n := 0
	for _, c := range r.Chains {
		if c.Link != nil {
			n++
		}
	}
	return n
}

// Unlinked returns every chain that no link file continues into.
//
// An unlinked chain is REPORTED, never a finding, because honest runs are
// legitimately unlinked: the first run, a run started while its predecessor
// was still live (concurrent siblings), a run whose predecessor tail was
// corrupt, a run on a platform that cannot prove a writer is gone, and every
// chain an older binary wrote. Failing those would make every multi-process
// deployment look damaged. The cost of that choice is that deleting a link
// file is indistinguishable from an honest unlinked restart, so callers must
// show this list and must not present a healthy report as proof of
// continuity.
func (r BaseReport) Unlinked() []string {
	var out []string
	for _, c := range r.Chains {
		if c.Link == nil && c.RecoverySeal == nil {
			out = append(out, c.Session)
		}
	}
	return out
}

// ResolveBaseSessions lists every chain of base in dir: the legacy plain base
// session an older binary wrote and every run session minted from base.
//
// Enumeration is uncapped, like the recorder's resume scan: a continuity
// verdict over a partial session list would present missing chains as absent.
func ResolveBaseSessions(dir, base string) ([]string, error) {
	ix, err := indexRecorderFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}
	return baseSessions(ix, base), nil
}

// ResolveBaseSessionsExcludingReceiptGroups lists only legacy sessions. A
// grouped shard is verified as part of its signed group and cannot be treated
// as an independent passing run.
func ResolveBaseSessionsExcludingReceiptGroups(dir, base string) ([]string, error) {
	ix, err := indexRecorderFilesExcludingReceiptGroups(dir)
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}
	return baseSessions(ix, base), nil
}

func baseSessions(ix evidenceIndex, base string) []string {
	var out []string
	for _, s := range ix.sessions() {
		if isBaseChain(s, base) {
			out = append(out, s)
		}
	}
	return out
}

// ContinuityBases lists every base in dir that has restart continuity to
// report: a base with at least one run chain, or one named by a link file.
func ContinuityBases(dir string) ([]string, error) {
	ix, err := indexRecorderFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}
	set := make(map[string]struct{})
	for _, s := range ix.sessions() {
		if b, ok := RunSessionBase(s); ok {
			set[b] = struct{}{}
		}
	}
	names, err := chainLinkFileNames(dir)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		pred, _ := chainLinkFilePredecessor(name)
		if b, ok := RunSessionBase(pred); ok {
			set[b] = struct{}{}
		} else {
			set[pred] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for b := range set {
		out = append(out, b)
	}
	sort.Strings(out)
	return out, nil
}

// VerifyCrossChainEndorsement verifies e and matches it against a link whose
// successor key differs from its predecessor key: the endorsement must be
// signed by the predecessor key, name the successor key, and bind the
// predecessor session and its exact tail sequence and hash.
func VerifyCrossChainEndorsement(e RotationEndorsement, link ChainLink) error {
	if err := VerifyRotationEndorsement(e); err != nil {
		return err
	}
	switch {
	case e.SessionID != link.PredecessorSession:
		return fmt.Errorf("endorsement session %q does not match predecessor %q", e.SessionID, link.PredecessorSession)
	case e.PriorSignerKey != link.PredecessorSignerKey:
		return errors.New("endorsement prior key does not match predecessor signer key")
	case e.NewSignerKey != link.SuccessorSignerKey:
		return errors.New("endorsement new key does not match successor signer key")
	case e.PriorFinalSeq != link.PredecessorTailSeq || e.PriorTailHash != link.PredecessorTailHash:
		return errors.New("endorsement does not bind the linked predecessor tail")
	}
	return nil
}

// baseChainData is what VerifyBase keeps about one chain. It is gathered in
// one streaming read and holds no receipts beyond the last one: the counts,
// the first signer, the run nonces, whether a link's named tail occurs before
// the chain's last receipt, and, when the chain's trust inputs were known
// before the read, its verification results.
type baseChainData struct {
	chain BaseChain

	receiptCount  int
	evidenceCount int
	firstKey      string
	last          Receipt
	runNonces     map[string]struct{}
	// tailMatches records, for each link tail that names this chain as its
	// predecessor, how often a receipt with that sequence and hash occurs and
	// where the last one sits.
	tailMatches map[linkTail]tailMatch
	// digest binds a later verification read to the exact bytes this read
	// verified, shard by shard, and shards holds each shard's identity at
	// that read, so a second read of a replaced file fails even when its
	// bytes are the same.
	digest [sha256.Size]byte
	shards []os.FileInfo

	verified    bool
	actionRes   ChainResult
	evidenceRes contractreceipt.ChainResult
}

// linkTail is the predecessor tail a link names.
type linkTail struct {
	hash string
	seq  uint64
}

// tailMatch counts receipts matching a linkTail and remembers the index of
// the last one, which tells whether one occurs before the final receipt.
type tailMatch struct {
	count int
	last  int
}

// clearSummary drops everything a failed read summarized. A receipt decode
// failure keeps the receipts decoded before it, as later checks expect, so it
// does not clear.
func (d *baseChainData) clearSummary() {
	d.receiptCount, d.evidenceCount = 0, 0
	d.firstKey = ""
	d.last = Receipt{}
	d.runNonces = nil
	d.tailMatches = nil
}

// sortedRunNonces returns the chain's distinct run nonces, sorted.
func (d *baseChainData) sortedRunNonces() []string {
	out := make([]string, 0, len(d.runNonces))
	for n := range d.runNonces {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// chainLinkRecord is one link file as read from disk.
type chainLinkRecord struct {
	name       string
	namePred   string
	link       *ChainLink
	seal       *RecoverySeal
	isRecovery bool
	err        error

	// info is the file's identity when it was read, nil when it could not
	// be stat'ed. digest is the SHA-256 of the bytes read, set only when
	// hashed. The final directory re-check compares both, so a link file
	// changed after it was parsed fails the verification.
	info   os.FileInfo
	digest [sha256.Size]byte
	hashed bool
}

// baseSession returns the first chain of base this link file concerns: the
// successor it continues, then the predecessor, then the predecessor its
// name claims. ok is false when the file concerns no chain of base.
func (lf chainLinkRecord) baseSession(base string) (string, bool) {
	var candidates []string
	if lf.link != nil {
		candidates = append(candidates, lf.link.SuccessorSession, lf.link.PredecessorSession)
	}
	if lf.seal != nil {
		candidates = append(candidates, lf.seal.SuccessorSession, lf.seal.PredecessorSession)
	}
	candidates = append(candidates, lf.namePred)
	for _, s := range candidates {
		if isBaseChain(s, base) {
			return s, true
		}
	}
	return "", false
}

// chainLinkFileNames lists link file names in dir, sorted.
func chainLinkFileNames(dir string) ([]string, error) {
	des, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return nil, fmt.Errorf("listing chain link files: %w", err)
	}
	var out []string
	for _, de := range des {
		if _, ok := chainLinkFilePredecessor(de.Name()); ok {
			out = append(out, de.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// readChainLinkFiles reads and verifies every link file in dir. A file that
// cannot be read, is not a regular file, is oversized, or fails to parse or
// verify is returned with err set, never dropped.
func readChainLinkFiles(dir string) ([]chainLinkRecord, error) {
	names, err := chainLinkFileNames(dir)
	if err != nil {
		return nil, err
	}
	out := make([]chainLinkRecord, 0, len(names))
	for _, name := range names {
		out = append(out, readChainLinkRecord(dir, name))
	}
	return out, nil
}

// readChainLinkRecord reads, hashes, and parses one link file. Any failure is
// kept in the record's err.
func readChainLinkRecord(dir, name string) chainLinkRecord {
	pred, _ := chainLinkFilePredecessor(name)
	rec := chainLinkRecord{name: name, namePred: pred}
	raw, info, readErr := readClaimFile(filepath.Join(filepath.Clean(dir), name))
	rec.info = info
	if readErr == nil {
		rec.digest = sha256.Sum256(raw)
		rec.hashed = true
	}
	var fields map[string]json.RawMessage
	if readErr == nil {
		readErr = json.Unmarshal(raw, &fields)
	}
	_, rec.isRecovery = fields["kind"]
	switch {
	case readErr != nil:
		rec.err = readErr
	case rec.isRecovery:
		seal, err := UnmarshalRecoverySeal(raw)
		if err != nil {
			rec.err = err
		} else {
			rec.seal = &seal
		}
	default:
		link, err := UnmarshalChainLink(raw)
		if err != nil {
			rec.err = err
		} else {
			rec.link = &link
		}
	}
	return rec
}

func readChainLinkFile(path string) (ChainLink, error) {
	raw, err := readClaimBytes(path)
	if err != nil {
		return ChainLink{}, err
	}
	return UnmarshalChainLink(raw)
}

func readClaimBytes(path string) ([]byte, error) {
	raw, _, err := readClaimFile(path)
	return raw, err
}

// readClaimFile reads a link file and returns its bytes and the identity it
// had when stat'ed before the read. info is nil only when the stat failed.
func readClaimFile(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("stat chain link file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, info, errors.New("chain link file is not a regular file")
	}
	raw, err := recorder.ReadEvidenceFileBounded(path, maxChainLinkFileBytes)
	if errors.Is(err, recorder.ErrEvidenceReadLimitExceeded) {
		return nil, info, fmt.Errorf("chain link file exceeds %d bytes: %w", maxChainLinkFileBytes, err)
	}
	return raw, info, err
}

// VerifyBase verifies every chain of base in dir and every link file that
// names a chain of base. An error means the base could not be enumerated at
// all; a caller must treat that as incomplete, never as healthy.
//
// A healthy report does NOT prove continuity: a deleted link file leaves its
// successor listed in Unlinked, which is not a finding (see Unlinked).
func VerifyBase(dir, base string, opts BaseVerifyOptions) (BaseReport, error) {
	report := BaseReport{Base: base}
	var ix evidenceIndex
	var err error
	if opts.ExcludeReceiptGroupSessions {
		ix, err = indexRecorderFilesExcludingReceiptGroups(dir)
	} else {
		ix, err = indexRecorderFiles(dir)
	}
	if err != nil {
		return report, fmt.Errorf("listing sessions: %w", err)
	}
	sessions := baseSessions(ix, base)
	links, err := readChainLinkFiles(dir)
	if err != nil {
		return report, err
	}
	add := func(kind, session, detail string) {
		report.Findings = append(report.Findings, BaseFinding{Kind: kind, Session: session, Detail: detail})
	}
	addChanged := func(kind, session, detail string) {
		report.Findings = append(report.Findings, BaseFinding{Kind: kind, Session: session, Detail: detail, EvidenceChanged: true})
	}

	scoped := make([]chainLinkRecord, 0, len(links))
	need := make(map[string]bool)
	for _, lf := range links {
		if lf.link != nil {
			need[lf.link.PredecessorSession] = true
			need[lf.link.SuccessorSession] = true
		}
		if lf.seal != nil {
			need[lf.seal.PredecessorSession], need[lf.seal.SuccessorSession] = true, true
		}
		if _, in := lf.baseSession(base); in {
			scoped = append(scoped, lf)
		}
	}

	// Every tail a link names, by predecessor, so a chain's read can note
	// where those tails occur without keeping its receipts.
	tails := make(map[string][]linkTail)
	for _, lf := range links {
		if lf.link != nil {
			tails[lf.link.PredecessorSession] = append(tails[lf.link.PredecessorSession], linkTail{hash: lf.link.PredecessorTailHash, seq: lf.link.PredecessorTailSeq})
		}
	}
	// Without endorsements every chain is verified under exactly the pinned
	// keys, so it can be verified during the same read that loads it. With
	// them, a chain's trust depends on its predecessor's verdict and its own
	// tail, so it is verified by a second read in dependency order.
	load := baseLoadOptions{linksOnly: opts.LinksOnly}
	if !opts.LinksOnly && len(opts.Endorsements) == 0 {
		load.verifyInline = true
		load.trustedKeys = opts.TrustedKeys
	}
	data := make(map[string]*baseChainData, len(sessions))
	for _, s := range sessions {
		d := &baseChainData{chain: BaseChain{Session: s, Legacy: s == base}}
		data[s] = d
		if opts.LinksOnly && !need[s] {
			continue
		}
		loadBaseChain(ix, d, load, tails[s], add)
	}

	// Attach each link file to its successor. Every rejection is a finding:
	// a link file that cannot be trusted is never silently skipped.
	successors := make(map[string][]string)
	for _, lf := range scoped {
		if lf.err != nil {
			kind := FindingInvalidLink
			if lf.isRecovery {
				kind = FindingInvalidRecoverySeal
			}
			add(kind, lf.namePred, fmt.Sprintf("link file %s: %v", lf.name, lf.err))
			continue
		}
		if lf.seal != nil {
			continue
		}
		link := lf.link
		if link.PredecessorSession != lf.namePred {
			add(FindingLinkNameMismatch, lf.namePred, fmt.Sprintf("link file %s names predecessor %q", lf.name, link.PredecessorSession))
		}
		successors[link.PredecessorSession] = append(successors[link.PredecessorSession], link.SuccessorSession)
		if !isBaseChain(link.PredecessorSession, base) {
			add(FindingInvalidLink, link.SuccessorSession, fmt.Sprintf("link file %s: predecessor %q is not a chain of %q", lf.name, link.PredecessorSession, base))
			continue
		}
		if b, ok := RunSessionBase(link.SuccessorSession); !ok || b != base {
			add(FindingInvalidLink, link.SuccessorSession, fmt.Sprintf("link file %s: successor is not a run chain of %q", lf.name, base))
			continue
		}
		sd, exists := data[link.SuccessorSession]
		if !exists {
			add(FindingDanglingLink, link.SuccessorSession, fmt.Sprintf("link file %s: successor %q not found", lf.name, link.SuccessorSession))
			continue
		}
		if sd.chain.Link != nil {
			add(FindingInvalidLink, link.SuccessorSession, fmt.Sprintf("link file %s: successor already continues %q", lf.name, sd.chain.Link.PredecessorSession))
			continue
		}
		sd.chain.Link = link
		sd.chain.LinkFile = lf.name
	}

	// Key trust across links: an endorsed successor key joins the pinned set
	// for that chain only.
	//
	// An endorsement is authority only when the key that signed it is itself
	// trusted, so a successor counts as endorsed only after its predecessor
	// chain has verified. Chains are therefore verified in dependency order.
	// Chains that wait on each other in a cycle never reach a verified root;
	// they are verified without the endorsement and so report as untrusted,
	// rather than vouching for each other.
	endorsed := make(map[string]bool)
	if !opts.LinksOnly {
		betweenVerificationReads(dir)
		reread := &evidenceReread{dir: dir}
		endorsable := make(map[string]bool)
		crossUsed := make(map[int]bool)
		for _, s := range sessions {
			link := data[s].chain.Link
			if link == nil || link.SuccessorSignerKey == link.PredecessorSignerKey {
				continue
			}
			for i, e := range opts.Endorsements {
				if VerifyCrossChainEndorsement(e, *link) == nil {
					endorsable[s] = true
					crossUsed[i] = true
					break
				}
			}
		}
		verify := func(s string) {
			// In-chain rotation endorsements go only to their own chain, and
			// never one already consumed across a link: the single-chain
			// verifier rejects any endorsement it cannot place. An endorsement
			// that binds this chain's final receipt hands off across a link,
			// never within the chain; when its link is missing it stays
			// unused, and the successor then reports as unlinked rather than
			// this chain as corrupt.
			var own []RotationEndorsement
			for i, e := range opts.Endorsements {
				if e.SessionID == s && !crossUsed[i] && !bindsFinalReceipt(e, data[s].chain) {
					own = append(own, e)
				}
			}
			verifyBaseChain(reread, ix, data[s], opts.TrustedKeys, own, endorsed[s], add, addChanged)
		}
		resolved := make(map[string]bool)
		pending := sessions
		for progress := true; progress && len(pending) > 0; {
			progress = false
			var waiting []string
			for _, s := range pending {
				if endorsable[s] {
					predSession := data[s].chain.Link.PredecessorSession
					pred, exists := data[predSession]
					if exists && !resolved[predSession] {
						waiting = append(waiting, s)
						continue
					}
					// The endorsement's signer must be the key that signed the
					// predecessor's actual tail, not only the key the link names.
					endorsed[s] = exists && pred.chain.Valid && pred.receiptCount > 0 &&
						checkLinkedTail(pred, *data[s].chain.Link) == nil
				}
				verify(s)
				resolved[s] = true
				progress = true
			}
			pending = waiting
		}
		for _, s := range pending {
			verify(s)
		}
	}

	for _, s := range sessions {
		checkBaseLink(data, s, opts, endorsed[s], add)
	}
	checkRecoveryClaims(dir, base, scoped, data, opts, successors, add)
	preds := make([]string, 0, len(successors))
	for p := range successors {
		preds = append(preds, p)
	}
	sort.Strings(preds)
	for _, p := range preds {
		if len(successors[p]) > 1 {
			add(FindingDoubleSuccessor, p, fmt.Sprintf("continued by %d link files: %v", len(successors[p]), successors[p]))
		}
	}

	if !opts.LinksOnly {
		checkRunNonces(data, sessions, add)
	}

	// Every read is finished. A shard the reads never opened must not leave
	// the report healthy.
	// Links-only mode is the evidence doctor's structural check, run against
	// live recorders whose active shard grows; it makes no full-verification
	// claim, so it does not refuse a directory that changed while it read.
	if !opts.LinksOnly {
		if err := checkShardSetUnchanged(dir, base, ix, sessions, links, data, addChanged, opts.ExcludeReceiptGroupSessions); err != nil {
			return report, err
		}
	}

	for _, s := range sessions {
		report.Chains = append(report.Chains, data[s].chain)
	}
	return report, nil
}

// checkRunNonces reports two chains whose signed action records carry the
// same run nonce. A run with no action records has no nonce and is skipped.
func checkRunNonces(data map[string]*baseChainData, sessions []string, add func(kind, session, detail string)) {
	owner := make(map[string]string)
	for _, s := range sessions {
		for _, n := range data[s].sortedRunNonces() {
			if first, dup := owner[n]; dup {
				add(FindingDuplicateRunNonce, s, fmt.Sprintf("run nonce %s is also signed in chain %s: the same run is present twice", n, first))
				continue
			}
			owner[n] = s
		}
	}
}

// loadBaseChain reads one chain's receipts and records its tail. In
// links-only mode a chain is valid when its tail receipt verifies on its own;
// otherwise validity is decided later by full chain verification.
// baseLoadOptions selects what loadBaseChain checks during its read.
type baseLoadOptions struct {
	linksOnly bool
	// verifyInline verifies both receipt chains under trustedKeys during the
	// load read, for a chain whose trust inputs cannot change afterwards.
	verifyInline bool
	trustedKeys  []string
}

// baseChainRead is the per-read state of one chain's entries: the checks a
// read applies in order, each keeping its first failure, plus the summary
// the later link checks need.
type baseChainRead struct {
	session    string
	index      int
	sessionErr error
	outer      recorder.ChainWalker
	evidence   bool // extract EvidenceReceipt v2 receipts
	evErr      error
	rErr       error
	digest     hash.Hash

	d       *baseChainData
	tails   []linkTail
	actions ChainAccumulator
	evWalk  *EvidenceChainWalker
}

func (r *baseChainRead) add(e recorder.Entry) {
	i := r.index
	r.index++
	if r.sessionErr == nil && e.SessionID != r.session {
		r.sessionErr = recorder.EntrySessionError(e, r.session)
	}
	if r.evidence {
		_ = r.outer.Add(e)
		if r.evErr == nil {
			ev, ok, err := contractreceipt.EvidenceReceiptFromEntry(i, e)
			switch {
			case err != nil:
				r.evErr = err
			case ok:
				r.d.evidenceCount++
				if r.evWalk != nil {
					r.evWalk.Add(ev)
				}
			}
		}
	}
	if e.Type != recorderEntryType || r.rErr != nil {
		return
	}
	rcpt, err := receiptFromEntry(e)
	if err != nil {
		r.rErr = err
		return
	}
	r.addReceipt(*rcpt)
}

func (r *baseChainRead) addReceipt(rcpt Receipt) {
	d := r.d
	index := d.receiptCount
	d.receiptCount++
	if index == 0 {
		d.firstKey = rcpt.SignerKey
	}
	d.last = rcpt
	if n := rcpt.ActionRecord.RunNonce; n != "" {
		if d.runNonces == nil {
			d.runNonces = make(map[string]struct{})
		}
		d.runNonces[n] = struct{}{}
	}
	for _, t := range r.tails {
		if rcpt.ActionRecord.ChainSeq != t.seq {
			continue
		}
		if h, err := ReceiptHash(rcpt); err == nil && h == t.hash {
			if d.tailMatches == nil {
				d.tailMatches = make(map[linkTail]tailMatch)
			}
			m := d.tailMatches[t]
			m.count++
			m.last = index
			d.tailMatches[t] = m
		}
	}
	if r.actions != nil {
		r.actions.Add(rcpt)
	}
}

// walkIndexedEntries reads every recorder entry of session, in shard order,
// with the same per-shard limits and errors as readIndexedEntries. Each shard
// is opened the way the evidence readers open it, refusing a symlinked or
// non-regular file, and is read only as far as it was long when opened.
// Every byte read is hashed per shard and folded, with the shard's name, into raw,
// so two reads that produce the same digest verified the same bytes. It
// returns each shard's identity at open.
func walkIndexedEntries(ix evidenceIndex, session string, raw hash.Hash, consume func(recorder.Entry)) ([]os.FileInfo, error) {
	files, err := ix.files(session)
	if err != nil {
		return nil, err
	}
	infos := make([]os.FileInfo, 0, len(files))
	shard := sha256.New()
	var n [8]byte
	for _, f := range files {
		shard.Reset()
		info, err := recorder.WalkEvidenceFile(f, shard, func(e recorder.Entry) error {
			consume(e)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", filepath.Base(f), err)
		}
		infos = append(infos, info)
		duringEvidenceWalk(f)
		name := filepath.Base(f)
		binary.BigEndian.PutUint64(n[:], uint64(len(name)))
		_, _ = raw.Write(n[:])
		_, _ = raw.Write([]byte(name))
		_, _ = raw.Write(shard.Sum(nil))
	}
	return infos, nil
}

// loadBaseChain reads one chain once and records its tail. In links-only
// mode a chain is valid when its tail receipt verifies on its own; otherwise
// validity is decided by full chain verification, done during this read when
// opts.verifyInline is set and by verifyBaseChain's own read otherwise.
func loadBaseChain(ix evidenceIndex, d *baseChainData, opts baseLoadOptions, tails []linkTail, add func(kind, session, detail string)) {
	s := d.chain.Session
	read := &baseChainRead{session: s, evidence: !opts.linksOnly, digest: sha256.New(), d: d, tails: tails}
	if opts.verifyInline {
		read.actions = NewChainWalker(opts.trustedKeys)
		read.evWalk = NewEvidenceChainWalker(opts.trustedKeys, contractreceipt.ChainVerifyOptions{})
	}
	shards, readErr := walkIndexedEntries(ix, s, read.digest, read.add)
	if readErr == nil {
		readErr = read.sessionErr
	}
	if readErr != nil {
		// A chain that could not be read holds no receipts for any later
		// check, whatever was summarized before the failure surfaced.
		d.clearSummary()
		d.chain.Error = readErr.Error()
		add(FindingCorruptChain, s, readErr.Error())
		return
	}
	read.digest.Sum(d.digest[:0])
	d.shards = shards
	if !opts.linksOnly {
		if chainErr := read.outer.Err(); chainErr != nil {
			add(FindingOuterChainBroken, s, chainErr.Error())
		}
		if read.evErr != nil {
			// Receipts are extracted only once the evidence chain extracts.
			d.clearSummary()
			d.chain.Error = "evidence receipt chain: " + read.evErr.Error()
			add(FindingCorruptChain, s, d.chain.Error)
			return
		}
		d.chain.EvidenceReceipts = d.evidenceCount
	}
	if read.rErr != nil {
		d.chain.Error = read.rErr.Error()
		add(FindingCorruptChain, s, read.rErr.Error())
		return
	}
	if opts.verifyInline {
		d.verified = true
		d.actionRes = read.actions.Result()
		d.evidenceRes = read.evWalk.Result()
	}
	if d.receiptCount == 0 {
		// A chain with only EvidenceReceipt v2 entries is decided by full
		// verification; one with no receipts of either kind has nothing to
		// fail.
		d.chain.Valid = d.evidenceCount == 0
		return
	}
	d.chain.Receipts = d.receiptCount
	d.chain.SignerKey = d.firstKey
	last := d.last
	d.chain.FinalSeq = last.ActionRecord.ChainSeq
	if h, hErr := ReceiptHash(last); hErr == nil {
		d.chain.TailHash = h
	}
	if opts.linksOnly {
		if tailErr := VerifyInternalConsistencyOnly(last); tailErr != nil {
			d.chain.Error = tailErr.Error()
			return
		}
		d.chain.Valid = true
	}
}

// errEvidenceChanged is the failure of a second verification read that did
// not see exactly what the first read verified.
var errEvidenceChanged = errors.New("evidence changed between verification reads")

// betweenVerificationReads runs after every chain's first read and before any
// second read. Tests replace it to change the evidence directory there.
var betweenVerificationReads = func(_ string) {}

// duringEvidenceWalk runs after each shard a verification read walks, while
// that read is still in progress. Tests replace it to change the evidence
// directory in the middle of a read.
var duringEvidenceWalk = func(_ string) {}

// errEvidenceChangedDuring is the failure of a verification whose evidence
// directory no longer lists, after every read finished, exactly the shard
// files the reads verified.
var errEvidenceChangedDuring = errors.New("evidence changed during verification")

// checkShardSetUnchanged lists dir once more after every verification read
// has finished and fails each chain whose shard list, or any shard's file
// identity or size, differs from what its reads verified, and each chain of
// base that appeared or vanished. A shard created or replaced after a read
// listed the directory was never opened by that read, so without this check
// it could hold anything. Link files of base get the same check, plus a
// comparison of their bytes, since they are small and are parsed only once.
// A listing error is returned and means the verification is incomplete.
//
// This is best-effort detection for a recorder that should not be written
// while it is verified. A same-size in-place rewrite of a shard by a process
// with write access to dir can still go unseen.
func checkShardSetUnchanged(dir, base string, ix evidenceIndex, sessions []string, links []chainLinkRecord, data map[string]*baseChainData, add func(kind, session, detail string), excludeGroups bool) error {
	var final evidenceIndex
	var err error
	if excludeGroups {
		final, err = indexRecorderFilesExcludingReceiptGroups(dir)
	} else {
		final, err = indexRecorderFiles(dir)
	}
	if err != nil {
		return fmt.Errorf("re-listing sessions after verification: %w", err)
	}
	failChain := func(s, why string) {
		detail := fmt.Sprintf("%v: %s", errEvidenceChangedDuring, why)
		if d, ok := data[s]; ok {
			d.chain.Valid = false
			d.chain.Error = detail
		}
		add(FindingCorruptChain, s, detail)
	}
	for _, s := range baseSessions(final, base) {
		if !slices.Contains(sessions, s) {
			failChain(s, "shard set differs")
		}
	}
	for _, s := range sessions {
		if !slices.Equal(ix[s], final[s]) {
			failChain(s, "shard set differs")
			continue
		}
		d := data[s]
		if len(d.shards) != len(final[s]) {
			// This chain's read did not finish, so it verified no shard
			// whose identity could be compared; it already failed.
			continue
		}
		if why := shardIdentityChange(d.shards, final[s]); why != "" {
			failChain(s, why)
		}
	}
	return checkLinkFilesUnchanged(dir, base, links, failChain)
}

// checkLinkFilesUnchanged lists and reads dir's link files again and fails
// the chain of base that each added, removed, replaced, resized, or rewritten
// link file concerns, judged by what the file held at either read.
func checkLinkFilesUnchanged(dir, base string, links []chainLinkRecord, failChain func(s, why string)) error {
	names, err := chainLinkFileNames(dir)
	if err != nil {
		return fmt.Errorf("re-listing chain link files after verification: %w", err)
	}
	before := make(map[string]chainLinkRecord, len(links))
	for _, lf := range links {
		before[lf.name] = lf
	}
	fail := func(why string, records ...chainLinkRecord) {
		for _, lf := range records {
			if s, ok := lf.baseSession(base); ok {
				failChain(s, why)
				return
			}
		}
	}
	for _, name := range names {
		now := readChainLinkRecord(dir, name)
		orig, existed := before[name]
		if !existed {
			fail("link file set differs", now)
			continue
		}
		delete(before, name)
		if why := linkFileChange(orig, now); why != "" {
			fail(why, orig, now)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(before)) {
		fail("link file set differs", before[name])
	}
	return nil
}

// linkFileChange reports how a link file read again differs from the read
// that was verified, or "" when it is the same file with the same bytes.
func linkFileChange(orig, now chainLinkRecord) string {
	switch {
	case (orig.info == nil) != (now.info == nil):
		return "link file replaced"
	case orig.info != nil && !os.SameFile(orig.info, now.info):
		return "link file replaced"
	case orig.info != nil && orig.info.Size() != now.info.Size():
		return "link file size changed"
	case orig.hashed != now.hashed || orig.digest != now.digest:
		return "link file bytes changed"
	}
	return ""
}

// shardIdentityChange reports how the files now at paths differ from the
// shards a read verified, without following a symlink, or "" when they are
// the same files at the same sizes.
func shardIdentityChange(verified []os.FileInfo, paths []string) string {
	for i, f := range paths {
		info, err := os.Lstat(f)
		switch {
		case err != nil:
			return "shard set differs"
		case !os.SameFile(verified[i], info):
			return "shard file replaced"
		case verified[i].Size() != info.Size():
			return "shard size changed"
		}
	}
	return ""
}

// evidenceReread lists the evidence directory again, once, for the second
// verification reads, so a shard added or removed after the first reads is
// seen.
type evidenceReread struct {
	dir  string
	done bool
	ix   evidenceIndex
	err  error
}

func (r *evidenceReread) index() (evidenceIndex, error) {
	if !r.done {
		r.done = true
		r.ix, r.err = indexRecorderFiles(r.dir)
	}
	return r.ix, r.err
}

// sameShards reports whether the second read opened the same files, of the
// same size, that the first read verified.
func sameShards(first, second []os.FileInfo) bool {
	if len(first) != len(second) {
		return false
	}
	for i := range first {
		if !os.SameFile(first[i], second[i]) || first[i].Size() != second[i].Size() {
			return false
		}
	}
	return true
}

// reverifyBaseChain reads a loaded chain again and verifies both receipt
// chains under the trust its predecessor decided. The read must see exactly
// the bytes the load verified, from the same shard files, and the directory
// must still list the same shards for the chain; anything else fails it.
func reverifyBaseChain(reread *evidenceReread, ix evidenceIndex, d *baseChainData, trusted []string, own []RotationEndorsement) error {
	s := d.chain.Session
	current, err := reread.index()
	if err != nil {
		return fmt.Errorf("re-reading chain for verification: %w", err)
	}
	firstFiles, err := ix.files(s)
	if err != nil {
		return fmt.Errorf("re-reading chain for verification: %w", err)
	}
	nowFiles, err := current.files(s)
	if err != nil {
		return fmt.Errorf("re-reading chain for verification: %w", err)
	}
	if !slices.Equal(firstFiles, nowFiles) {
		return fmt.Errorf("re-reading chain for verification: %w: shard set differs", errEvidenceChanged)
	}
	var actions ChainAccumulator
	if len(own) > 0 {
		actions = NewEndorsedChainWalker(s, own, trusted)
	} else {
		actions = NewChainWalker(trusted)
	}
	evWalk := NewEvidenceChainWalker(trusted, contractreceipt.ChainVerifyOptions{})
	digest := sha256.New()
	index := 0
	var stepErr error
	// Walk the list just compared, not the index the first read used: the
	// two are equal here, and the final relist in VerifyBase catches any
	// shard created after this point.
	shards, err := walkIndexedEntries(current, s, digest, func(e recorder.Entry) {
		i := index
		index++
		if stepErr != nil {
			return
		}
		if ev, ok, evErr := contractreceipt.EvidenceReceiptFromEntry(i, e); evErr != nil {
			stepErr = evErr
			return
		} else if ok {
			evWalk.Add(ev)
		}
		if e.Type == recorderEntryType {
			rcpt, rErr := receiptFromEntry(e)
			if rErr != nil {
				stepErr = rErr
				return
			}
			actions.Add(*rcpt)
		}
	})
	if err == nil {
		err = stepErr
	}
	var sum [sha256.Size]byte
	digest.Sum(sum[:0])
	// Equal bytes mean this read verified exactly what the first read
	// checked, outer hash chain included; the same files mean neither read
	// was served by a replacement.
	switch {
	case err != nil:
	case sum != d.digest:
		err = fmt.Errorf("%w: shard bytes differ", errEvidenceChanged)
	case !sameShards(d.shards, shards):
		err = fmt.Errorf("%w: shard file replaced", errEvidenceChanged)
	}
	if err != nil {
		return fmt.Errorf("re-reading chain for verification: %w", err)
	}
	d.verified = true
	d.actionRes = actions.Result()
	d.evidenceRes = evWalk.Result()
	return nil
}

// verifyBaseChain runs full signature and key-trust verification on one
// chain: its ActionReceipt v1 chain and its EvidenceReceipt v2 chain, each
// when present. The chain is valid only when every chain present verifies.
func verifyBaseChain(reread *evidenceReread, ix evidenceIndex, d *baseChainData, trusted []string, own []RotationEndorsement, endorsed bool, add, addChanged func(kind, session, detail string)) {
	if d.chain.Error != "" || (d.receiptCount == 0 && d.evidenceCount == 0) {
		return
	}
	if endorsed && len(trusted) > 0 && d.chain.Link != nil {
		trusted = append(slices.Clone(trusted), d.chain.Link.SuccessorSignerKey)
	}
	if !d.verified {
		if err := reverifyBaseChain(reread, ix, d, trusted, own); err != nil {
			d.chain.Valid = false
			d.chain.Error = err.Error()
			report := add
			if errors.Is(err, errEvidenceChanged) {
				report = addChanged
			}
			report(FindingCorruptChain, d.chain.Session, d.chain.Error)
			return
		}
	}
	if d.receiptCount > 0 {
		res := d.actionRes
		if !res.Valid && (res.FailureKind != ChainFailureLifecycleOpen || !res.IntegrityVerified) {
			d.chain.Valid = false
			d.chain.Error = res.Error
			add(FindingCorruptChain, d.chain.Session, res.Error)
			return
		}
	}
	if d.evidenceCount > 0 {
		res := d.evidenceRes
		if !res.Valid {
			d.chain.Valid = false
			d.chain.Error = "evidence receipt chain: " + res.Error
			add(FindingCorruptChain, d.chain.Session, d.chain.Error)
			return
		}
	}
	d.chain.Valid = true
}

// checkBaseLink matches one chain's link against its predecessor.
func checkBaseLink(data map[string]*baseChainData, s string, opts BaseVerifyOptions, endorsed bool, add func(kind, session, detail string)) {
	d := data[s]
	link := d.chain.Link
	if link == nil {
		return
	}
	if d.receiptCount > 0 && d.firstKey != link.SuccessorSignerKey {
		add(FindingInvalidLink, s, "link successor key does not sign the chain")
	}
	pred, exists := data[link.PredecessorSession]
	if !exists {
		add(FindingDanglingLink, s, fmt.Sprintf("predecessor %q not found", link.PredecessorSession))
		return
	}
	if !pred.chain.Valid || pred.receiptCount == 0 {
		add(FindingPredecessorUnverified, s, fmt.Sprintf("predecessor %q did not verify", link.PredecessorSession))
		return
	}
	if checkErr := checkLinkedTail(pred, *link); checkErr != nil {
		kind := FindingLinkTailMismatch
		if errors.Is(checkErr, errAppendedAfterLink) {
			kind = FindingAppendedAfterLink
		}
		add(kind, link.PredecessorSession, fmt.Sprintf("linked by %s: %v", s, checkErr))
	}
	switch {
	case link.SuccessorSignerKey == link.PredecessorSignerKey:
		d.chain.LinkTrust = LinkTrustSameKey
	case opts.LinksOnly:
		// Key trust needs pinned keys; links-only mode does not judge it.
	case slices.Contains(opts.TrustedKeys, link.SuccessorSignerKey):
		d.chain.LinkTrust = LinkTrustTrustedKey
	case endorsed:
		d.chain.LinkTrust = LinkTrustEndorsed
	default:
		add(FindingUntrustedSuccessorKey, s, "successor key differs from predecessor key and is neither trusted nor endorsed")
	}
}

var errAppendedAfterLink = errors.New("entries were appended to the predecessor after the linked tail")

// checkLinkedTail matches the link against the predecessor's verified chain.
// The predecessor's receipts were summarized when it was read: its last
// receipt, and where each linked tail occurs.
func checkLinkedTail(pred *baseChainData, link ChainLink) error {
	last := pred.last
	lastHash, err := ReceiptHash(last)
	if err != nil {
		return err
	}
	if last.ActionRecord.ChainSeq == link.PredecessorTailSeq && lastHash == link.PredecessorTailHash {
		if last.SignerKey != link.PredecessorSignerKey {
			return errors.New("link predecessor key does not sign the linked tail")
		}
		return nil
	}
	// A receipt before the last one carries the linked tail.
	if m, ok := pred.tailMatches[linkTail{hash: link.PredecessorTailHash, seq: link.PredecessorTailSeq}]; ok &&
		(m.count > 1 || m.last != pred.receiptCount-1) {
		return errAppendedAfterLink
	}
	return fmt.Errorf("link names tail seq %d hash %s, predecessor tail is seq %d hash %s",
		link.PredecessorTailSeq, link.PredecessorTailHash, last.ActionRecord.ChainSeq, lastHash)
}

// readSessionEntries reads every recorder entry of session, in shard order.
func readSessionEntries(dir, session string) ([]recorder.Entry, error) {
	ix, err := indexRecorderFiles(dir)
	if err != nil {
		return nil, err
	}
	return readIndexedEntries(ix, session)
}

func readIndexedEntries(ix evidenceIndex, session string) ([]recorder.Entry, error) {
	files, err := ix.files(session)
	if err != nil {
		return nil, err
	}
	var entries []recorder.Entry
	for _, f := range files {
		es, readErr := recorder.ReadHistoryEntries(f)
		if readErr != nil {
			return nil, fmt.Errorf("reading %s: %w", filepath.Base(f), readErr)
		}
		entries = append(entries, es...)
	}
	return entries, nil
}

// bindsFinalReceipt reports whether e hands off from c's last receipt. Only a
// cross-chain endorsement does that: an in-chain rotation always has receipts
// after the prior tail it names. Sequence numbers are not compared, because a
// rotated chain can restart them in its new segment.
func bindsFinalReceipt(e RotationEndorsement, c BaseChain) bool {
	return c.TailHash != "" && e.PriorFinalSeq == c.FinalSeq && e.PriorTailHash == c.TailHash
}
