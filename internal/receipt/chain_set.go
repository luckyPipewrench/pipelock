// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"

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
}

// BaseChain is one chain of a base: a run session or the legacy base session.
// Valid describes that chain; LinkTrust separately describes its predecessor.
type BaseChain struct {
	Session   string
	Legacy    bool
	Receipts  int
	FinalSeq  uint64
	TailHash  string
	SignerKey string
	Link      *ChainLink
	LinkFile  string
	LinkTrust string
	Valid     bool
	Error     string
}

// BaseFinding is one problem found while verifying a base.
type BaseFinding struct {
	Kind    string
	Session string
	Detail  string
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
		if c.Link == nil {
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

type baseChainData struct {
	chain    BaseChain
	receipts []Receipt
}

// chainLinkRecord is one link file as read from disk.
type chainLinkRecord struct {
	name     string
	namePred string
	link     *ChainLink
	err      error
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
		pred, _ := chainLinkFilePredecessor(name)
		rec := chainLinkRecord{name: name, namePred: pred}
		link, readErr := readChainLinkFile(filepath.Join(filepath.Clean(dir), name))
		if readErr != nil {
			rec.err = readErr
		} else {
			rec.link = &link
		}
		out = append(out, rec)
	}
	return out, nil
}

func readChainLinkFile(path string) (ChainLink, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return ChainLink{}, fmt.Errorf("stat chain link file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return ChainLink{}, errors.New("chain link file is not a regular file")
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return ChainLink{}, fmt.Errorf("open chain link file: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxChainLinkFileBytes+1))
	if err != nil {
		return ChainLink{}, fmt.Errorf("read chain link file: %w", err)
	}
	if len(data) > maxChainLinkFileBytes {
		return ChainLink{}, fmt.Errorf("chain link file exceeds %d bytes", maxChainLinkFileBytes)
	}
	return UnmarshalChainLink(data)
}

// VerifyBase verifies every chain of base in dir and every link file that
// names a chain of base. An error means the base could not be enumerated at
// all; a caller must treat that as incomplete, never as healthy.
//
// A healthy report does NOT prove continuity: a deleted link file leaves its
// successor listed in Unlinked, which is not a finding (see Unlinked).
func VerifyBase(dir, base string, opts BaseVerifyOptions) (BaseReport, error) {
	report := BaseReport{Base: base}
	ix, err := indexRecorderFiles(dir)
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

	scoped := make([]chainLinkRecord, 0, len(links))
	need := make(map[string]bool)
	for _, lf := range links {
		in := isBaseChain(lf.namePred, base)
		if lf.link != nil {
			in = in || isBaseChain(lf.link.PredecessorSession, base) || isBaseChain(lf.link.SuccessorSession, base)
			need[lf.link.PredecessorSession] = true
			need[lf.link.SuccessorSession] = true
		}
		if in {
			scoped = append(scoped, lf)
		}
	}

	data := make(map[string]*baseChainData, len(sessions))
	for _, s := range sessions {
		d := &baseChainData{chain: BaseChain{Session: s, Legacy: s == base}}
		data[s] = d
		if opts.LinksOnly && !need[s] {
			continue
		}
		loadBaseChain(ix, d, opts.LinksOnly, add)
	}

	// Attach each link file to its successor. Every rejection is a finding:
	// a link file that cannot be trusted is never silently skipped.
	successors := make(map[string][]string)
	for _, lf := range scoped {
		if lf.err != nil {
			add(FindingInvalidLink, lf.namePred, fmt.Sprintf("link file %s: %v", lf.name, lf.err))
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
	endorsed := make(map[string]bool)
	if !opts.LinksOnly {
		crossUsed := make(map[int]bool)
		for _, s := range sessions {
			link := data[s].chain.Link
			if link == nil || link.SuccessorSignerKey == link.PredecessorSignerKey {
				continue
			}
			for i, e := range opts.Endorsements {
				if VerifyCrossChainEndorsement(e, *link) == nil {
					endorsed[s] = true
					crossUsed[i] = true
					break
				}
			}
		}
		for _, s := range sessions {
			// In-chain rotation endorsements go only to their own chain, and
			// never one already consumed across a link: the single-chain
			// verifier rejects any endorsement it cannot place.
			var own []RotationEndorsement
			for i, e := range opts.Endorsements {
				if e.SessionID == s && !crossUsed[i] {
					own = append(own, e)
				}
			}
			verifyBaseChain(data[s], opts.TrustedKeys, own, endorsed[s], add)
		}
	}

	for _, s := range sessions {
		checkBaseLink(data, s, opts, endorsed[s], add)
	}
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

	for _, s := range sessions {
		report.Chains = append(report.Chains, data[s].chain)
	}
	return report, nil
}

// loadBaseChain reads one chain's receipts and records its tail. In
// links-only mode a chain is valid when its tail receipt verifies on its own;
// otherwise validity is decided later by full chain verification.
func loadBaseChain(ix evidenceIndex, d *baseChainData, linksOnly bool, add func(kind, session, detail string)) {
	s := d.chain.Session
	entries, readErr := readIndexedEntries(ix, s)
	if readErr != nil {
		d.chain.Error = readErr.Error()
		add(FindingCorruptChain, s, readErr.Error())
		return
	}
	if !linksOnly {
		if chainErr := recorder.VerifyChain(entries); chainErr != nil {
			add(FindingOuterChainBroken, s, chainErr.Error())
		}
	}
	for _, entry := range entries {
		if entry.Type != recorderEntryType {
			continue
		}
		rcpt, rErr := receiptFromEntry(entry)
		if rErr != nil {
			d.chain.Error = rErr.Error()
			add(FindingCorruptChain, s, rErr.Error())
			return
		}
		d.receipts = append(d.receipts, *rcpt)
	}
	if len(d.receipts) == 0 {
		d.chain.Valid = true
		return
	}
	d.chain.Receipts = len(d.receipts)
	d.chain.SignerKey = d.receipts[0].SignerKey
	last := d.receipts[len(d.receipts)-1]
	d.chain.FinalSeq = last.ActionRecord.ChainSeq
	if h, hErr := ReceiptHash(last); hErr == nil {
		d.chain.TailHash = h
	}
	if linksOnly {
		if tailErr := VerifyInternalConsistencyOnly(last); tailErr != nil {
			d.chain.Error = tailErr.Error()
			return
		}
		d.chain.Valid = true
	}
}

// verifyBaseChain runs full signature and key-trust verification on one chain.
func verifyBaseChain(d *baseChainData, trusted []string, own []RotationEndorsement, endorsed bool, add func(kind, session, detail string)) {
	if d.chain.Error != "" || len(d.receipts) == 0 {
		return
	}
	if endorsed && len(trusted) > 0 {
		trusted = append(slices.Clone(trusted), d.chain.Link.SuccessorSignerKey)
	}
	var res ChainResult
	if len(own) > 0 {
		res = VerifyChainWithEndorsements(d.chain.Session, d.receipts, own, trusted)
	} else {
		res = VerifyChainTrusted(d.receipts, trusted)
	}
	if !res.Valid && (res.FailureKind != ChainFailureLifecycleOpen || !res.IntegrityVerified) {
		d.chain.Valid = false
		d.chain.Error = res.Error
		add(FindingCorruptChain, d.chain.Session, res.Error)
		return
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
	if len(d.receipts) > 0 && d.receipts[0].SignerKey != link.SuccessorSignerKey {
		add(FindingInvalidLink, s, "link successor key does not sign the chain")
	}
	pred, exists := data[link.PredecessorSession]
	if !exists {
		add(FindingDanglingLink, s, fmt.Sprintf("predecessor %q not found", link.PredecessorSession))
		return
	}
	if !pred.chain.Valid || len(pred.receipts) == 0 {
		add(FindingPredecessorUnverified, s, fmt.Sprintf("predecessor %q did not verify", link.PredecessorSession))
		return
	}
	if checkErr := checkLinkedTail(pred.receipts, *link); checkErr != nil {
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
func checkLinkedTail(receipts []Receipt, link ChainLink) error {
	last := receipts[len(receipts)-1]
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
	for i := len(receipts) - 2; i >= 0; i-- {
		h, hErr := ReceiptHash(receipts[i])
		if hErr == nil && h == link.PredecessorTailHash && receipts[i].ActionRecord.ChainSeq == link.PredecessorTailSeq {
			return errAppendedAfterLink
		}
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
		es, readErr := recorder.ReadEntries(f)
		if readErr != nil {
			return nil, fmt.Errorf("reading %s: %w", filepath.Base(f), readErr)
		}
		entries = append(entries, es...)
	}
	return entries, nil
}
