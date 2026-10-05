// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

// This file keeps VerifyBase as it was before it streamed: every chain's
// entries and receipts are read into memory before any check runs. It is the
// oracle for the streaming VerifyBase's parity tests and must not change
// except to follow a deliberate verdict change in both implementations.

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type legacyBaseChainData struct {
	chain    BaseChain
	receipts []Receipt
	evidence []contractreceipt.EvidenceReceipt
}

// legacyVerifyBase verifies every chain of base in dir and every link file that
// names a chain of base. An error means the base could not be enumerated at
// all; a caller must treat that as incomplete, never as healthy.
//
// A healthy report does NOT prove continuity: a deleted link file leaves its
// successor listed in Unlinked, which is not a finding (see Unlinked).
func legacyVerifyBase(dir, base string, opts BaseVerifyOptions) (BaseReport, error) {
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
		if lf.seal != nil {
			in = in || isBaseChain(lf.seal.PredecessorSession, base) || isBaseChain(lf.seal.SuccessorSession, base)
			need[lf.seal.PredecessorSession], need[lf.seal.SuccessorSession] = true, true
		}
		if in {
			scoped = append(scoped, lf)
		}
	}

	data := make(map[string]*legacyBaseChainData, len(sessions))
	for _, s := range sessions {
		d := &legacyBaseChainData{chain: BaseChain{Session: s, Legacy: s == base}}
		data[s] = d
		if opts.LinksOnly && !need[s] {
			continue
		}
		legacyLoadBaseChain(ix, d, opts.LinksOnly, add)
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
			legacyVerifyBaseChain(data[s], opts.TrustedKeys, own, endorsed[s], add)
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
					endorsed[s] = exists && pred.chain.Valid && len(pred.receipts) > 0 &&
						legacyCheckLinkedTail(pred.receipts, *data[s].chain.Link) == nil
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
		legacyCheckBaseLink(data, s, opts, endorsed[s], add)
	}
	legacyCheckRecoveryClaims(dir, base, scoped, data, opts, successors, add)
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
		legacyCheckRunNonces(data, sessions, add)
	}

	for _, s := range sessions {
		report.Chains = append(report.Chains, data[s].chain)
	}
	return report, nil
}

// legacyCheckRunNonces reports two chains whose signed action records carry the
// same run nonce. A run with no action records has no nonce and is skipped.
func legacyCheckRunNonces(data map[string]*legacyBaseChainData, sessions []string, add func(kind, session, detail string)) {
	owner := make(map[string]string)
	for _, s := range sessions {
		for _, n := range runNonces(data[s].receipts) {
			if first, dup := owner[n]; dup {
				add(FindingDuplicateRunNonce, s, fmt.Sprintf("run nonce %s is also signed in chain %s: the same run is present twice", n, first))
				continue
			}
			owner[n] = s
		}
	}
}

// legacyLoadBaseChain reads one chain's receipts and records its tail. In
// links-only mode a chain is valid when its tail receipt verifies on its own;
// otherwise validity is decided later by full chain verification.
func legacyLoadBaseChain(ix evidenceIndex, d *legacyBaseChainData, linksOnly bool, add func(kind, session, detail string)) {
	s := d.chain.Session
	entries, readErr := readIndexedEntries(ix, s)
	if readErr == nil {
		readErr = recorder.CheckEntrySessions(entries, s)
	}
	if readErr != nil {
		d.chain.Error = readErr.Error()
		add(FindingCorruptChain, s, readErr.Error())
		return
	}
	if !linksOnly {
		if chainErr := recorder.VerifyChain(entries); chainErr != nil {
			add(FindingOuterChainBroken, s, chainErr.Error())
		}
		evidence, evErr := contractreceipt.ExtractEvidenceReceiptsFromEntries(entries)
		if evErr != nil {
			d.chain.Error = "evidence receipt chain: " + evErr.Error()
			add(FindingCorruptChain, s, d.chain.Error)
			return
		}
		d.evidence = evidence
		d.chain.EvidenceReceipts = len(evidence)
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
		// A chain with only EvidenceReceipt v2 entries is decided by full
		// verification; one with no receipts of either kind has nothing to
		// fail.
		d.chain.Valid = len(d.evidence) == 0
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

// legacyVerifyBaseChain runs full signature and key-trust verification on one
// chain: its ActionReceipt v1 chain and its EvidenceReceipt v2 chain, each
// when present. The chain is valid only when every chain present verifies.
func legacyVerifyBaseChain(d *legacyBaseChainData, trusted []string, own []RotationEndorsement, endorsed bool, add func(kind, session, detail string)) {
	if d.chain.Error != "" || (len(d.receipts) == 0 && len(d.evidence) == 0) {
		return
	}
	if endorsed && len(trusted) > 0 && d.chain.Link != nil {
		trusted = append(slices.Clone(trusted), d.chain.Link.SuccessorSignerKey)
	}
	if len(d.receipts) > 0 {
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
	}
	if len(d.evidence) > 0 {
		res := VerifyEvidenceChainTrusted(d.evidence, trusted, contractreceipt.ChainVerifyOptions{})
		if !res.Valid {
			d.chain.Valid = false
			d.chain.Error = "evidence receipt chain: " + res.Error
			add(FindingCorruptChain, d.chain.Session, d.chain.Error)
			return
		}
	}
	d.chain.Valid = true
}

// legacyCheckBaseLink matches one chain's link against its predecessor.
func legacyCheckBaseLink(data map[string]*legacyBaseChainData, s string, opts BaseVerifyOptions, endorsed bool, add func(kind, session, detail string)) {
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
	if checkErr := legacyCheckLinkedTail(pred.receipts, *link); checkErr != nil {
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

// legacyCheckLinkedTail matches the link against the predecessor's verified chain.
func legacyCheckLinkedTail(receipts []Receipt, link ChainLink) error {
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

func legacyCheckRecoveryClaims(dir, base string, claims []chainLinkRecord, data map[string]*legacyBaseChainData, opts BaseVerifyOptions, successors map[string][]string, add func(string, string, string)) {
	for _, claim := range claims {
		s := claim.seal
		if s == nil {
			continue
		}
		successors[s.PredecessorSession] = append(successors[s.PredecessorSession], s.SuccessorSession)
		fail := func(detail string) { add(FindingInvalidRecoverySeal, s.SuccessorSession, detail) }
		if claim.namePred != s.PredecessorSession || !isBaseChain(s.PredecessorSession, base) || !isBaseChain(s.SuccessorSession, base) {
			fail("recovery seal filename or base mismatch")
			continue
		}
		d := data[s.SuccessorSession]
		if d == nil || !d.chain.Valid || d.chain.Link != nil || d.chain.RecoverySeal != nil {
			fail("recovery successor unavailable, invalid, or already linked")
			continue
		}
		if !opts.LinksOnly && s.SuccessorSignerKey != s.PredecessorSignerKey && !slices.Contains(opts.TrustedKeys, s.SuccessorSignerKey) {
			fail("recovery successor key is not explicitly trusted")
			continue
		}
		trusted := opts.TrustedKeys
		if opts.LinksOnly {
			// Doctor checks signatures and placement, not operator key trust.
			trusted = nil
		}
		if err := verifyRecoveryBinding(dir, *s, trusted, opts.LinksOnly); err != nil {
			fail(err.Error())
			continue
		}
		d.chain.RecoverySeal = s
		add(FindingAttestedDiscontinuity, s.SuccessorSession, fmt.Sprintf("linked across attested discontinuity from %s: shard %s byte %d; evidence remains damaged", s.PredecessorSession, s.Shard, s.DamageOffset))
	}
}
