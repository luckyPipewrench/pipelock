// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"errors"
	"fmt"
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
	FindingMisplacedLink         = "misplaced_link"
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
type BaseVerifyOptions struct {
	// TrustedKeys pins signer keys (hex). Empty means trust-on-first-use per
	// chain; a key change across a link then needs an endorsement.
	TrustedKeys []string
	// Endorsements authorize a successor key across a link when signed by the
	// predecessor key and bound to the predecessor session and exact tail.
	Endorsements []RotationEndorsement
}

// BaseChain is one chain of a base: a run session or the legacy base session.
type BaseChain struct {
	Session   string
	Legacy    bool
	Receipts  int
	FinalSeq  uint64
	TailHash  string
	SignerKey string
	Link      *ChainLink
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
type BaseReport struct {
	Base     string
	Chains   []BaseChain
	Findings []BaseFinding
}

// Healthy reports whether every chain verified and every link held.
func (r BaseReport) Healthy() bool { return len(r.Findings) == 0 }

// LinkCount returns the number of chains carrying a link.
func (r BaseReport) LinkCount() int {
	n := 0
	for _, c := range r.Chains {
		if c.Link != nil {
			n++
		}
	}
	return n
}

// Unlinked returns chains that carry no link. An unlinked chain is not a
// finding: the first run, a run whose predecessor was still live or corrupt,
// and every chain from an older binary start unlinked.
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
func ResolveBaseSessions(dir, base string) ([]string, error) {
	sessions, err := recorder.ListSessions(dir)
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}
	out := make([]string, 0, len(sessions))
	for _, s := range sessions {
		if isBaseChain(s, base) {
			out = append(out, s)
		}
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

// VerifyBase verifies every chain of base in dir and every continuity link
// between them. An error means the base could not be enumerated at all; a
// caller must treat that as incomplete, never as healthy.
func VerifyBase(dir, base string, opts BaseVerifyOptions) (BaseReport, error) {
	report := BaseReport{Base: base}
	sessions, err := ResolveBaseSessions(dir, base)
	if err != nil {
		return report, err
	}
	add := func(kind, session, detail string) {
		report.Findings = append(report.Findings, BaseFinding{Kind: kind, Session: session, Detail: detail})
	}

	data := make(map[string]*baseChainData, len(sessions))
	for _, s := range sessions {
		d := &baseChainData{chain: BaseChain{Session: s, Legacy: s == base}}
		data[s] = d
		entries, readErr := readSessionEntries(dir, s)
		if readErr != nil {
			d.chain.Error = readErr.Error()
			add(FindingCorruptChain, s, readErr.Error())
			continue
		}
		if chainErr := recorder.VerifyChain(entries); chainErr != nil {
			add(FindingOuterChainBroken, s, chainErr.Error())
		}
		for i, entry := range entries {
			switch entry.Type {
			case ChainLinkEntryType:
				link, linkErr := chainLinkFromEntry(entry)
				switch {
				case linkErr != nil:
					add(FindingInvalidLink, s, linkErr.Error())
				case i != 0 || d.chain.Link != nil:
					add(FindingMisplacedLink, s, fmt.Sprintf("chain_link at entry %d; a link must be the first and only link entry", i))
				case link.SuccessorSession != s:
					add(FindingInvalidLink, s, fmt.Sprintf("link names successor %q", link.SuccessorSession))
				default:
					d.chain.Link = &link
				}
			case recorderEntryType:
				rcpt, rErr := receiptFromEntry(entry)
				if rErr != nil {
					d.chain.Error = rErr.Error()
					add(FindingCorruptChain, s, rErr.Error())
					continue
				}
				d.receipts = append(d.receipts, *rcpt)
			}
		}
	}

	// Key trust across links: an endorsed successor key joins the pinned set
	// for that chain only.
	endorsed := make(map[string]bool)
	for _, s := range sessions {
		link := data[s].chain.Link
		if link == nil || link.SuccessorSignerKey == link.PredecessorSignerKey {
			continue
		}
		for _, e := range opts.Endorsements {
			if VerifyCrossChainEndorsement(e, *link) == nil {
				endorsed[s] = true
				break
			}
		}
	}

	for _, s := range sessions {
		d := data[s]
		if d.chain.Error != "" || len(d.receipts) == 0 {
			d.chain.Valid = d.chain.Error == ""
			continue
		}
		trusted := opts.TrustedKeys
		if endorsed[s] && len(trusted) > 0 {
			trusted = append(slices.Clone(trusted), d.chain.Link.SuccessorSignerKey)
		}
		res := VerifyChainTrusted(d.receipts, trusted)
		ok := res.Valid || (res.FailureKind == ChainFailureLifecycleOpen && res.IntegrityVerified)
		d.chain.Receipts = len(d.receipts)
		d.chain.SignerKey = d.receipts[0].SignerKey
		last := d.receipts[len(d.receipts)-1]
		d.chain.FinalSeq = last.ActionRecord.ChainSeq
		if h, hErr := ReceiptHash(last); hErr == nil {
			d.chain.TailHash = h
		}
		if !ok {
			d.chain.Error = res.Error
			add(FindingCorruptChain, s, res.Error)
			continue
		}
		d.chain.Valid = true
	}

	successors := make(map[string][]string)
	for _, s := range sessions {
		d := data[s]
		link := d.chain.Link
		if link == nil {
			continue
		}
		successors[link.PredecessorSession] = append(successors[link.PredecessorSession], s)
		if len(d.receipts) > 0 && d.receipts[0].SignerKey != link.SuccessorSignerKey {
			add(FindingInvalidLink, s, "link successor key does not sign the chain")
		}
		pred, exists := data[link.PredecessorSession]
		if !exists {
			add(FindingDanglingLink, s, fmt.Sprintf("predecessor %q not found", link.PredecessorSession))
			continue
		}
		if !pred.chain.Valid || len(pred.receipts) == 0 {
			add(FindingPredecessorUnverified, s, fmt.Sprintf("predecessor %q did not verify", link.PredecessorSession))
			continue
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
		case slices.Contains(opts.TrustedKeys, link.SuccessorSignerKey):
			d.chain.LinkTrust = LinkTrustTrustedKey
		case endorsed[s]:
			d.chain.LinkTrust = LinkTrustEndorsed
		default:
			add(FindingUntrustedSuccessorKey, s, "successor key differs from predecessor key and is neither trusted nor endorsed")
		}
	}
	preds := make([]string, 0, len(successors))
	for p := range successors {
		preds = append(preds, p)
	}
	sort.Strings(preds)
	for _, p := range preds {
		if len(successors[p]) > 1 {
			add(FindingDoubleSuccessor, p, fmt.Sprintf("claimed by %d successors: %v", len(successors[p]), successors[p]))
		}
	}

	for _, s := range sessions {
		report.Chains = append(report.Chains, data[s].chain)
	}
	return report, nil
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

func chainLinkFromEntry(entry recorder.Entry) (ChainLink, error) {
	raw := entry.RawDetail
	if len(raw) == 0 {
		b, err := json.Marshal(entry.Detail)
		if err != nil {
			return ChainLink{}, fmt.Errorf("encoding chain link detail: %w", err)
		}
		raw = b
	}
	return UnmarshalChainLink(raw)
}

// readSessionEntries reads every recorder entry of session, in shard order.
func readSessionEntries(dir, session string) ([]recorder.Entry, error) {
	files, err := recorderFiles(dir, session)
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
