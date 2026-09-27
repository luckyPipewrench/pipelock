// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// chainSetReport is the directory-mode report when the evidence directory
// holds per-run receipt chains: one chain report per run, then the base's
// restart continuity. Unlinked runs are always listed, because a passing
// result is not proof that no run's evidence is missing.
type chainSetReport struct {
	Path       string             `json:"path"`
	Base       string             `json:"base"`
	Valid      bool               `json:"valid"`
	Chains     []chainSetEntry    `json:"chains"`
	Continuity chainSetContinuity `json:"continuity"`
}

type chainSetEntry struct {
	Session string `json:"session"`
	chainReport
}

type chainSetContinuity struct {
	Healthy  bool              `json:"healthy"`
	Linked   []chainSetLink    `json:"linked"`
	Unlinked []string          `json:"unlinked"`
	Findings []chainSetFinding `json:"findings"`
}

type chainSetLink struct {
	Session            string `json:"session"`
	PredecessorSession string `json:"predecessor_session"`
	PredecessorTailSeq uint64 `json:"predecessor_tail_seq"`
	Trust              string `json:"trust"`
}

type chainSetFinding struct {
	Kind    string `json:"kind"`
	Session string `json:"session"`
	Detail  string `json:"detail"`
}

// runChainSetIfRuns verifies the whole base when the directory holds per-run
// chains of it, and reports handled=false otherwise so the caller keeps the
// single-session path. The base is the --session value, or its base when it
// names a run session.
//
// With an explicit --session the report keeps its single-session shape, but
// the whole base is still verified and any finding in it fails the result,
// naming the offending run, as in verify-receipt: a run's standing depends on
// base facts only a base pass sees, such as whether its predecessor's tail
// matches its link, whether the predecessor has a second successor, or
// whether another chain replays it.
func runChainSetIfRuns(stdout, stderr io.Writer, location recorder.EvidenceLocation, trust chainTrust, opts chainOptions) (bool, error) {
	base := opts.sessionID
	if b, ok := actionreceipt.RunSessionBase(base); ok {
		base = b
	}
	sessions, err := actionreceipt.ResolveBaseSessions(location.Dir, base)
	if err != nil {
		return true, evidenceContentError(fmt.Errorf("listing receipt chains: %w", err))
	}
	hasRuns := false
	for _, s := range sessions {
		if _, ok := actionreceipt.RunSessionBase(s); ok {
			hasRuns = true
			break
		}
	}
	if !hasRuns {
		return false, nil
	}
	baseReport, err := actionreceipt.VerifyBase(location.Dir, base, actionreceipt.BaseVerifyOptions{
		TrustedKeys:  trust.keys,
		Endorsements: trust.endorsements,
	})
	if err != nil {
		return true, evidenceContentError(fmt.Errorf("restart continuity check incomplete: %w", err))
	}
	report := chainSetReport{
		Path:   location.Dir,
		Base:   base,
		Chains: make([]chainSetEntry, 0, len(sessions)),
		Continuity: chainSetContinuity{
			Healthy:  baseReport.Healthy(),
			Linked:   []chainSetLink{},
			Unlinked: baseReport.Unlinked(),
			Findings: []chainSetFinding{},
		},
	}
	if report.Continuity.Unlinked == nil {
		report.Continuity.Unlinked = []string{}
	}
	baseChains := make(map[string]actionreceipt.BaseChain, len(baseReport.Chains))
	for _, c := range baseReport.Chains {
		baseChains[c.Session] = c
	}
	for _, c := range baseReport.Chains {
		if c.Link == nil {
			continue
		}
		linkTrust := c.LinkTrust
		if linkTrust == "" {
			linkTrust = "untrusted"
		}
		report.Continuity.Linked = append(report.Continuity.Linked, chainSetLink{
			Session:            c.Session,
			PredecessorSession: c.Link.PredecessorSession,
			PredecessorTailSeq: c.Link.PredecessorTailSeq,
			Trust:              linkTrust,
		})
	}
	for _, f := range baseReport.Findings {
		report.Continuity.Findings = append(report.Continuity.Findings, chainSetFinding(f))
	}
	if opts.sessionExplicit {
		return true, runNamedChainInBase(stdout, stderr, location, report, baseReport, trust, opts)
	}
	valid := report.Continuity.Healthy
	for _, s := range sessions {
		keys, own := actionreceipt.ScopedChainTrust(baseReport, s, trust.keys, trust.endorsements)
		chain, chainErr := sessionChainReport(location, s, chainTrust{keys: keys, endorsements: own, session: s}, opts)
		// The base check reads what a per-run report does not, such as a
		// forged receipt the per-run pass missed. A line must not say valid
		// when that check failed.
		if bc, ok := baseChains[s]; ok && !bc.Valid && chain.Valid {
			chain.Valid = false
			chain.Unpinned = false
			chain.Error = "base check: " + bc.Error
		}
		if chainErr != nil || !chain.Valid {
			valid = false
		}
		report.Chains = append(report.Chains, chainSetEntry{Session: s, chainReport: chain})
	}
	report.Valid = valid
	emitChainSetReport(stdout, stderr, report, opts.jsonOutput)
	if !report.Valid {
		return true, cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New(chainSetFailureReason(report)))
	}
	return true, nil
}

// runNamedChainInBase reports the one run --session names, in the
// single-session report shape, and fails it on any finding in its base.
func runNamedChainInBase(stdout, stderr io.Writer, location recorder.EvidenceLocation, set chainSetReport, baseReport actionreceipt.BaseReport, trust chainTrust, opts chainOptions) error {
	s := opts.sessionID
	keys, own := actionreceipt.ScopedChainTrust(baseReport, s, trust.keys, trust.endorsements)
	chain, chainErr := sessionChainReport(location, s, chainTrust{keys: keys, endorsements: own, session: s}, opts)
	if chainErr == nil && chain.Valid && !baseReport.Healthy() {
		f := baseReport.Findings[0]
		chain.Valid = false
		chain.Unpinned = false
		chain.Error = fmt.Sprintf("restart continuity: %d finding(s) in base %q, first %s on %s: %s",
			len(baseReport.Findings), set.Base, f.Kind, f.Session, f.Detail)
	}
	emitChainReport(stdout, stderr, chain, opts.jsonOutput)
	if !opts.jsonOutput {
		emitContinuity(stdout, set)
	}
	if chainErr != nil {
		return evidenceContentError(fmt.Errorf("%s: %w", s, chainErr))
	}
	if !chain.Valid {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("%s: %s", s, chain.Error))
	}
	return nil
}

// chainSetFailureReason names what failed, for the one-line error.
func chainSetFailureReason(r chainSetReport) string {
	var failed []string
	for _, c := range r.Chains {
		if !c.Valid {
			failed = append(failed, c.Session)
		}
	}
	parts := []string{"receipt chain set rejected"}
	if len(failed) > 0 {
		parts = append(parts, fmt.Sprintf("chain(s) failed: %s", strings.Join(failed, ", ")))
	}
	if n := len(r.Continuity.Findings); n > 0 {
		f := r.Continuity.Findings[0]
		parts = append(parts, fmt.Sprintf("%d base finding(s), first %s on %s", n, f.Kind, f.Session))
	}
	return strings.Join(parts, "; ")
}

// sessionChainReport verifies one run exactly as --session <run> does: its
// EvidenceReceipt v2 chain and its ActionReceipt v1 chain when it has both,
// else whichever one it has.
func sessionChainReport(location recorder.EvidenceLocation, session string, trust chainTrust, opts chainOptions) (chainReport, error) {
	label := fmt.Sprintf("%s (session %s)", location.Dir, session)
	v2, err := contractreceipt.ExtractEvidenceReceiptsFromResolvedSessionDir(location, session)
	if err != nil {
		return chainReport{Path: label, Error: fmt.Sprintf("extract evidence receipts: %v", err)}, err
	}
	if len(v2) > 0 {
		v1, v1Err := sessionActionReceipts(location, session)
		if v1Err != nil {
			return chainReport{Path: label, Error: fmt.Sprintf("extract receipts: %v", v1Err)}, v1Err
		}
		report, reportErr := evidenceChainReport(label, v2, trust, opts)
		return withActionChain(report, reportErr, label, v1, trust, opts)
	}
	if opts.anySet() {
		err := fmt.Errorf("EvidenceReceipt expectation flags require record_type=%s", recordTypeEvidenceV2)
		return chainReport{Path: label, Error: err.Error()}, err
	}
	receipts, err := actionreceipt.ExtractReceiptsFromResolvedSessionDir(location, session)
	if err != nil {
		return chainReport{Path: label, Error: fmt.Sprintf("extract receipts: %v", err)}, err
	}
	return actionChainReport(label, receipts, trust, opts)
}

func emitChainSetReport(stdout, stderr io.Writer, r chainSetReport, jsonMode bool) {
	if jsonMode {
		writeJSON(stdout, r)
		return
	}
	for _, c := range r.Chains {
		emitChainReport(stdout, stderr, c.chainReport, false)
	}
	emitContinuity(stdout, r)
	result := "VALID"
	if !r.Valid {
		result = "INVALID"
	}
	_, _ = fmt.Fprintf(stdout, "  result:     %s\n", result)
}

// emitContinuity prints a base's restart continuity. Unlinked runs are always
// listed, because a passing result must not read as proof of continuity.
func emitContinuity(stdout io.Writer, r chainSetReport) {
	label := "RESTART CONTINUITY OK"
	if !r.Continuity.Healthy {
		label = "RESTART CONTINUITY FAILED"
	}
	chains := len(r.Chains)
	if chains == 0 {
		chains = len(r.Continuity.Linked) + len(r.Continuity.Unlinked)
	}
	_, _ = fmt.Fprintf(stdout, "%s: base %q: %d chain(s), %d linked, %d unlinked, %d link finding(s)\n",
		label, r.Base, chains, len(r.Continuity.Linked), len(r.Continuity.Unlinked), len(r.Continuity.Findings))
	for _, l := range r.Continuity.Linked {
		_, _ = fmt.Fprintf(stdout, "  linked:   %s continues %s at seq %d (%s)\n", l.Session, l.PredecessorSession, l.PredecessorTailSeq, l.Trust)
	}
	for _, s := range r.Continuity.Unlinked {
		_, _ = fmt.Fprintf(stdout, "  unlinked: %s\n", s)
	}
	for _, f := range r.Continuity.Findings {
		_, _ = fmt.Fprintf(stdout, "  - %s: %s: %s\n", f.Kind, f.Session, f.Detail)
	}
	_, _ = fmt.Fprintln(stdout, "  Note: an unlinked run claims no predecessor. That is normal for a first run or concurrent runs,")
	_, _ = fmt.Fprintln(stdout, "  and it is also what a deleted link file looks like: this does not prove no run's evidence is missing.")
}
