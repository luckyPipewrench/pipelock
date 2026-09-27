// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"

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
func runChainSetIfRuns(stdout, stderr io.Writer, location recorder.EvidenceLocation, keyHex string, opts chainOptions) (bool, error) {
	base := opts.sessionID
	if b, ok := actionreceipt.RunSessionBase(base); ok {
		base = b
	}
	sessions, err := actionreceipt.ResolveBaseSessions(location.Dir, base)
	if err != nil {
		return true, cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("listing receipt chains: %w", err))
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
	var trusted []string
	if keyHex != "" {
		trusted = []string{keyHex}
	}
	baseReport, err := actionreceipt.VerifyBase(location.Dir, base, actionreceipt.BaseVerifyOptions{TrustedKeys: trusted})
	if err != nil {
		return true, cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("restart continuity check incomplete: %w", err))
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
	valid := report.Continuity.Healthy
	for _, s := range sessions {
		chainOpts := opts
		chainOpts.sessionID = s
		chain, chainErr := sessionChainReport(location, s, keyHex, chainOpts)
		// A run whose v2 chain verifies can still hold a forged action
		// receipt, which only the base check reads. Its line must not say
		// valid when that check failed.
		if bc, ok := baseChains[s]; ok && !bc.Valid && chain.Valid {
			chain.Valid = false
			chain.Unpinned = false
			chain.Error = "action receipt chain: " + bc.Error
		}
		if chainErr != nil || !chain.Valid {
			valid = false
		}
		report.Chains = append(report.Chains, chainSetEntry{Session: s, chainReport: chain})
	}
	for _, c := range baseReport.Chains {
		if c.Link == nil {
			continue
		}
		trust := c.LinkTrust
		if trust == "" {
			trust = "untrusted"
		}
		report.Continuity.Linked = append(report.Continuity.Linked, chainSetLink{
			Session:            c.Session,
			PredecessorSession: c.Link.PredecessorSession,
			PredecessorTailSeq: c.Link.PredecessorTailSeq,
			Trust:              trust,
		})
	}
	for _, f := range baseReport.Findings {
		report.Continuity.Findings = append(report.Continuity.Findings, chainSetFinding(f))
	}
	report.Valid = valid
	emitChainSetReport(stdout, stderr, report, opts.jsonOutput)
	if !report.Valid {
		return true, cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New("receipt chain set rejected"))
	}
	return true, nil
}

// sessionChainReport verifies one run exactly as --session <run> does: its
// EvidenceReceipt v2 chain and its ActionReceipt v1 chain when it has both,
// else whichever one it has.
func sessionChainReport(location recorder.EvidenceLocation, session, keyHex string, opts chainOptions) (chainReport, error) {
	label := fmt.Sprintf("%s (session %s)", location.Dir, session)
	v2, err := contractreceipt.ExtractEvidenceReceiptsFromResolvedSessionDir(location, session)
	if err != nil {
		return chainReport{Path: label, Error: fmt.Sprintf("extract evidence receipts: %v", err)}, err
	}
	if len(v2) > 0 {
		chainOpts, optsErr := opts.chainVerifyOptions(keyHex)
		if optsErr != nil {
			return chainReport{Path: label, Error: optsErr.Error()}, optsErr
		}
		v1, v1Err := sessionActionReceipts(location, session)
		if v1Err != nil {
			return chainReport{Path: label, Error: fmt.Sprintf("extract receipts: %v", v1Err)}, v1Err
		}
		report, reportErr := evidenceChainReport(label, v2, chainOpts, opts)
		return withActionChain(report, reportErr, label, v1, keyHex, opts)
	}
	if opts.anySet() {
		err := fmt.Errorf("EvidenceReceipt expectation flags require record_type=%s", recordTypeEvidenceV2)
		return chainReport{Path: label, Error: err.Error()}, err
	}
	receipts, err := actionreceipt.ExtractReceiptsFromResolvedSessionDir(location, session)
	if err != nil {
		return chainReport{Path: label, Error: fmt.Sprintf("extract receipts: %v", err)}, err
	}
	return actionChainReport(label, receipts, keyHex, opts)
}

func emitChainSetReport(stdout, stderr io.Writer, r chainSetReport, jsonMode bool) {
	if jsonMode {
		writeJSON(stdout, r)
		return
	}
	for _, c := range r.Chains {
		emitChainReport(stdout, stderr, c.chainReport, false)
	}
	label := "RESTART CONTINUITY OK"
	if !r.Continuity.Healthy {
		label = "RESTART CONTINUITY FAILED"
	}
	_, _ = fmt.Fprintf(stdout, "%s: base %q: %d chain(s), %d linked, %d unlinked, %d link finding(s)\n",
		label, r.Base, len(r.Chains), len(r.Continuity.Linked), len(r.Continuity.Unlinked), len(r.Continuity.Findings))
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
	result := "VALID"
	if !r.Valid {
		result = "INVALID"
	}
	_, _ = fmt.Fprintf(stdout, "  result:     %s\n", result)
}
