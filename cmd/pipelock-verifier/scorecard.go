// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/evidence/completeness"
	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
)

const scorecardSchema = "pipelock.scorecard.v1"

type scorecard struct {
	Schema       string                    `json:"schema"`
	Authentic    scorecardAuthentic        `json:"authentic"`
	Untampered   scorecardUntampered       `json:"untampered"`
	Anchored     scorecardAnchored         `json:"anchored"`
	Completeness scorecardCompletenessLine `json:"completeness"`
}

type scorecardAuthentic struct {
	Status              string `json:"status"`
	SelfConsistentCount uint64 `json:"self_consistency_count"`
	Detail              string `json:"detail,omitempty"`
}

type scorecardUntampered struct {
	Status      string `json:"status"`
	BrokenAtSeq uint64 `json:"broken_at_seq,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type scorecardAnchored struct {
	Status string   `json:"status"`
	Detail string   `json:"detail,omitempty"`
	Limits []string `json:"limits,omitempty"`
}

type scorecardCompletenessLine struct {
	Status              completeness.Status `json:"status"`
	Reason              completeness.Reason `json:"reason"`
	ReceiptCount        uint64              `json:"receipt_count"`
	GapCount            uint64              `json:"gap_count"`
	CoveredWindowStart  uint64              `json:"covered_window_start"`
	CoveredWindowEnd    uint64              `json:"covered_window_end"`
	HeartbeatContinuity string              `json:"heartbeat_continuity"`
	StandingExclusions  []string            `json:"standing_exclusions"`
}

func newActionScorecard(res actionreceipt.ChainResult, keyPinned bool, report completeness.Report) scorecard {
	authentic := scorecardAuthentic{
		Status:              "FAIL",
		SelfConsistentCount: res.ReceiptCount,
	}
	if res.IntegrityVerified || res.Valid {
		authentic.Status = "PASS"
	}
	if !keyPinned {
		authentic.Status = "UNVERIFIED"
		authentic.Detail = "no trusted signer key pinned"
	}
	untampered := scorecardUntampered{Status: "FAIL", BrokenAtSeq: res.BrokenAtSeq, Reason: res.Error}
	if res.Valid || res.IntegrityVerified {
		untampered = scorecardUntampered{Status: "PASS"}
	}
	gaps := uint64(0)
	heartbeat := "continuous"
	for _, run := range report.Runs {
		if run.UnmatchedIntents > 0 {
			gaps += uint64(run.UnmatchedIntents)
		}
		if run.HeartbeatGapDetected {
			heartbeat = "gap_detected"
		}
	}
	return scorecard{
		Schema:     scorecardSchema,
		Authentic:  authentic,
		Untampered: untampered,
		Anchored: scorecardAnchored{
			Status: "UNVERIFIED",
			Detail: "no anchor bundle supplied",
		},
		Completeness: scorecardCompletenessLine{
			Status:              report.Status,
			Reason:              report.Reason,
			ReceiptCount:        report.ReceiptCount,
			GapCount:            gaps,
			CoveredWindowStart:  0,
			CoveredWindowEnd:    report.FinalSeq,
			HeartbeatContinuity: heartbeat,
			StandingExclusions: []string{
				"mediated evidence cannot prove unmediated egress did not occur",
				"local recorder evidence cannot prove wall-clock completeness without external witnessing",
			},
		},
	}
}

func emitScorecard(out io.Writer, sc scorecard) {
	_, _ = fmt.Fprintf(out, "Authentic: %s self_consistency_count=%d", sc.Authentic.Status, sc.Authentic.SelfConsistentCount)
	if sc.Authentic.Detail != "" {
		_, _ = fmt.Fprintf(out, " detail=%q", sc.Authentic.Detail)
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "Untampered: %s", sc.Untampered.Status)
	if sc.Untampered.Status == "FAIL" {
		_, _ = fmt.Fprintf(out, " broken at seq %d reason=%q", sc.Untampered.BrokenAtSeq, sc.Untampered.Reason)
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "Anchored: %s", sc.Anchored.Status)
	if sc.Anchored.Detail != "" {
		_, _ = fmt.Fprintf(out, " detail=%q", sc.Anchored.Detail)
	}
	if len(sc.Anchored.Limits) > 0 {
		_, _ = fmt.Fprintf(out, " limits=%q", strings.Join(sc.Anchored.Limits, " | "))
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "Completeness: %s receipts=%d gaps=%d covered_window=%d..%d heartbeat=%s exclusions=%q\n",
		sc.Completeness.Status,
		sc.Completeness.ReceiptCount,
		sc.Completeness.GapCount,
		sc.Completeness.CoveredWindowStart,
		sc.Completeness.CoveredWindowEnd,
		sc.Completeness.HeartbeatContinuity,
		strings.Join(sc.Completeness.StandingExclusions, " | "),
	)
}
