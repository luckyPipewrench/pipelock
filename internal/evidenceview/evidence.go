// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidenceview

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// RedactedDestination replaces a receipt Destination in the metadata view. A
// destination URL can carry a capability token or secret in its query string,
// so it is only shown to a request that authenticated with raw access.
const RedactedDestination = "[redacted — raw access required]"

// Read/timeline limit defaults.
const (
	DashboardReceiptReadLimit = 5000
	DashboardTimelineLimit    = 500
)

// SessionSummary is the left-nav row for one recorder session.
type SessionSummary struct {
	ID              string
	Agent           string
	ReceiptCount    int
	ReadLimited     bool
	StartTime       time.Time
	EndTime         time.Time
	ReceiptsEnabled bool
	Pips            []SummaryPip
	// Verdicts is the sorted, de-duplicated, lower-cased set of decision
	// verdicts that appear on this session's receipts (e.g. "block", "allow",
	// "warn", "defer"). It backs the bounded session-level verdict filter so a
	// "show agents that blocked something" query has real effect instead of
	// silently matching everything.
	Verdicts []string
}

// HasVerdict reports whether at least one receipt in this session carried the
// given verdict. The comparison is on the normalized (trimmed, lower-cased)
// verdict, matching how sessionVerdicts records them.
func (s SessionSummary) HasVerdict(verdict string) bool {
	want := strings.ToLower(strings.TrimSpace(verdict))
	if want == "" {
		return true
	}
	for _, v := range s.Verdicts {
		if v == want {
			return true
		}
	}
	return false
}

// sessionVerdicts returns the sorted, de-duplicated, lower-cased set of
// verdicts present across the given receipts. Empty verdicts are skipped so an
// unset field never becomes a spurious filter match.
func sessionVerdicts(receipts []receipt.Receipt) []string {
	seen := make(map[string]struct{}, 4)
	for _, r := range receipts {
		v := strings.ToLower(strings.TrimSpace(r.ActionRecord.Verdict))
		if v == "" {
			continue
		}
		seen[v] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// SummaryPip is a compact state indicator for one scorecard line.
type SummaryPip struct {
	State string
	Label string
}

// SessionEvidence is the full Evidence view for one session.
type SessionEvidence struct {
	ID              string
	Agent           string
	ReceiptsEnabled bool
	ReceiptCount    int
	Receipts        []receipt.Receipt
	ReadLimited     bool
	ReadLimit       int
	TimelineLimited bool
	TimelineLimit   int
	TimelineWindow  string
	Chain           receipt.ChainResult
	Scorecard       Scorecard
	Timeline        []TimelineItem
	TrustedKeyText  string
	// RawRedacted is true when this view was rendered without raw access, so the
	// template shows a "raw access required" note instead of the signed payload.
	RawRedacted bool
}

// TimelineItem is one rendered receipt row.
type TimelineItem struct {
	Seq          uint64
	Time         time.Time
	Verdict      string
	Reason       string
	Destination  string
	PrevShort    string
	HashShort    string
	Unverifiable bool
	RawJSON      string
}

// SessionSummaryOf computes a SessionSummary for one session's receipts.
func SessionSummaryOf(id string, receipts []receipt.Receipt, trustedKeys map[string]TrustedKey, readLimited bool, readLimit int) SessionSummary {
	if len(receipts) == 0 {
		return SessionSummary{
			ID:              id,
			Agent:           id,
			ReceiptsEnabled: false,
			Pips:            ScorecardPips(AbsentScorecard()),
		}
	}

	var scorecard Scorecard
	if readLimited {
		scorecard = ReadLimitedScorecard(len(receipts), readLimit)
	} else {
		scorecard = ComputeScorecard(receipts, trustedKeys, id).Scorecard
	}
	return SessionSummary{
		ID:              id,
		Agent:           agentLabel(id, receipts),
		ReceiptCount:    len(receipts),
		ReadLimited:     readLimited,
		StartTime:       receipts[0].ActionRecord.Timestamp,
		EndTime:         receipts[len(receipts)-1].ActionRecord.Timestamp,
		ReceiptsEnabled: true,
		Pips:            ScorecardPips(scorecard),
		Verdicts:        sessionVerdicts(receipts),
	}
}

// SessionEvidenceOf computes the full SessionEvidence for one session's receipts.
func SessionEvidenceOf(id string, receipts []receipt.Receipt, trustedKeys map[string]TrustedKey, readLimited bool, readLimit, timelineLimit int) SessionEvidence {
	if len(receipts) == 0 {
		return SessionEvidence{
			ID:              id,
			Agent:           id,
			ReceiptsEnabled: false,
			Scorecard:       AbsentScorecard(),
			TrustedKeyText:  "none",
		}
	}

	result := ComputeScorecard(receipts, trustedKeys, id)
	scorecard := result.Scorecard
	if readLimited {
		scorecard = ReadLimitedScorecard(len(receipts), readLimit)
	}
	timelineReceipts, timelineStartIndex, timelineLimited, timelineWindow := selectTimelineReceipts(receipts, readLimited, timelineLimit)
	return SessionEvidence{
		ID:              id,
		Agent:           agentLabel(id, receipts),
		ReceiptsEnabled: true,
		ReceiptCount:    len(receipts),
		Receipts:        append([]receipt.Receipt(nil), receipts...),
		ReadLimited:     readLimited,
		ReadLimit:       readLimit,
		TimelineLimited: timelineLimited,
		TimelineLimit:   timelineLimit,
		TimelineWindow:  timelineWindow,
		Chain:           result.Chain,
		Scorecard:       scorecard,
		Timeline:        buildTimeline(timelineReceipts, timelineStartIndex, result.Chain),
		TrustedKeyText:  FormatKeyList(TrustedKeysForSession(SignerKeys(receipts), trustedKeys)),
	}
}

// ScorecardPips returns the compact pip indicators for the four scorecard lines.
func ScorecardPips(scorecard Scorecard) []SummaryPip {
	return []SummaryPip{
		{State: scorecard.Authentic.State, Label: "A"},
		{State: scorecard.Untampered.State, Label: "U"},
		{State: scorecard.Anchored.State, Label: "N"},
		{State: scorecard.Completeness.State, Label: "C"},
	}
}

func agentLabel(id string, receipts []receipt.Receipt) string {
	if len(receipts) == 0 {
		return id
	}
	first := receipts[0].ActionRecord
	if first.Actor != "" {
		return first.Actor
	}
	if first.SessionID != "" {
		return first.SessionID
	}
	return id
}

func buildTimeline(receipts []receipt.Receipt, startIndex int, chain receipt.ChainResult) []TimelineItem {
	items := make([]TimelineItem, 0, len(receipts))
	for i, r := range receipts {
		ar := r.ActionRecord
		hash, err := receipt.ReceiptHash(r)
		if err != nil {
			hash = "hash-error"
		}
		raw, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			raw = []byte(`{"error":"receipt marshal failed"}`)
		}
		items = append(items, TimelineItem{
			Seq:          ar.ChainSeq,
			Time:         ar.Timestamp,
			Verdict:      ar.Verdict,
			Reason:       reasonLabel(ar.Layer, ar.Pattern, ar.ActionType),
			Destination:  ar.Target,
			PrevShort:    shortHash(ar.ChainPrevHash),
			HashShort:    shortHash(hash),
			Unverifiable: !chain.Valid && startIndex+i >= chain.BrokenAtIndex,
			RawJSON:      string(raw),
		})
	}
	return items
}

func selectTimelineReceipts(receipts []receipt.Receipt, readLimited bool, timelineLimit int) ([]receipt.Receipt, int, bool, string) {
	if timelineLimit <= 0 {
		timelineLimit = DashboardTimelineLimit
	}
	if len(receipts) <= timelineLimit {
		return receipts, 0, false, "all"
	}
	if readLimited {
		return receipts[:timelineLimit], 0, true, "first"
	}
	start := len(receipts) - timelineLimit
	return receipts[start:], start, true, "latest"
}

func reasonLabel(layer, pattern string, actionType receipt.ActionType) string {
	switch {
	case layer != "" && pattern != "":
		return layer + " / " + pattern
	case layer != "":
		return layer
	case pattern != "":
		return pattern
	case actionType != "":
		return string(actionType)
	default:
		return "policy decision"
	}
}

func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

// RedactRaw strips the raw exfil surface from an evidence view: every receipt's
// destination and full signed payload. It operates on the freshly built value,
// so callers hand the redacted copy to the template and the raw bytes never
// reach the response. Idempotent and safe on a zero value.
func RedactRaw(ev SessionEvidence) SessionEvidence {
	ev.RawRedacted = true
	ev.Receipts = nil
	// ev is passed by value, but ev.Timeline shares its backing array with the
	// caller's slice. Copy it before redacting so this never mutates the
	// caller's (possibly raw) evidence in place.
	if len(ev.Timeline) > 0 {
		timeline := make([]TimelineItem, len(ev.Timeline))
		copy(timeline, ev.Timeline)
		for i := range timeline {
			timeline[i].Destination = RedactedDestination
			timeline[i].RawJSON = ""
		}
		ev.Timeline = timeline
	}
	return ev
}

// CloneTrustedKeys returns a shallow copy of the trusted key map.
func CloneTrustedKeys(in map[string]TrustedKey) map[string]TrustedKey {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]TrustedKey, len(in))
	for key, trusted := range in {
		out[key] = trusted
	}
	return out
}
