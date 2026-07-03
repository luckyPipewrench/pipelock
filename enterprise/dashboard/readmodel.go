//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	dashboardReceiptReadLimit = 5000
	dashboardTimelineLimit    = 500
)

// Options configures the read-only Evidence dashboard.
type Options struct {
	ReceiptDir  string
	TrustedKeys map[string]TrustedKey
	HasFeature  func(string) bool
	// Authorize, when non-nil, runs per request after the license-feature check
	// and fails the request closed (403) on a non-nil error. It is the handler's
	// authentication/authorization seam, distinct from the license entitlement
	// check. Nil means the surrounding router must own authentication.
	Authorize        func(*http.Request) error
	ReceiptReadLimit int
	TimelineLimit    int
}

// ReadModel builds dashboard views over recorder sessions and receipts.
type ReadModel struct {
	receiptDir       string
	trustedKeys      map[string]TrustedKey
	receiptReadLimit int
	timelineLimit    int
}

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

// NewReadModel creates a dashboard read model from Options.
func NewReadModel(opts Options) *ReadModel {
	receiptReadLimit := opts.ReceiptReadLimit
	if receiptReadLimit <= 0 {
		receiptReadLimit = dashboardReceiptReadLimit
	}
	timelineLimit := opts.TimelineLimit
	if timelineLimit <= 0 {
		timelineLimit = dashboardTimelineLimit
	}
	return &ReadModel{
		receiptDir:       opts.ReceiptDir,
		trustedKeys:      cloneTrustedKeys(opts.TrustedKeys),
		receiptReadLimit: receiptReadLimit,
		timelineLimit:    timelineLimit,
	}
}

// Sessions lists available recorder sessions and computes their compact state.
func (m *ReadModel) Sessions() ([]SessionSummary, error) {
	ids, err := recorder.ListSessions(m.receiptDir)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}

	summaries := make([]SessionSummary, 0, len(ids))
	for _, id := range ids {
		receipts, readLimited, err := receipt.ExtractReceiptsFromSessionDirBounded(m.receiptDir, id, m.receiptReadLimit)
		if err != nil {
			return nil, fmt.Errorf("read session %s receipts: %w", id, err)
		}
		summaries = append(summaries, sessionSummary(id, receipts, m.trustedKeys, readLimited, m.receiptReadLimit))
	}
	return summaries, nil
}

// Session reads one session's complete evidence.
func (m *ReadModel) Session(id string) (SessionEvidence, error) {
	receipts, readLimited, err := receipt.ExtractReceiptsFromSessionDirBounded(m.receiptDir, id, m.receiptReadLimit)
	if err != nil {
		return SessionEvidence{}, fmt.Errorf("read session %s receipts: %w", id, err)
	}
	return sessionEvidence(id, receipts, m.trustedKeys, readLimited, m.receiptReadLimit, m.timelineLimit), nil
}

func sessionSummary(id string, receipts []receipt.Receipt, trustedKeys map[string]TrustedKey, readLimited bool, readLimit int) SessionSummary {
	if len(receipts) == 0 {
		return SessionSummary{
			ID:              id,
			Agent:           id,
			ReceiptsEnabled: false,
			Pips:            scorecardPips(absentScorecard()),
		}
	}

	var scorecard Scorecard
	if readLimited {
		scorecard = readLimitedScorecard(len(receipts), readLimit)
	} else {
		scorecard = computeScorecard(receipts, trustedKeys, id).Scorecard
	}
	return SessionSummary{
		ID:              id,
		Agent:           agentLabel(id, receipts),
		ReceiptCount:    len(receipts),
		ReadLimited:     readLimited,
		StartTime:       receipts[0].ActionRecord.Timestamp,
		EndTime:         receipts[len(receipts)-1].ActionRecord.Timestamp,
		ReceiptsEnabled: true,
		Pips:            scorecardPips(scorecard),
	}
}

func sessionEvidence(id string, receipts []receipt.Receipt, trustedKeys map[string]TrustedKey, readLimited bool, readLimit, timelineLimit int) SessionEvidence {
	if len(receipts) == 0 {
		return SessionEvidence{
			ID:              id,
			Agent:           id,
			ReceiptsEnabled: false,
			Scorecard:       absentScorecard(),
			TrustedKeyText:  "none",
		}
	}

	result := computeScorecard(receipts, trustedKeys, id)
	scorecard := result.Scorecard
	if readLimited {
		scorecard = readLimitedScorecard(len(receipts), readLimit)
	}
	timelineReceipts, timelineStartIndex, timelineLimited, timelineWindow := selectTimelineReceipts(receipts, readLimited, timelineLimit)
	return SessionEvidence{
		ID:              id,
		Agent:           agentLabel(id, receipts),
		ReceiptsEnabled: true,
		Receipts:        append([]receipt.Receipt(nil), receipts...),
		ReadLimited:     readLimited,
		ReadLimit:       readLimit,
		TimelineLimited: timelineLimited,
		TimelineLimit:   timelineLimit,
		TimelineWindow:  timelineWindow,
		Chain:           result.Chain,
		Scorecard:       scorecard,
		Timeline:        buildTimeline(timelineReceipts, timelineStartIndex, result.Chain),
		TrustedKeyText:  formatKeyList(trustedKeysForSession(signerKeys(receipts), trustedKeys)),
	}
}

func scorecardPips(scorecard Scorecard) []SummaryPip {
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
		timelineLimit = dashboardTimelineLimit
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

func cloneTrustedKeys(in map[string]TrustedKey) map[string]TrustedKey {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]TrustedKey, len(in))
	for key, trusted := range in {
		out[key] = trusted
	}
	return out
}
