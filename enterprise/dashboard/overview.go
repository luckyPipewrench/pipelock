//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

const (
	overviewClaim    = "signed receipt evidence, accepted follower reports, configured exemptions, trust metadata, and budget snapshots already exposed by the deep views"
	overviewNonClaim = "does not certify fleet-wide clearance, does not prove absence of unmediated activity, " +
		"and does not roll up facts into a single verdict"

	overviewFleetClaim    = "accepted follower reports for the configured fleet scope"
	overviewFleetNonClaim = "absence of unmediated activity, host compromise, or activity outside the reporting window"

	overviewEnforcementClaim    = "recent mediated block, warn, and defer receipts loaded from the evidence store"
	overviewEnforcementNonClaim = "quiet agents are clean, or that unmediated traffic was observed"

	overviewEvidenceClaim    = "receipt ordering, signer trust, anchor status, and explicit no-receipt gaps from the evidence scorecard"
	overviewEvidenceNonClaim = "activity after a broken chain, activity outside loaded receipts, or trust for absent evidence"

	overviewCoverageClaim    = "receipt and follower-reporting blind spots visible to the agents and fleet read models"
	overviewCoverageNonClaim = "that an agent with no receipts or no heartbeat was idle"

	overviewGovernanceClaim    = "configured exemption lifecycle, CRL read status, alert-delivery health, and legal-hold metadata"
	overviewGovernanceNonClaim = "that expired, inert, or untracked governance state is safe to ignore"

	overviewBudgetClaim    = "budget counters returned by the configured budget source"
	overviewBudgetNonClaim = "live spend outside the snapshot, outside this process, or on unenforced transports"

	overviewReadOnlyFooter = "This console prepares, verifies, and explains. It does not publish, kill, roll back, submit, or hold signing keys."
)

type OverviewPage struct {
	Nav          NavContext
	RawAllowed   bool
	Claim        string
	NonClaim     string
	Header       OverviewHeader
	Attention    []OverviewAttentionItem
	Fleet        OverviewFleetPosture
	Enforcement  OverviewEnforcement
	Evidence     OverviewEvidenceIntegrity
	Incidents    OverviewIncidents
	Coverage     OverviewCoverage
	Governance   OverviewGovernance
	Budget       OverviewBudgetPressure
	ReadOnlyText string
}

type OverviewHeader struct {
	RedFacts   int
	AmberFacts int
	Proven     int
}

type OverviewAttentionItem struct {
	Severity   string
	Kind       string
	Fact       string
	Count      int
	CountLabel string
	Link       string
}

type OverviewFleetPosture struct {
	SourceConfigured  bool
	ScopeConfigured   bool
	SourceUnavailable bool
	Truncated         bool
	OrgID             string
	FleetID           string
	Claim             string
	NonClaim          string
	EmptyTitle        string
	EmptyDetail       string

	Reporting         int
	Stale             int
	Dark              int
	NeverReported     int
	VerifiedApplied   int
	UnsignedSelf      int
	Drift             int
	ApplyFailed       int
	SignedUnverified  int
	NoSignedState     int
	TotalAcceptedRows int
}

type OverviewEnforcement struct {
	Claim    string
	NonClaim string
	Rows     []OverviewEnforcementRow
}

type OverviewEnforcementRow struct {
	Verdict  string
	Scanner  string
	Agent    string
	Count    int
	LastSeen string
	Link     string
}

type OverviewEvidenceIntegrity struct {
	Claim          string
	NonClaim       string
	BrokenChains   int
	MissingAnchors int
	Untrusted      int
	NoReceipts     int
	Intact         int
	Rows           []OverviewEvidenceRow
}

type OverviewEvidenceRow struct {
	SessionID string
	Agent     string
	Chain     string
	Anchor    string
	Signer    string
	Receipts  int
	Severity  string
	Link      string
}

type OverviewIncidents struct {
	SourceConfigured bool
	Claim            string
	NonClaim         string
	EmptyTitle       string
	EmptyDetail      string
	Rows             []OverviewIncidentRow
}

type OverviewIncidentRow struct {
	Label  string
	Detail string
	Link   string
}

type OverviewCoverage struct {
	Claim             string
	NonClaim          string
	NoReceiptAgents   []string
	NoHeartbeatAgents []string
	MonitorOnlyAgents []string
	FleetSourceNote   string
}

type OverviewGovernance struct {
	Claim                 string
	NonClaim              string
	ConfigLoaded          bool
	ExpiredExemptions     int
	InertExemptions       int
	MisdirectedExemptions int
	CRLStatus             string
	CRLDetail             string
	AlertFailures         int
	DeliveryConfigured    bool
	DeliveryError         string
	LegalHoldConfigured   bool
	LegalHoldError        string
	ActiveLegalHolds      int
}

type OverviewBudgetPressure struct {
	SourceConfigured     bool
	SourceUnavailable    bool
	Claim                string
	NonClaim             string
	HasSnapshotFreshness bool
	SnapshotAge          string
	SnapshotStale        bool
	Rows                 []OverviewBudgetRow
	EmptyTitle           string
	EmptyDetail          string
}

type OverviewBudgetRow struct {
	Agent   string
	Percent int
	Basis   string
	Link    string
}

func (m *ReadModel) Overview(ctx context.Context, rawAllowed bool) (OverviewPage, error) {
	sessions, err := m.Sessions()
	if err != nil {
		return OverviewPage{}, err
	}
	trust, err := m.TrustKeys()
	if err != nil {
		return OverviewPage{}, err
	}
	exemptions := m.Exemptions()
	if !rawAllowed {
		exemptions = redactExemptions(exemptions)
	}
	health := m.OperabilityHealth()
	fleet := m.overviewFleet(ctx, rawAllowed)
	enforcement := m.overviewEnforcement(sessions)
	evidence := overviewEvidenceIntegrity(sessions)
	incidents := m.overviewIncidents()
	coverage := m.overviewCoverage(sessions, fleet)
	governance := m.overviewGovernance(exemptions, trust, health)
	budget, err := m.overviewBudget(ctx, rawAllowed)
	if err != nil {
		return OverviewPage{}, err
	}

	page := OverviewPage{
		RawAllowed:   rawAllowed,
		Claim:        overviewClaim,
		NonClaim:     overviewNonClaim,
		Fleet:        fleet,
		Enforcement:  enforcement,
		Evidence:     evidence,
		Incidents:    incidents,
		Coverage:     coverage,
		Governance:   governance,
		Budget:       budget,
		ReadOnlyText: overviewReadOnlyFooter,
	}
	page.Attention = m.overviewAttention(page)
	for _, item := range page.Attention {
		switch item.Severity {
		case "red":
			page.Header.RedFacts += item.Count
		case "amber":
			page.Header.AmberFacts += item.Count
		}
	}
	page.Header.Proven = page.Fleet.VerifiedApplied + page.Evidence.Intact
	return page, nil
}

func (m *ReadModel) overviewFleet(ctx context.Context, rawAllowed bool) OverviewFleetPosture {
	out := OverviewFleetPosture{
		SourceConfigured: m.fleetSource != nil,
		Claim:            overviewFleetClaim,
		NonClaim:         overviewFleetNonClaim,
		EmptyTitle:       "No fleet source configured",
		EmptyDetail:      "Fleet posture is not fabricated. Attach a FleetSource to show accepted follower reports.",
	}
	if m.fleetSource == nil {
		return out
	}
	if m.hasFeature == nil || !m.hasFeature(license.FeatureFleet) {
		out.ScopeConfigured = false
		out.EmptyTitle = "Enterprise fleet feature required"
		out.EmptyDetail = "Fleet posture requires the Enterprise fleet feature. This section stays empty instead of querying fleet sources for this license tier."
		return out
	}
	scope := m.defaultFleetScope
	if scope.OrgID == "" || scope.FleetID == "" {
		out.EmptyTitle = "No default fleet scope configured"
		out.EmptyDetail = "A FleetSource exists, but /overview has no org/fleet scope to read. This section stays empty instead of querying an ambiguous fleet."
		return out
	}
	view, err := m.FleetOverview(ctx, scope.OrgID, scope.FleetID, rawAllowed)
	if err != nil {
		// The fleet source is configured but could not be read (for example the
		// conductor is unreachable). Degrade to an explicit unavailable/unknown
		// state rather than failing the whole overview or fabricating a clean
		// posture. Honesty rule: an unreachable source is unknown, never green.
		out.SourceUnavailable = true
		out.EmptyTitle = "Fleet source unreachable"
		out.EmptyDetail = "The configured fleet source could not be read, so follower reporting posture is unknown. Treat this as unverified, not as a clean fleet."
		return out
	}
	out.ScopeConfigured = true
	out.Truncated = view.Truncated
	out.OrgID = view.OrgID
	out.FleetID = view.FleetID
	out.TotalAcceptedRows = len(view.Followers)
	now := m.now()
	for _, follower := range view.Followers {
		switch fleetFreshnessBucket(follower, now) {
		case "stale":
			out.Stale++
		case "dark":
			out.Dark++
		case "never":
			out.NeverReported++
		default:
			out.Reporting++
		}
		switch follower.SourceClass() {
		case "verified":
			out.VerifiedApplied++
		case "signed-unverified":
			out.SignedUnverified++
		case "unsigned":
			out.UnsignedSelf++
		default:
			out.NoSignedState++
		}
		if follower.Drift == "drift" {
			out.Drift++
		}
		if follower.FleetHealth == "apply_failed" {
			out.ApplyFailed++
		}
	}
	return out
}

func fleetFreshnessBucket(f FleetFollowerView, now time.Time) string {
	switch {
	case !f.RuntimeReported && !f.SignedStatePresent:
		return "never"
	case f.FleetHealth == "stale":
		return "stale"
	case f.RuntimeReported && !f.RuntimeSeenAt.IsZero() && now.Sub(f.RuntimeSeenAt) > time.Hour:
		return "dark"
	case f.FleetHealth == fleetHealthUnknown && f.Active && !f.RuntimeSeenAt.IsZero() && now.Sub(f.RuntimeSeenAt) > time.Hour:
		return "dark"
	default:
		return "reporting"
	}
}

func (m *ReadModel) overviewEnforcement(sessions []SessionSummary) OverviewEnforcement {
	out := OverviewEnforcement{Claim: overviewEnforcementClaim, NonClaim: overviewEnforcementNonClaim}
	type key struct {
		verdict string
		scanner string
		agent   string
	}
	rows := map[key]*OverviewEnforcementRow{}
	for _, summary := range sessions {
		if !summary.ReceiptsEnabled {
			continue
		}
		evidence, readErr := m.Session(summary.ID)
		if readErr != nil {
			continue
		}
		for _, r := range evidence.Receipts {
			verdict := strings.ToLower(strings.TrimSpace(r.ActionRecord.Verdict))
			if verdict != verdictBlock && verdict != verdictWarn && verdict != verdictDefer {
				continue
			}
			scanner := scannerLabel(r.ActionRecord.Layer, r.ActionRecord.Pattern)
			agent := r.ActionRecord.Actor
			if agent == "" {
				agent = evidence.Agent
			}
			k := key{verdict: verdict, scanner: scanner, agent: agent}
			row := rows[k]
			if row == nil {
				row = &OverviewEnforcementRow{
					Verdict: strings.ToUpper(verdict),
					Scanner: scanner,
					Agent:   displayOverviewString(agent),
					Link:    "/agents?verdict=" + url.QueryEscape(verdict) + "&agent=" + url.QueryEscape(agent),
				}
				rows[k] = row
			}
			row.Count++
			if row.LastSeen == "" || r.ActionRecord.Timestamp.After(parseOverviewTime(row.LastSeen)) {
				row.LastSeen = r.ActionRecord.Timestamp.UTC().Format(time.RFC3339)
			}
		}
	}
	for _, row := range rows {
		out.Rows = append(out.Rows, *row)
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		return out.Rows[i].LastSeen > out.Rows[j].LastSeen
	})
	if len(out.Rows) > 8 {
		out.Rows = out.Rows[:8]
	}
	return out
}

func scannerLabel(layer, pattern string) string {
	layer = strings.TrimSpace(layer)
	pattern = strings.TrimSpace(pattern)
	switch {
	case layer != "" && pattern != "":
		return layer + "/" + pattern
	case layer != "":
		return layer
	case pattern != "":
		return pattern
	default:
		return "unclassified"
	}
}

func parseOverviewTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339, value)
	return parsed
}

func overviewEvidenceIntegrity(sessions []SessionSummary) OverviewEvidenceIntegrity {
	out := OverviewEvidenceIntegrity{Claim: overviewEvidenceClaim, NonClaim: overviewEvidenceNonClaim}
	for _, session := range sessions {
		chain := overviewChainLabel(session)
		anchor := overviewAnchorLabel(session)
		signer := overviewSignerLabel(session)
		severity := "proven"
		if !session.ReceiptsEnabled || chain == "broken" || signer == "untrusted" {
			severity = "red"
		} else if anchor != "verified" || signer == "unverified" {
			severity = "amber"
		}
		if !session.ReceiptsEnabled {
			out.NoReceipts++
		}
		if chain == "broken" {
			out.BrokenChains++
		}
		if signer == "untrusted" {
			out.Untrusted++
		}
		if anchor != "verified" && session.ReceiptsEnabled {
			out.MissingAnchors++
		}
		if severity == "proven" {
			out.Intact++
		}
		out.Rows = append(out.Rows, OverviewEvidenceRow{
			SessionID: session.ID,
			Agent:     displayOverviewString(session.Agent),
			Chain:     chain,
			Anchor:    anchor,
			Signer:    signer,
			Receipts:  session.ReceiptCount,
			Severity:  severity,
			Link:      "/session/" + url.PathEscape(session.ID),
		})
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		if severityRank(out.Rows[i].Severity) != severityRank(out.Rows[j].Severity) {
			return severityRank(out.Rows[i].Severity) < severityRank(out.Rows[j].Severity)
		}
		return out.Rows[i].SessionID < out.Rows[j].SessionID
	})
	if len(out.Rows) > 10 {
		out.Rows = out.Rows[:10]
	}
	return out
}

func overviewChainLabel(session SessionSummary) string {
	if !session.ReceiptsEnabled {
		return "no receipts"
	}
	switch overviewPipState(session, "U") {
	case StateFail:
		return "broken"
	case StateVerify, StateLimited:
		return "intact"
	default:
		return "unverified"
	}
}

func overviewAnchorLabel(session SessionSummary) string {
	if !session.ReceiptsEnabled {
		return "absent"
	}
	if overviewPipState(session, "N") == StateVerify {
		return "verified"
	}
	return "missing"
}

func overviewSignerLabel(session SessionSummary) string {
	if !session.ReceiptsEnabled {
		return "absent"
	}
	switch overviewPipState(session, "A") {
	case StateVerify:
		return "trusted"
	case StateWarn, StateLimited:
		return "untrusted"
	default:
		return "unverified"
	}
}

func overviewPipState(session SessionSummary, label string) string {
	for _, pip := range session.Pips {
		if pip.Label == label {
			return pip.State
		}
	}
	return ""
}

func severityRank(severity string) int {
	switch severity {
	case "red":
		return 0
	case "amber":
		return 1
	default:
		return 2
	}
}

func (m *ReadModel) overviewIncidents() OverviewIncidents {
	out := OverviewIncidents{
		SourceConfigured: m.conductorSource != nil,
		Claim:            "read-only incident and replay queue entries when a list source exists",
		NonClaim:         "that a configured replay-by-hash source can list queue depth",
	}
	if m.conductorSource == nil {
		out.EmptyTitle = "No conductor decision source configured"
		out.EmptyDetail = "No incident or replay queue facts are shown. The overview cannot verify coordination state without a read-only conductor source."
		return out
	}
	out.EmptyTitle = "No queue listing seam available"
	out.EmptyDetail = "The configured conductor seam can replay a known artifact hash, but it cannot list incidents or queued decisions for this overview."
	return out
}

func (m *ReadModel) overviewCoverage(sessions []SessionSummary, fleet OverviewFleetPosture) OverviewCoverage {
	out := OverviewCoverage{Claim: overviewCoverageClaim, NonClaim: overviewCoverageNonClaim}
	seenAgents := make(map[string]struct{})
	for _, session := range sessions {
		if strings.TrimSpace(session.Agent) != "" {
			seenAgents[session.Agent] = struct{}{}
		}
		if !session.ReceiptsEnabled {
			out.NoReceiptAgents = appendUnique(out.NoReceiptAgents, session.Agent)
		}
	}
	if m.cfg != nil {
		for agent, profile := range m.cfg.Agents {
			if _, ok := seenAgents[agent]; !ok {
				out.NoReceiptAgents = appendUnique(out.NoReceiptAgents, agent)
			}
			if profile.Mode == config.ModeAudit || (profile.Enforce != nil && !*profile.Enforce) {
				out.MonitorOnlyAgents = appendUnique(out.MonitorOnlyAgents, agent)
			}
		}
	}
	if !fleet.SourceConfigured {
		out.FleetSourceNote = "No FleetSource is configured, so heartbeat blind spots cannot be enumerated."
		return out
	}
	if !fleet.ScopeConfigured {
		out.FleetSourceNote = "FleetSource is configured, but no default fleet scope is available for heartbeat enumeration."
		return out
	}
	if fleet.Dark > 0 {
		out.NoHeartbeatAgents = append(out.NoHeartbeatAgents, fmt.Sprintf("%d dark followers", fleet.Dark))
	}
	if fleet.NeverReported > 0 {
		out.NoHeartbeatAgents = append(out.NoHeartbeatAgents, fmt.Sprintf("%d never-reported followers", fleet.NeverReported))
	}
	sort.Strings(out.NoReceiptAgents)
	sort.Strings(out.MonitorOnlyAgents)
	return out
}

func (m *ReadModel) overviewGovernance(exemptions ExemptionInventory, trust TrustKeysPage, health OperabilityHealth) OverviewGovernance {
	out := OverviewGovernance{
		Claim:              overviewGovernanceClaim,
		NonClaim:           overviewGovernanceNonClaim,
		ConfigLoaded:       exemptions.ConfigLoaded,
		CRLStatus:          trust.CRLStatus,
		CRLDetail:          trust.CRLDetail,
		DeliveryConfigured: health.DeliveryConfigured,
		DeliveryError:      health.DeliveryError,
	}
	for _, entry := range exemptions.Entries {
		switch {
		case entry.LifecycleExpired:
			out.ExpiredExemptions++
		case entry.State == ExemptionStateInert:
			out.InertExemptions++
		case entry.State == ExemptionStateMisdirected:
			out.MisdirectedExemptions++
		}
	}
	if health.DeliveryConfigured && health.DeliveryError == "" {
		out.AlertFailures = addBoundedInts(
			boundedUint64ToInt(health.Delivery.Failed),
			boundedUint64ToInt(health.Delivery.Dropped),
			health.Delivery.DeadLetters,
		)
	}
	if m.legalHoldStore == nil {
		return out
	}
	out.LegalHoldConfigured = true
	holds, err := m.legalHoldStore.Snapshot()
	if err != nil {
		out.LegalHoldError = "legal hold store could not be read"
		return out
	}
	for _, hold := range holds {
		if hold.Released == nil {
			out.ActiveLegalHolds++
		}
	}
	return out
}

func (m *ReadModel) overviewBudget(ctx context.Context, rawAllowed bool) (OverviewBudgetPressure, error) {
	out := OverviewBudgetPressure{
		Claim:       overviewBudgetClaim,
		NonClaim:    overviewBudgetNonClaim,
		EmptyTitle:  "No budget source configured",
		EmptyDetail: "Budget pressure is not fabricated. Attach a BudgetSource to show agents near configured limits.",
	}
	budgets, err := m.Budgets(ctx, rawAllowed)
	if err != nil {
		return out, err
	}
	out.SourceConfigured = budgets.SourceConfigured
	out.SourceUnavailable = budgets.SourceUnavailable
	out.HasSnapshotFreshness = budgets.HasSnapshotFreshness
	if budgets.HasSnapshotFreshness {
		out.SnapshotAge = budgets.SnapshotFreshness.AgeDisplay()
		out.SnapshotStale = budgets.SnapshotFreshness.Stale
	}
	if !budgets.SourceConfigured {
		return out, nil
	}
	if budgets.SourceUnavailable {
		out.EmptyTitle = "Budget snapshot unavailable"
		out.EmptyDetail = "Counters are hidden because the snapshot source is missing, invalid, oversized, future-dated, or stale."
		return out, nil
	}
	for _, agent := range budgets.Agents {
		percent, basis := budgetPressure(agent)
		if percent < 75 {
			continue
		}
		out.Rows = append(out.Rows, OverviewBudgetRow{
			Agent:   displayOverviewString(agent.Agent),
			Percent: percent,
			Basis:   basis,
			Link:    "/budgets",
		})
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		if out.Rows[i].Percent != out.Rows[j].Percent {
			return out.Rows[i].Percent > out.Rows[j].Percent
		}
		return out.Rows[i].Agent < out.Rows[j].Agent
	})
	if len(out.Rows) == 0 {
		out.EmptyTitle = "No agents near configured limits"
		out.EmptyDetail = "No budget row in the loaded snapshot is at or above 75% of a configured limit."
	}
	return out, nil
}

func budgetPressure(agent AgentBudgetView) (int, string) {
	best := 0
	basis := "configured limit"
	considerInt := func(used, limit int, label string) {
		if limit <= 0 {
			return
		}
		pct := percentInt(int64(used), int64(limit))
		if pct > best {
			best = pct
			basis = label
		}
	}
	considerInt64 := func(used, limit int64, label string) {
		if limit <= 0 {
			return
		}
		pct := percentInt(used, limit)
		if pct > best {
			best = pct
			basis = label
		}
	}
	considerInt(agent.RequestCount, agent.MaxRequests, "request budget")
	considerInt64(agent.ByteCount, agent.MaxBytes, "byte budget")
	considerInt(agent.UniqueDomainCount, agent.MaxUniqueDomains, "unique-domain budget")
	considerInt(agent.TotalToolCalls, agent.MaxToolCallsPerSession, "MCP tool-call budget")
	considerInt(agent.Inflight, agent.MaxConcurrentToolCalls, "MCP concurrency budget")
	return best, basis
}

func (m *ReadModel) overviewAttention(page OverviewPage) []OverviewAttentionItem {
	var items []OverviewAttentionItem
	add := func(severity, kind, fact string, count int, label, link string) {
		if count <= 0 {
			return
		}
		if !m.hasFleetFeature() && fleetGatedOverviewLink(link) {
			link = ""
		}
		items = append(items, OverviewAttentionItem{
			Severity:   severity,
			Kind:       kind,
			Fact:       fact,
			Count:      count,
			CountLabel: label,
			Link:       link,
		})
	}
	add("red", "CHAIN", "receipt chains are broken", page.Evidence.BrokenChains, pluralize(page.Evidence.BrokenChains, "session", "sessions"), "/agents?chain=broken")
	add("red", "SIGNER", "sessions are signed by untrusted or unverifiable keys", page.Evidence.Untrusted, pluralize(page.Evidence.Untrusted, "session", "sessions"), "/trust-keys")
	add("red", "DARK", "followers have gone dark", page.Fleet.Dark, pluralize(page.Fleet.Dark, "follower", "followers"), "/fleet")
	add("red", "APPLY", "followers report last policy apply failed", page.Fleet.ApplyFailed, pluralize(page.Fleet.ApplyFailed, "follower", "followers"), "/fleet")
	add("red", "EXEMPT", "active exemptions are expired", page.Governance.ExpiredExemptions, pluralize(page.Governance.ExpiredExemptions, "exemption", "exemptions"), "/exemptions")
	add("red", "ALERTS", "alert delivery failures are recorded", page.Governance.AlertFailures, pluralize(page.Governance.AlertFailures, "failure", "failures"), "/")
	if !page.Incidents.SourceConfigured {
		add("red", "SOURCE", "no conductor source is configured", 1, "fleet-wide", "/workbench")
	}
	add("amber", "STALE", "followers are stale", page.Fleet.Stale, pluralize(page.Fleet.Stale, "follower", "followers"), "/fleet")
	add("amber", "BUDGET", "agents are near configured budget limits", len(page.Budget.Rows), pluralize(len(page.Budget.Rows), "agent", "agents"), "/budgets")
	add("amber", "UNSIGN", "followers self-report applied state without verification", page.Fleet.UnsignedSelf+page.Fleet.SignedUnverified, pluralize(page.Fleet.UnsignedSelf+page.Fleet.SignedUnverified, "follower", "followers"), "/fleet")
	add("amber", "DRIFT", "followers report config drift", page.Fleet.Drift, pluralize(page.Fleet.Drift, "follower", "followers"), "/fleet")
	fleetUnreachable := 0
	if page.Fleet.SourceUnavailable {
		fleetUnreachable = 1
	}
	add("amber", "FLEET", "the configured fleet source is unreachable, so follower posture is unknown", fleetUnreachable, "source", "/fleet")
	add("amber", "GAP", "sessions or configured agents have no receipts in loaded evidence", len(page.Coverage.NoReceiptAgents), pluralize(len(page.Coverage.NoReceiptAgents), "agent", "agents"), "/agents")
	return items
}

func (m *ReadModel) hasFleetFeature() bool {
	return m != nil && m.hasFeature != nil && m.hasFeature(license.FeatureFleet)
}

func fleetGatedOverviewLink(link string) bool {
	switch link {
	case "/fleet", "/workbench", "/incident":
		return true
	default:
		return false
	}
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "-"
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func displayOverviewString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func pluralize(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

func boundedUint64ToInt(value uint64) int {
	maxInt := int(^uint(0) >> 1)
	if value > uint64(maxInt) {
		return maxInt
	}
	return int(uint(value))
}

func percentInt(used, limit int64) int {
	if used <= 0 || limit <= 0 {
		return 0
	}
	maxInt := int64(int(^uint(0) >> 1))
	quotient := used / limit
	if quotient > maxInt/100 {
		return int(maxInt)
	}
	remainder := used % limit
	return int(quotient*100 + (remainder*100)/limit)
}

func addBoundedInts(values ...int) int {
	maxInt := int(^uint(0) >> 1)
	total := 0
	for _, value := range values {
		if value > maxInt-total {
			return maxInt
		}
		total += value
	}
	return total
}
