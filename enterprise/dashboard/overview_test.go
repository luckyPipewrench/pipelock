//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestOverviewReadModelAggregatesExistingSources(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	trustedPub, trustedPriv := generateDashboardKey(t)
	trusted := map[string]TrustedKey{hex.EncodeToString(trustedPub): {Source: trustedKeySource}}
	writeReceiptsToDirWithSession(t, dir, "broken-session", brokenDashboardChain(t, trustedPriv, "build-bot", "broken-session", now))

	_, untrustedPriv := generateDashboardKey(t)
	writeReceiptsToDirWithSession(t, dir, "untrusted-session", buildChainForAgent(t, untrustedPriv, "retrieval-7", "untrusted-session", 2))
	writeZeroReceiptSessionFile(t, dir, "gap-agent")

	cfg := config.Defaults()
	cfg.Suppress = []config.SuppressEntry{{Rule: "dlp/aws-secret-key", Path: "*api.vendor.example*", Reason: "test"}}
	store := expiredExemptionStore(t, now, "*api.vendor.example*")
	fleetSource := &fakeFleetSource{followers: overviewFleetFollowers(now)}
	budgetSource := &fakeBudgetSource{agents: []AgentBudgetView{{
		Agent:             "nightly-batch",
		ForwardConfigured: true,
		RequestCount:      92,
		MaxRequests:       100,
	}}}

	model := NewReadModel(Options{
		ReceiptDir:          dir,
		TrustedKeys:         trusted,
		Config:              cfg,
		HasFeature:          allowAllDashboardFeatures,
		ExemptionStore:      store,
		FleetSource:         fleetSource,
		DefaultFleetScope:   DecisionScope{OrgID: fleetTestOrgID, FleetID: fleetTestFleetID},
		BudgetSource:        budgetSource,
		Now:                 func() time.Time { return now },
		TrustedOuterAuth:    true,
		AuthorizeFleetScope: allowFleetScope,
	})
	page, err := model.Overview(context.Background(), true)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if page.Header.RedFacts != 6 {
		t.Fatalf("red facts = %d, want 6; attention=%+v", page.Header.RedFacts, page.Attention)
	}
	if page.Header.AmberFacts != 6 {
		t.Fatalf("amber facts = %d, want 6; attention=%+v", page.Header.AmberFacts, page.Attention)
	}
	if page.Header.Proven != 2 {
		t.Fatalf("proven = %d, want 2", page.Header.Proven)
	}
	assertOverviewAttention(t, page, "red", "CHAIN", "receipt chains are broken", 1)
	assertOverviewAttention(t, page, "red", "SOURCE", "no conductor source is configured", 1)
	assertOverviewAttention(t, page, "amber", "BUDGET", "agents are near configured budget limits", 1)
	if page.Fleet.VerifiedApplied != 2 || page.Fleet.Dark != 1 || page.Fleet.ApplyFailed != 1 {
		t.Fatalf("fleet posture = %+v", page.Fleet)
	}
	if page.Governance.ExpiredExemptions != 1 {
		t.Fatalf("expired exemptions = %d, want 1", page.Governance.ExpiredExemptions)
	}
}

func TestOverviewHandlerRendersAttentionLedgerAndHonestEmptyStates(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       dir,
		TrustedKeys:      trusted,
		HasFeature:       allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/overview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Operator Overview",
		"No aggregate score.",
		"No fleet source configured",
		"No conductor decision source configured",
		"No budget source configured",
		"Quiet is not clean.",
		"No receipt means no evidence, not no activity.",
		"Read-only.",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("overview body missing %q: %s", want, body)
		}
	}
	if strings.Contains(strings.ToLower(body), "healthy") {
		t.Fatalf("overview must not render healthy verdict wording: %s", body)
	}
}

func TestOverviewAllCleanFixtureSaysNoRedFactsNotHealthy(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth:    true,
		ReceiptDir:          dir,
		TrustedKeys:         trusted,
		HasFeature:          allowAllDashboardFeatures,
		FleetSource:         &fakeFleetSource{},
		DefaultFleetScope:   DecisionScope{OrgID: fleetTestOrgID, FleetID: fleetTestFleetID},
		ConductorSource:     &fakeConductorSource{},
		BudgetSource:        &fakeBudgetSource{},
		AuthorizeFleetScope: allowFleetScope,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/overview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "No red facts in the currently loaded evidence") {
		t.Fatalf("clean fixture did not render no-red-facts copy: %s", body)
	}
	if strings.Contains(strings.ToLower(body), "healthy") {
		t.Fatalf("clean fixture rendered healthy wording: %s", body)
	}
}

func TestOverviewRouteGatedEvidenceReadAndGETOnly(t *testing.T) {
	t.Parallel()

	noFeature := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       func(string) bool { return false },
	})
	rec := httptest.NewRecorder()
	noFeature.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/overview", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no feature status = %d, want 403", rec.Code)
	}

	var got []Permission
	permissioned := New(Options{
		ReceiptDir: t.TempDir(),
		HasFeature: func(feature string) bool {
			return feature == license.FeatureAgents
		},
		AuthorizePermission: func(_ *http.Request, permission Permission) error {
			got = append(got, permission)
			return nil
		},
	})
	rec = httptest.NewRecorder()
	permissioned.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/overview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("permissioned status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if len(got) == 0 || got[0] != PermissionEvidenceRead {
		t.Fatalf("/overview first permission = %v, want first %q", got, PermissionEvidenceRead)
	}

	source := &fakeBudgetSource{agents: []AgentBudgetView{{Agent: "agent", RequestCount: 1, MaxRequests: 10}}}
	postOnly := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       allowAgentsFeature,
		BudgetSource:     source,
	})
	rec = httptest.NewRecorder()
	postOnly.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/overview", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("Allow = %q, want GET", rec.Header().Get("Allow"))
	}
	if source.calls != 0 {
		t.Fatalf("budget source calls = %d, want 0 for rejected method", source.calls)
	}
}

func TestOverviewNilSourcesRenderHonestEmptySections(t *testing.T) {
	t.Parallel()

	model := NewReadModel(Options{ReceiptDir: t.TempDir()})
	page, err := model.Overview(context.Background(), false)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if page.Fleet.SourceConfigured || page.Budget.SourceConfigured || page.Incidents.SourceConfigured {
		t.Fatalf("nil source flags = fleet:%v budget:%v incident:%v", page.Fleet.SourceConfigured, page.Budget.SourceConfigured, page.Incidents.SourceConfigured)
	}
	if page.Fleet.EmptyTitle != "No fleet source configured" {
		t.Fatalf("fleet empty title = %q", page.Fleet.EmptyTitle)
	}
	if page.Budget.EmptyTitle != "No budget source configured" {
		t.Fatalf("budget empty title = %q", page.Budget.EmptyTitle)
	}
	if page.Incidents.EmptyTitle != "No conductor decision source configured" {
		t.Fatalf("incidents empty title = %q", page.Incidents.EmptyTitle)
	}
}

// A configured-but-unreachable fleet source (for example a down conductor) must
// degrade the fleet section to an explicit unavailable/unknown state, never fail
// the whole overview and never fabricate a clean fleet.
func TestOverviewFleetSourceUnreachableDegradesToAmber(t *testing.T) {
	t.Parallel()

	model := NewReadModel(Options{
		ReceiptDir:        t.TempDir(),
		HasFeature:        allowFleetFeature,
		FleetSource:       &fakeFleetSource{err: errors.New("conductor unreachable")},
		DefaultFleetScope: DecisionScope{OrgID: fleetTestOrgID, FleetID: fleetTestFleetID},
	})
	page, err := model.Overview(context.Background(), true)
	if err != nil {
		t.Fatalf("Overview must degrade, not error, when the fleet source is unreachable: %v", err)
	}
	if !page.Fleet.SourceUnavailable {
		t.Fatal("expected Fleet.SourceUnavailable=true when the fleet source errors")
	}
	if page.Fleet.EmptyTitle != "Fleet source unreachable" {
		t.Fatalf("fleet empty title = %q, want %q", page.Fleet.EmptyTitle, "Fleet source unreachable")
	}
	if page.Fleet.TotalAcceptedRows != 0 || page.Fleet.Reporting != 0 || page.Fleet.VerifiedApplied != 0 {
		t.Fatalf("degraded fleet must not fabricate followers: rows=%d reporting=%d verified=%d",
			page.Fleet.TotalAcceptedRows, page.Fleet.Reporting, page.Fleet.VerifiedApplied)
	}
	// Honesty: an unreachable source surfaces as an amber fact, never silently clean.
	var amberFleet bool
	for _, item := range page.Attention {
		if item.Kind == "FLEET" && item.Severity == "amber" && item.Count >= 1 {
			amberFleet = true
		}
	}
	if !amberFleet {
		t.Fatal("expected an amber FLEET attention fact when the fleet source is unreachable")
	}
}

func TestOverviewAgentsOnlyWithFleetSourceDoesNotQueryFleetPosture(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	source := &fakeFleetSource{followers: overviewFleetFollowers(now)}
	var fleetScopeAuthCalls int
	handler := New(Options{
		TrustedOuterAuth:  true,
		ReceiptDir:        t.TempDir(),
		HasFeature:        allowAgentsFeature,
		FleetSource:       source,
		DefaultFleetScope: DecisionScope{OrgID: fleetTestOrgID, FleetID: fleetTestFleetID},
		AuthorizeFleetScope: func(*http.Request, DecisionScope, bool) error {
			fleetScopeAuthCalls++
			return nil
		},
		Now: func() time.Time { return now },
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/overview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("agents-only /overview status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Enterprise fleet feature required") ||
		!strings.Contains(body, "Fleet posture requires the Enterprise fleet feature") {
		t.Fatalf("overview missing fleet-required empty state: %s", body)
	}
	for _, leaked := range []string{"Scope " + fleetTestOrgID, "4 accepted follower rows", "verified applied"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("agents-only overview rendered fleet posture data %q: %s", leaked, body)
		}
	}
	if !strings.Contains(body, "no conductor source is configured") {
		t.Fatalf("agents-only overview should keep the conductor-source attention fact: %s", body)
	}
	for _, blocked := range []string{`href="/fleet"`, `href="/workbench"`, `href="/incident"`} {
		if strings.Contains(body, blocked) {
			t.Fatalf("agents-only overview rendered fleet-gated link %q: %s", blocked, body)
		}
	}
	if source.gotOrgID != "" || source.gotFleet != "" || source.gotLimit != 0 {
		t.Fatalf("agents-only overview queried fleet source: org=%q fleet=%q limit=%d", source.gotOrgID, source.gotFleet, source.gotLimit)
	}
	if fleetScopeAuthCalls != 0 {
		t.Fatalf("agents-only overview called fleet scope authorizer %d times", fleetScopeAuthCalls)
	}
}

func TestOverviewFleetLicensedRendersFleetPosture(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	handler := New(Options{
		TrustedOuterAuth:    true,
		ReceiptDir:          t.TempDir(),
		HasFeature:          allowAllDashboardFeatures,
		FleetSource:         &fakeFleetSource{followers: overviewFleetFollowers(now)},
		DefaultFleetScope:   DecisionScope{OrgID: fleetTestOrgID, FleetID: fleetTestFleetID},
		AuthorizeFleetScope: allowFleetScope,
		Now:                 func() time.Time { return now },
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/overview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("fleet-licensed /overview status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Scope redacted / redacted", "4 accepted follower rows", "verified applied"} {
		if !strings.Contains(body, want) {
			t.Fatalf("fleet-licensed overview missing %q: %s", want, body)
		}
	}
	if !strings.Contains(body, `href="/workbench"`) {
		t.Fatalf("fleet-licensed overview should link conductor-source attention to workbench: %s", body)
	}
}

func brokenDashboardChain(t *testing.T, priv ed25519.PrivateKey, agent, sessionID string, now time.Time) []receipt.Receipt {
	t.Helper()
	first := overviewAction(agent, sessionID, 0, receipt.GenesisHash, now, "allow")
	r0, err := receipt.Sign(first, priv)
	if err != nil {
		t.Fatalf("Sign first: %v", err)
	}
	second := overviewAction(agent, sessionID, 1, "sha256:not-the-previous-hash", now.Add(time.Second), "block")
	r1, err := receipt.Sign(second, priv)
	if err != nil {
		t.Fatalf("Sign second: %v", err)
	}
	return []receipt.Receipt{r0, r1}
}

func overviewAction(agent, sessionID string, seq uint64, prevHash string, ts time.Time, verdict string) receipt.ActionRecord {
	ar := validDashboardAction(seq, prevHash, ts)
	ar.Actor = agent
	ar.SessionID = sessionID
	ar.Verdict = verdict
	ar.Layer = "dlp"
	ar.Pattern = "aws-secret-key"
	return ar
}

func overviewFleetFollowers(now time.Time) []FleetFollowerView {
	return []FleetFollowerView{
		{
			OrgID:              fleetTestOrgID,
			FleetID:            fleetTestFleetID,
			InstanceID:         "fw-edge-01",
			Active:             true,
			FleetHealth:        "ok",
			Drift:              "in_sync",
			RuntimeReported:    true,
			RuntimeSeenAt:      now.Add(-5 * time.Minute),
			SignedStatePresent: true,
			Verified:           true,
		},
		{
			OrgID:           fleetTestOrgID,
			FleetID:         fleetTestFleetID,
			InstanceID:      "fw-edge-02",
			Active:          true,
			FleetHealth:     "stale",
			Drift:           "in_sync",
			RuntimeReported: true,
			RuntimeSeenAt:   now.Add(-20 * time.Minute),
		},
		{
			OrgID:              fleetTestOrgID,
			FleetID:            fleetTestFleetID,
			InstanceID:         "fw-edge-03",
			Active:             true,
			FleetHealth:        "ok",
			Drift:              "in_sync",
			RuntimeReported:    true,
			RuntimeSeenAt:      now.Add(-2 * time.Hour),
			SignedStatePresent: true,
			Verified:           false,
		},
		{
			OrgID:              fleetTestOrgID,
			FleetID:            fleetTestFleetID,
			InstanceID:         "fw-edge-07",
			Active:             true,
			FleetHealth:        "apply_failed",
			Drift:              "drift",
			RuntimeReported:    true,
			RuntimeSeenAt:      now.Add(-3 * time.Minute),
			SignedStatePresent: true,
			Verified:           true,
		},
	}
}

func expiredExemptionStore(t *testing.T, now time.Time, scope string) *ExemptionStore {
	t.Helper()
	store, err := OpenExemptionStore(t.TempDir() + "/exemptions.json")
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}
	matched := now.Add(-2 * time.Hour)
	if err := store.Add(ExemptionRecord{
		ID:          "exmp-114",
		Scope:       scope,
		Owner:       "security",
		Reason:      "test",
		Created:     now.Add(-72 * time.Hour),
		Expiry:      now.Add(-24 * time.Hour),
		LastMatched: &matched,
	}, now); err != nil {
		t.Fatalf("Add exemption: %v", err)
	}
	return store
}

func assertOverviewAttention(t *testing.T, page OverviewPage, severity, kind, fact string, count int) {
	t.Helper()
	for _, item := range page.Attention {
		if item.Severity == severity && item.Kind == kind && item.Fact == fact {
			if item.Count != count {
				t.Fatalf("attention %s/%s count = %d, want %d", severity, kind, item.Count, count)
			}
			return
		}
	}
	t.Fatalf("missing attention item %s/%s/%q in %+v", severity, kind, fact, page.Attention)
}
