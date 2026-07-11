//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

const budgetTestSensitiveSession = "mcp-session-sensitive-alpha"

type fakeBudgetSource struct {
	agents []AgentBudgetView
	err    error
	calls  int
	limit  int
}

func (f *fakeBudgetSource) AllAgentBudgets(_ context.Context, limit int) ([]AgentBudgetView, error) {
	f.calls++
	f.limit = limit
	if f.err != nil {
		return nil, f.err
	}
	out := make([]AgentBudgetView, len(f.agents))
	for i, a := range f.agents {
		if len(a.Sessions) > 0 {
			sessions := make([]AgentBudgetSessionView, len(a.Sessions))
			copy(sessions, a.Sessions)
			a.Sessions = sessions
		}
		out[i] = a
	}
	return out, nil
}

func budgetAgentWithSession() AgentBudgetView {
	return AgentBudgetView{
		Agent:                  "agent-alpha",
		ForwardConfigured:      true,
		RequestCount:           7,
		ByteCount:              4096,
		UniqueDomainCount:      2,
		WindowStart:            time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC),
		MaxRequests:            100,
		MaxBytes:               1048576,
		MaxUniqueDomains:       10,
		WindowMinutes:          60,
		DoWConfigured:          true,
		ActiveSessions:         1,
		TotalToolCalls:         3,
		Inflight:               1,
		MaxToolCallsPerSession: 50,
		MaxConcurrentToolCalls: 5,
		MaxWallClockMinutes:    30,
		Sessions: []AgentBudgetSessionView{
			{SessionID: budgetTestSensitiveSession, TotalToolCalls: 3, Inflight: 1, StartedAt: time.Date(2026, 7, 10, 12, 5, 0, 0, time.UTC)},
		},
	}
}

// TestBudgets_Gating proves the /budgets panel is a Pro (FeatureAgents) surface:
// it must be allowed by agents entitlement and REFUSED by a fleet-only license.
func TestBudgets_Gating(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		hasFeature func(string) bool
		wantStatus int
	}{
		{name: "nil_feature", hasFeature: nil, wantStatus: http.StatusForbidden},
		{
			name:       "fleet_only_refused",
			hasFeature: func(f string) bool { return f == license.FeatureFleet },
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "agents_allowed",
			hasFeature: func(f string) bool { return f == license.FeatureAgents },
			wantStatus: http.StatusOK,
		},
		{
			name:       "enterprise_allowed",
			hasFeature: func(f string) bool { return f == license.FeatureAgents || f == license.FeatureFleet },
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler := New(Options{
				TrustedOuterAuth: true,
				ReceiptDir:       t.TempDir(),
				HasFeature:       tt.hasFeature,
				BudgetSource:     &fakeBudgetSource{agents: []AgentBudgetView{budgetAgentWithSession()}},
				AuthorizeRaw:     allowRawAccess,
			})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/budgets", nil))
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "agent-alpha") {
				t.Fatal("forbidden response leaked budget body")
			}
		})
	}
}

// TestBudgets_NilSourceDegrades: with no BudgetSource, the panel renders the
// honest empty state (200), never an error and never invented data.
func TestBudgets_NilSourceDegrades(t *testing.T) {
	t.Parallel()
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       func(f string) bool { return f == license.FeatureAgents },
		AuthorizeRaw:     allowRawAccess,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/budgets", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "No budget source is configured") {
		t.Fatalf("nil source did not render the empty state; body=%s", rec.Body.String())
	}
}

func TestBudgets_RouteExactMethodAndSourceError(t *testing.T) {
	t.Parallel()

	t.Run("trailing_slash_not_budget_panel", func(t *testing.T) {
		t.Parallel()
		source := &fakeBudgetSource{agents: []AgentBudgetView{budgetAgentWithSession()}}
		handler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       t.TempDir(),
			HasFeature:       func(f string) bool { return f == license.FeatureAgents },
			BudgetSource:     source,
			AuthorizeRaw:     allowRawAccess,
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/budgets/", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
		}
		if source.calls != 0 {
			t.Fatalf("source calls = %d, want 0", source.calls)
		}
	})

	t.Run("post_rejected_before_source", func(t *testing.T) {
		t.Parallel()
		source := &fakeBudgetSource{agents: []AgentBudgetView{budgetAgentWithSession()}}
		handler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       t.TempDir(),
			HasFeature:       func(f string) bool { return f == license.FeatureAgents },
			BudgetSource:     source,
			AuthorizeRaw:     allowRawAccess,
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/budgets", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405; body=%s", rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("Allow = %q, want GET", rec.Header().Get("Allow"))
		}
		if source.calls != 0 {
			t.Fatalf("source calls = %d, want 0", source.calls)
		}
	})

	t.Run("source_error_is_generic_500", func(t *testing.T) {
		t.Parallel()
		source := &fakeBudgetSource{err: fmt.Errorf("backend details should not leak")}
		handler := New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       t.TempDir(),
			HasFeature:       func(f string) bool { return f == license.FeatureAgents },
			BudgetSource:     source,
			AuthorizeRaw:     allowRawAccess,
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/budgets", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "backend details") {
			t.Fatalf("source error leaked to response: %s", rec.Body.String())
		}
	})
}

// TestBudgets_SessionIDRedaction: the sensitive per-session identifier is
// redacted in the metadata view and shown only in the raw view.
func TestBudgets_SessionIDRedaction(t *testing.T) {
	t.Parallel()

	newHandler := func(raw func(*http.Request) error) http.Handler {
		return New(Options{
			TrustedOuterAuth: true,
			ReceiptDir:       t.TempDir(),
			HasFeature:       func(f string) bool { return f == license.FeatureAgents },
			BudgetSource:     &fakeBudgetSource{agents: []AgentBudgetView{budgetAgentWithSession()}},
			AuthorizeRaw:     raw,
		})
	}

	// Metadata view (no raw authorizer): session id must be redacted.
	recMeta := httptest.NewRecorder()
	newHandler(nil).ServeHTTP(recMeta, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/budgets", nil))
	metaBody := recMeta.Body.String()
	if recMeta.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, want 200", recMeta.Code)
	}
	if strings.Contains(metaBody, budgetTestSensitiveSession) {
		t.Fatal("metadata view leaked the sensitive session id")
	}
	if !strings.Contains(metaBody, budgetRedacted) {
		t.Fatal("metadata view did not mark the session id redacted")
	}

	// Raw view: session id must be visible.
	recRaw := httptest.NewRecorder()
	newHandler(allowRawAccess).ServeHTTP(recRaw, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/budgets", nil))
	if !strings.Contains(recRaw.Body.String(), budgetTestSensitiveSession) {
		t.Fatal("raw view did not show the session id")
	}
}

func TestReadModel_Budgets_NilSource(t *testing.T) {
	t.Parallel()
	m := NewReadModel(Options{})
	ov, err := m.Budgets(context.Background(), true)
	if err != nil {
		t.Fatalf("Budgets: %v", err)
	}
	if ov.SourceConfigured {
		t.Fatal("SourceConfigured should be false with no source")
	}
	if len(ov.Agents) != 0 {
		t.Fatalf("expected no agents, got %d", len(ov.Agents))
	}
}

func TestReadModel_Budgets_SortTruncateRedact(t *testing.T) {
	t.Parallel()

	// Unsorted input, one over the display cap.
	agents := make([]AgentBudgetView, 0, budgetAgentLimit+1)
	agents = append(agents, AgentBudgetView{
		Agent: "zzz-last", DoWConfigured: true, ActiveSessions: 1,
		Sessions: []AgentBudgetSessionView{{SessionID: "sensitive-zzz"}},
	})
	for i := 0; i < budgetAgentLimit; i++ {
		agents = append(agents, AgentBudgetView{Agent: fmt.Sprintf("agent-%04d", i), ForwardConfigured: true})
	}

	m := NewReadModel(Options{BudgetSource: &fakeBudgetSource{agents: agents}})

	// Redacted (metadata) view.
	ov, err := m.Budgets(context.Background(), false)
	if err != nil {
		t.Fatalf("Budgets: %v", err)
	}
	if !ov.SourceConfigured {
		t.Fatal("SourceConfigured should be true")
	}
	if !ov.Truncated {
		t.Fatalf("expected Truncated, got %d agents (cap %d)", len(ov.Agents), budgetAgentLimit)
	}
	if len(ov.Agents) != budgetAgentLimit {
		t.Fatalf("expected %d agents after truncation, got %d", budgetAgentLimit, len(ov.Agents))
	}
	if ov.Agents[0].Agent != "agent-0000" {
		t.Fatalf("expected sorted-first agent-0000, got %q", ov.Agents[0].Agent)
	}
	// "zzz-last" (with the sensitive session) sorts last and is dropped by the
	// cap, so build a small deterministic case for the redaction assertion.
	small := NewReadModel(Options{BudgetSource: &fakeBudgetSource{agents: []AgentBudgetView{
		{Agent: "a", DoWConfigured: true, ActiveSessions: 1, Sessions: []AgentBudgetSessionView{{SessionID: "sensitive-abc"}}},
	}}})
	red, err := small.Budgets(context.Background(), false)
	if err != nil {
		t.Fatalf("Budgets: %v", err)
	}
	if red.Agents[0].Sessions[0].SessionID != budgetRedacted {
		t.Fatalf("session id not redacted in metadata view: %q", red.Agents[0].Sessions[0].SessionID)
	}
	rawov, err := small.Budgets(context.Background(), true)
	if err != nil {
		t.Fatalf("Budgets: %v", err)
	}
	if rawov.Agents[0].Sessions[0].SessionID != "sensitive-abc" {
		t.Fatalf("session id should be visible in raw view, got %q", rawov.Agents[0].Sessions[0].SessionID)
	}
}

func TestReadModel_Budgets_RequestsBoundedSourceAndCapsSessions(t *testing.T) {
	t.Parallel()

	sessions := make([]AgentBudgetSessionView, 0, budgetSessionLimit+1)
	for i := 0; i <= budgetSessionLimit; i++ {
		sessions = append(sessions, AgentBudgetSessionView{SessionID: fmt.Sprintf("session-%03d", i)})
	}
	source := &fakeBudgetSource{agents: []AgentBudgetView{{
		Agent:          "agent-session-heavy",
		DoWConfigured:  true,
		ActiveSessions: len(sessions),
		Sessions:       sessions,
	}}}
	m := NewReadModel(Options{BudgetSource: source})

	ov, err := m.Budgets(context.Background(), false)
	if err != nil {
		t.Fatalf("Budgets: %v", err)
	}
	if source.limit != budgetAgentLimit+1 {
		t.Fatalf("BudgetSource limit = %d, want %d", source.limit, budgetAgentLimit+1)
	}
	if got := len(ov.Agents[0].Sessions); got != budgetSessionLimit {
		t.Fatalf("session rows = %d, want cap %d", got, budgetSessionLimit)
	}
	if !ov.Agents[0].SessionsTruncated {
		t.Fatal("expected SessionsTruncated when source returns more than the display cap")
	}
	for _, session := range ov.Agents[0].Sessions {
		if session.SessionID != budgetRedacted {
			t.Fatalf("metadata session id after cap/redaction = %q, want %q", session.SessionID, budgetRedacted)
		}
	}
}

func TestAgentBudgetView_Displays(t *testing.T) {
	t.Parallel()
	limited := AgentBudgetView{RequestCount: 3, MaxRequests: 10, TotalToolCalls: 4, MaxToolCallsPerSession: 50}
	if got := limited.RequestsDisplay(); got != "3 / 10" {
		t.Fatalf("RequestsDisplay = %q, want %q", got, "3 / 10")
	}
	limited.ByteCount = math.MaxInt32 + 1
	limited.MaxBytes = math.MaxInt32 + 2
	if got := limited.BytesDisplay(); got != "2147483648 / 2147483649" {
		t.Fatalf("BytesDisplay = %q, want %q", got, "2147483648 / 2147483649")
	}
	if got := limited.ToolCallsDisplay(); got != "4 / 50 per session" {
		t.Fatalf("ToolCallsDisplay = %q, want %q", got, "4 / 50 per session")
	}
	unlimited := AgentBudgetView{RequestCount: 3, MaxRequests: 0, TotalToolCalls: 4, MaxToolCallsPerSession: 0}
	if got := unlimited.RequestsDisplay(); got != "3 / "+budgetUnlimited {
		t.Fatalf("RequestsDisplay unlimited = %q", got)
	}
	if got := unlimited.ToolCallsDisplay(); got != "4 / "+budgetUnlimited {
		t.Fatalf("ToolCallsDisplay unlimited = %q", got)
	}
}
