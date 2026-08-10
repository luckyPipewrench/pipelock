//go:build enterprise

// Copyright 2026 Pipelock contributors
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
	copy(out, f.agents)
	return out, nil
}

func budgetAgent() AgentBudgetView {
	return AgentBudgetView{
		Agent:             "agent-alpha",
		ForwardConfigured: true,
		RequestCount:      7,
		ByteCount:         4096,
		UniqueDomainCount: 2,
		WindowStart:       time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC),
		MaxRequests:       100,
		MaxBytes:          1048576,
		MaxUniqueDomains:  10,
		WindowMinutes:     60,
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
				BudgetSource:     &fakeBudgetSource{agents: []AgentBudgetView{budgetAgent()}},
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
	body := rec.Body.String()
	for _, want := range []string{
		"Runtime &middot; Budgets",
		"Per-agent budgets",
		"Read-only; this page does not change limits, sessions, or enforcement state.",
		"agents with loaded budget rows",
		"Budget pressure proves only mediated per-agent budget consumption",
		"No budget source is connected",
		"--runtime-snapshot-file",
		"--receipt-dir/dashboard/runtime-snapshot.json",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("nil source body missing %q: %s", want, body)
		}
	}
}

func TestBudgets_ConnectedEmptySourceExplainsSnapshotRows(t *testing.T) {
	t.Parallel()
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       func(f string) bool { return f == license.FeatureAgents },
		BudgetSource:     &fakeBudgetSource{},
		AuthorizeRaw:     allowRawAccess,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/budgets", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Runtime &middot; Budgets",
		"Per-agent budgets",
		"Read-only; this page does not change limits, sessions, or enforcement state.",
		"agents with loaded budget rows",
		"Budget pressure proves only mediated per-agent budget consumption",
		"The source is connected",
		"no agents with configured forward-proxy budgets",
		"--runtime-snapshot-file",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("connected empty source body missing %q: %s", want, body)
		}
	}
}

func TestBudgets_RendersOnlyPopulatedForwardBudgetFields(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       func(f string) bool { return f == license.FeatureAgents },
		BudgetSource:     &fakeBudgetSource{agents: []AgentBudgetView{budgetAgent()}},
		AuthorizeRaw:     allowRawAccess,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/budgets", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// Every populated forward field is asserted by label AND rendered value.
	// Checking only the request count would let a regression that drops the
	// byte, unique-domain or window output pass unnoticed.
	for _, want := range []string{
		"Forward proxy",
		"Requests (used / limit)", "7 / 100",
		"Bytes (used / limit)", "4096 / 1048576",
		"Unique domains (used / limit)", "2 / 10",
		"Window", "60 min rolling",
		"Window started", "2026-07-10T12:00:00Z",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("budget body missing populated forward field %q", want)
		}
	}
	if strings.Contains(body, "MCP denial-of-wallet") {
		t.Fatal("budget body advertised unpopulated MCP denial-of-wallet fields")
	}
}

func TestBudgets_RouteExactMethodAndSourceError(t *testing.T) {
	t.Parallel()

	t.Run("trailing_slash_not_budget_panel", func(t *testing.T) {
		t.Parallel()
		source := &fakeBudgetSource{agents: []AgentBudgetView{budgetAgent()}}
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
		source := &fakeBudgetSource{agents: []AgentBudgetView{budgetAgent()}}
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

func TestReadModel_Budgets_SortAndTruncate(t *testing.T) {
	t.Parallel()

	// Unsorted input, one over the display cap.
	agents := make([]AgentBudgetView, 0, budgetAgentLimit+1)
	agents = append(agents, AgentBudgetView{Agent: "zzz-last", ForwardConfigured: true})
	for i := 0; i < budgetAgentLimit; i++ {
		agents = append(agents, AgentBudgetView{Agent: fmt.Sprintf("agent-%04d", i), ForwardConfigured: true})
	}

	m := NewReadModel(Options{BudgetSource: &fakeBudgetSource{agents: agents}})

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
}

func TestReadModel_Budgets_RequestsBoundedSource(t *testing.T) {
	t.Parallel()

	source := &fakeBudgetSource{agents: []AgentBudgetView{budgetAgent()}}
	m := NewReadModel(Options{BudgetSource: source})

	_, err := m.Budgets(context.Background(), false)
	if err != nil {
		t.Fatalf("Budgets: %v", err)
	}
	if source.limit != budgetAgentLimit+1 {
		t.Fatalf("BudgetSource limit = %d, want %d", source.limit, budgetAgentLimit+1)
	}
}

func TestAgentBudgetView_Displays(t *testing.T) {
	t.Parallel()
	limited := AgentBudgetView{RequestCount: 3, MaxRequests: 10}
	if got := limited.RequestsDisplay(); got != "3 / 10" {
		t.Fatalf("RequestsDisplay = %q, want %q", got, "3 / 10")
	}
	limited.ByteCount = math.MaxInt32 + 1
	limited.MaxBytes = math.MaxInt32 + 2
	if got := limited.BytesDisplay(); got != "2147483648 / 2147483649" {
		t.Fatalf("BytesDisplay = %q, want %q", got, "2147483648 / 2147483649")
	}
	unlimited := AgentBudgetView{RequestCount: 3, MaxRequests: 0}
	if got := unlimited.RequestsDisplay(); got != "3 / "+budgetUnlimited {
		t.Fatalf("RequestsDisplay unlimited = %q", got)
	}
}
