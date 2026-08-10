//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard/runtimesnapshot"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

func TestSnapshotBudgetSourceMapsForwardRows(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "dashboard", "runtime-snapshot.json")
	if err := runtimesnapshot.Write(path, runtimesnapshot.Envelope{
		Version:    runtimesnapshot.Version,
		ProducedAt: now,
		ProducerID: "producer-1",
		Budgets: []runtimesnapshot.AgentBudgetRow{{
			Agent:             "agent-alpha",
			RequestCount:      7,
			ByteCount:         4096,
			UniqueDomainCount: 2,
			WindowStart:       now.Add(-time.Hour),
			MaxRequests:       100,
			MaxBytes:          1 << 20,
			MaxUniqueDomains:  10,
			WindowMinutes:     60,
		}},
	}); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}

	source := &snapshotBudgetSource{path: path, maxAge: time.Minute, now: func() time.Time { return now.Add(5 * time.Second) }}
	rows, err := source.AllAgentBudgets(context.Background(), 10)
	if err != nil {
		t.Fatalf("AllAgentBudgets: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.Agent != "agent-alpha" || !row.ForwardConfigured || row.RequestCount != 7 || row.UniqueDomainCount != 2 {
		t.Fatalf("unexpected mapped row: %+v", row)
	}
	assertBudgetFieldsMapped(t, row, map[string]any{
		"Agent":             "agent-alpha",
		"ForwardConfigured": true,
		"RequestCount":      7,
		"ByteCount":         int64(4096),
		"UniqueDomainCount": 2,
		"WindowStart":       now.Add(-time.Hour),
		"MaxRequests":       100,
		"MaxBytes":          int64(1 << 20),
		"MaxUniqueDomains":  10,
		"WindowMinutes":     60,
	})
	fresh, ok := source.BudgetFreshness()
	if !ok || fresh.ProducedAt != now || fresh.Stale {
		t.Fatalf("freshness = %+v ok=%v, want produced_at and stale=false", fresh, ok)
	}
}

// TestSnapshotBudgetSourceMapsLegitimateZeroValues pins the reason the
// completeness check compares explicit expectations instead of asking whether a
// field is zero. A fresh window has no requests yet and a zero maximum means
// unlimited, so both are correctly mapped values that a zero-value heuristic
// would report as unpopulated. Without this case every numeric expectation is
// non-zero, and reintroducing that heuristic would still pass the suite.
func TestSnapshotBudgetSourceMapsLegitimateZeroValues(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "dashboard", "runtime-snapshot.json")
	if err := runtimesnapshot.Write(path, runtimesnapshot.Envelope{
		Version:    runtimesnapshot.Version,
		ProducedAt: now,
		ProducerID: "producer-1",
		Budgets: []runtimesnapshot.AgentBudgetRow{{
			Agent: "agent-zero",
			// Fresh window: nothing consumed yet.
			RequestCount:      0,
			ByteCount:         0,
			UniqueDomainCount: 0,
			WindowStart:       now.Add(-time.Minute),
			// MaxBytes 0 means unlimited; other limits stay positive so the
			// agent still has a configured forward budget.
			MaxRequests:      100,
			MaxBytes:         0,
			MaxUniqueDomains: 10,
			WindowMinutes:    60,
		}},
	}); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}

	source := &snapshotBudgetSource{path: path, maxAge: time.Minute, now: func() time.Time { return now.Add(5 * time.Second) }}
	rows, err := source.AllAgentBudgets(context.Background(), 10)
	if err != nil {
		t.Fatalf("AllAgentBudgets: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	assertBudgetFieldsMapped(t, rows[0], map[string]any{
		"Agent":             "agent-zero",
		"ForwardConfigured": true,
		"RequestCount":      0,
		"ByteCount":         int64(0),
		"UniqueDomainCount": 0,
		"WindowStart":       now.Add(-time.Minute),
		"MaxRequests":       100,
		"MaxBytes":          int64(0),
		"MaxUniqueDomains":  10,
		"WindowMinutes":     60,
	})
	// The unlimited maximum must render as unlimited rather than as a zero cap.
	if got := rows[0].BytesDisplay(); got != "0 / "+budgetUnlimited {
		t.Errorf("BytesDisplay() = %q, want unlimited rendering", got)
	}
}

// assertBudgetFieldsMapped checks that every field declared on AgentBudgetView
// is mapped by the snapshot source and matches its expectation. A field with no
// expectation fails, so adding a field to the view forces a decision about
// populating it rather than letting it render blank.
func assertBudgetFieldsMapped(t *testing.T, row AgentBudgetView, wantFields map[string]any) {
	t.Helper()

	value := reflect.ValueOf(row)
	typeOfRow := value.Type()
	for i := range value.NumField() {
		name := typeOfRow.Field(i).Name
		want, ok := wantFields[name]
		if !ok {
			t.Errorf("declared budget field %s has no expectation: map it in the snapshot source and assert it here, or remove it from the view", name)
			continue
		}
		if got := value.Field(i).Interface(); !reflect.DeepEqual(got, want) {
			t.Errorf("declared budget field %s = %v, want %v", name, got, want)
		}
	}
	if len(wantFields) != value.NumField() {
		t.Errorf("expectation count %d != declared field count %d", len(wantFields), value.NumField())
	}
}

func TestReadModelBudgetsSnapshotUnavailableRendersHonestState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "runtime-snapshot.json")
	if err := runtimesnapshot.Write(path, runtimesnapshot.Envelope{
		Version:    runtimesnapshot.Version,
		ProducedAt: now.Add(-time.Minute),
		ProducerID: "producer-1",
	}); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	source := &snapshotBudgetSource{path: path, maxAge: 10 * time.Second, now: func() time.Time { return now }}
	model := NewReadModel(Options{BudgetSource: source})

	overview, err := model.Budgets(context.Background(), false)
	if err != nil {
		t.Fatalf("Budgets: %v", err)
	}
	if !overview.SourceConfigured || !overview.SourceUnavailable {
		t.Fatalf("overview source state = configured:%v unavailable:%v, want true/true", overview.SourceConfigured, overview.SourceUnavailable)
	}
	if len(overview.Agents) != 0 {
		t.Fatalf("agents = %d, want 0 for unavailable source", len(overview.Agents))
	}
	if !overview.HasSnapshotFreshness || !overview.SnapshotFreshness.Stale {
		t.Fatalf("freshness = %+v has=%v, want stale freshness", overview.SnapshotFreshness, overview.HasSnapshotFreshness)
	}
}

func TestBudgetsHandlerSnapshotUnavailableRendersMessage(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "runtime-snapshot.json")
	if err := runtimesnapshot.Write(path, runtimesnapshot.Envelope{
		Version:    runtimesnapshot.Version,
		ProducedAt: now.Add(-time.Minute),
		ProducerID: "producer-1",
	}); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	source := &snapshotBudgetSource{path: path, maxAge: 10 * time.Second, now: func() time.Time { return now }}
	handler := New(Options{
		TrustedOuterAuth: true,
		ReceiptDir:       t.TempDir(),
		HasFeature:       func(f string) bool { return f == license.FeatureAgents },
		BudgetSource:     source,
		AuthorizeRaw:     allowRawAccess,
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/budgets", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Budget pressure proves only mediated per-agent budget consumption",
		"A budget source is configured",
		"--runtime-snapshot-file",
		"--receipt-dir/dashboard/runtime-snapshot.json",
		"stale",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("unavailable body missing %q: %s", want, body)
		}
	}
}

func TestSnapshotBudgetSourceMissingFileUnavailable(t *testing.T) {
	t.Parallel()

	source := NewSnapshotBudgetSource(filepath.Join(t.TempDir(), "missing.json"), time.Minute)
	_, err := source.AllAgentBudgets(context.Background(), 10)
	if err == nil || !budgetUnavailable(err) {
		t.Fatalf("AllAgentBudgets error = %v, want source unavailable", err)
	}
	if strings.Contains(err.Error(), "missing.json") {
		t.Fatalf("unavailable error leaked path through Error(): %q", err.Error())
	}
}

func TestSnapshotBudgetSourceHelpersAndLimit(t *testing.T) {
	t.Parallel()

	if got := NewSnapshotBudgetSource("", time.Minute); got != nil {
		t.Fatalf("NewSnapshotBudgetSource(empty) = %T, want nil", got)
	}
	if budgetUnavailable(nil) {
		t.Fatal("budgetUnavailable(nil) = true")
	}
	if budgetUnavailable(errors.New("ordinary error")) {
		t.Fatal("ordinary error marked unavailable")
	}
	if got := (BudgetSnapshotFreshness{Age: -time.Second}).AgeDisplay(); got != budgetEmptyDash {
		t.Fatalf("negative freshness age display = %q, want %q", got, budgetEmptyDash)
	}

	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "runtime-snapshot.json")
	if err := runtimesnapshot.Write(path, runtimesnapshot.Envelope{
		ProducedAt: now,
		Budgets: []runtimesnapshot.AgentBudgetRow{
			{Agent: "alpha"},
			{Agent: "bravo"},
		},
	}); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	source, ok := NewSnapshotBudgetSource(path, time.Minute).(*snapshotBudgetSource)
	if !ok {
		t.Fatal("NewSnapshotBudgetSource returned unexpected implementation")
	}
	rows, err := source.AllAgentBudgets(context.Background(), 1)
	if err != nil {
		t.Fatalf("AllAgentBudgets: %v", err)
	}
	if len(rows) != 1 || rows[0].Agent != "alpha" {
		t.Fatalf("limited rows = %+v", rows)
	}

	wrapped := snapshotBudgetUnavailableError{err: errors.New("root cause")}
	if wrapped.Error() != "runtime snapshot budget source unavailable" || wrapped.Unwrap() == nil || !wrapped.BudgetSourceUnavailable() {
		t.Fatalf("unavailable wrapper contract failed: %+v", wrapped)
	}
}
