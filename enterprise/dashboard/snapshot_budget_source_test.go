//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	if row.DoWConfigured || row.ActiveSessions != 0 || len(row.Sessions) != 0 {
		t.Fatalf("DoW fields should stay empty in this PR: %+v", row)
	}
	fresh, ok := source.BudgetFreshness()
	if !ok || fresh.ProducedAt != now || fresh.Stale {
		t.Fatalf("freshness = %+v ok=%v, want produced_at and stale=false", fresh, ok)
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
