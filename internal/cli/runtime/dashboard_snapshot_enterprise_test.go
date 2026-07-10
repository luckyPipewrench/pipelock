//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard/runtimesnapshot"
	"github.com/luckyPipewrench/pipelock/internal/edition"
)

type fakeAgentBudgetSnapshotProvider struct {
	snaps []edition.AgentBudgetSnapshot
	err   error
	limit int
}

func (f *fakeAgentBudgetSnapshotProvider) AgentBudgetSnapshots(_ context.Context, limit int) ([]edition.AgentBudgetSnapshot, error) {
	f.limit = limit
	if f.err != nil {
		return nil, f.err
	}
	return f.snaps, nil
}

func TestBuildDashboardRuntimeSnapshotMapsAndBoundsBudgets(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	provider := &fakeAgentBudgetSnapshotProvider{snaps: []edition.AgentBudgetSnapshot{{
		Agent: "agent-alpha",
		BudgetSnapshot: edition.BudgetSnapshot{
			RequestCount:      3,
			ByteCount:         99,
			UniqueDomainCount: 2,
			WindowStart:       now.Add(-time.Hour),
			MaxRequests:       10,
			MaxBytes:          1000,
			MaxUniqueDomains:  4,
			WindowMinutes:     60,
		},
	}}}

	snap, err := buildDashboardRuntimeSnapshot(context.Background(), provider, now, "producer-1", "policy-1")
	if err != nil {
		t.Fatalf("buildDashboardRuntimeSnapshot: %v", err)
	}
	if provider.limit != runtimesnapshot.MaxBudgetRows+1 {
		t.Fatalf("provider limit = %d, want %d", provider.limit, runtimesnapshot.MaxBudgetRows+1)
	}
	if snap.Version != runtimesnapshot.Version || snap.ProducerID != "producer-1" || snap.PolicyHash != "policy-1" {
		t.Fatalf("unexpected metadata: %+v", snap)
	}
	if len(snap.Budgets) != 1 || snap.Budgets[0].Agent != "agent-alpha" || snap.Budgets[0].ByteCount != 99 {
		t.Fatalf("unexpected budget rows: %+v", snap.Budgets)
	}
	if snap.Truncated.Budgets {
		t.Fatal("Truncated.Budgets = true, want false")
	}
}

func TestBuildDashboardRuntimeSnapshotDoesNotPersistHostProducerMetadata(t *testing.T) {
	t.Parallel()

	snap, err := buildDashboardRuntimeSnapshot(
		context.Background(),
		&fakeAgentBudgetSnapshotProvider{},
		time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC),
		dashboardRuntimeSnapshotProducerID(),
		"",
	)
	if err != nil {
		t.Fatalf("buildDashboardRuntimeSnapshot: %v", err)
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	host, _ := os.Hostname()
	body := string(data)
	if host != "" && strings.Contains(body, host) {
		t.Fatalf("snapshot persisted hostname metadata: %s", body)
	}
	if strings.Contains(body, strconv.Itoa(os.Getpid())) {
		t.Fatalf("snapshot persisted process id metadata: %s", body)
	}
}

func TestBuildDashboardRuntimeSnapshotTruncatesOverLimit(t *testing.T) {
	t.Parallel()

	snaps := make([]edition.AgentBudgetSnapshot, 0, runtimesnapshot.MaxBudgetRows+1)
	for i := 0; i <= runtimesnapshot.MaxBudgetRows; i++ {
		snaps = append(snaps, edition.AgentBudgetSnapshot{Agent: "agent"})
	}
	provider := &fakeAgentBudgetSnapshotProvider{snaps: snaps}

	snap, err := buildDashboardRuntimeSnapshot(context.Background(), provider, time.Now(), "producer-1", "")
	if err != nil {
		t.Fatalf("buildDashboardRuntimeSnapshot: %v", err)
	}
	if len(snap.Budgets) != runtimesnapshot.MaxBudgetRows {
		t.Fatalf("budget rows = %d, want %d", len(snap.Budgets), runtimesnapshot.MaxBudgetRows)
	}
	if !snap.Truncated.Budgets {
		t.Fatal("Truncated.Budgets = false, want true")
	}
}

func TestBuildDashboardRuntimeSnapshotPropagatesProviderError(t *testing.T) {
	t.Parallel()

	want := errors.New("provider unavailable")
	_, err := buildDashboardRuntimeSnapshot(context.Background(), &fakeAgentBudgetSnapshotProvider{err: want}, time.Now(), "producer-1", "")
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want provider error", err)
	}
}
