//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard/runtimesnapshot"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
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

func TestStartDashboardRuntimeSnapshotEnterpriseWritesAndStops(t *testing.T) {
	cfg := config.Defaults()
	enabled := true
	cfg.DashboardSnapshot.Enabled = &enabled
	cfg.DashboardSnapshot.Path = filepath.Join(t.TempDir(), "dashboard", "runtime-snapshot.json")
	cfg.DashboardSnapshot.Interval = "1s"

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var stderr strings.Builder
	startDashboardRuntimeSnapshotEnterprise(dashboardRuntimeSnapshotOptions{
		Context:        ctx,
		WaitGroup:      &wg,
		BudgetProvider: &fakeAgentBudgetSnapshotProvider{},
		StartupConfig:  cfg,
		CurrentConfig:  func() *config.Config { return cfg },
		Stderr:         &stderr,
	})

	testwait.For(t, 2*time.Second, func() bool {
		if _, err := os.Stat(cfg.DashboardSnapshot.Path); err == nil {
			return true
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat runtime snapshot: %v", err)
		}
		return false
	}, "runtime snapshot to be written; stderr=%s", stderr.String())
	cancel()
	wg.Wait()

	snap, _, err := runtimesnapshot.Read(cfg.DashboardSnapshot.Path, time.Minute, time.Now())
	if err != nil {
		t.Fatalf("Read runtime snapshot: %v", err)
	}
	if snap.ProducerID != dashboardRuntimeSnapshotProducerID() {
		t.Fatalf("producer ID = %q", snap.ProducerID)
	}
	if snap.PolicyHash != cfg.CanonicalPolicyHash() {
		t.Fatalf("policy hash = %q, want current config hash", snap.PolicyHash)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestStartDashboardRuntimeSnapshotEnterpriseGuards(t *testing.T) {
	t.Parallel()

	startDashboardRuntimeSnapshotEnterprise(dashboardRuntimeSnapshotOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var wg sync.WaitGroup
	cfg := config.Defaults()
	startDashboardRuntimeSnapshotEnterprise(dashboardRuntimeSnapshotOptions{
		Context:       ctx,
		WaitGroup:     &wg,
		StartupConfig: cfg,
	})
	wg.Wait()

	enabled := true
	cfg.DashboardSnapshot.Enabled = &enabled
	cfg.DashboardSnapshot.Path = ""
	startDashboardRuntimeSnapshotEnterprise(dashboardRuntimeSnapshotOptions{
		Context:        context.Background(),
		WaitGroup:      &wg,
		StartupConfig:  cfg,
		BudgetProvider: &fakeAgentBudgetSnapshotProvider{},
	})
	wg.Wait()

	writeDashboardRuntimeSnapshotTick(dashboardRuntimeSnapshotOptions{}, filepath.Join(t.TempDir(), "unused.json"), "producer")
}

func TestWriteDashboardRuntimeSnapshotTickReportsWriteFailure(t *testing.T) {
	var stderr strings.Builder
	path := t.TempDir()
	writeDashboardRuntimeSnapshotTick(dashboardRuntimeSnapshotOptions{
		Context:        context.Background(),
		BudgetProvider: &fakeAgentBudgetSnapshotProvider{},
		CurrentConfig:  func() *config.Config { return nil },
		Stderr:         &stderr,
	}, path, "producer")
	if !strings.Contains(stderr.String(), "dashboard runtime snapshot write failed") {
		t.Fatalf("stderr = %q, want write failure", stderr.String())
	}
}

func TestWriteDashboardRuntimeSnapshotTickReportsProviderFailure(t *testing.T) {
	var stderr strings.Builder
	writeDashboardRuntimeSnapshotTick(dashboardRuntimeSnapshotOptions{
		Context: context.Background(),
		BudgetProvider: &fakeAgentBudgetSnapshotProvider{
			err: errors.New("provider unavailable"),
		},
		Stderr: &stderr,
	}, filepath.Join(t.TempDir(), "runtime-snapshot.json"), "producer")
	if !strings.Contains(stderr.String(), "dashboard runtime snapshot unavailable") {
		t.Fatalf("stderr = %q, want provider failure", stderr.String())
	}
}
