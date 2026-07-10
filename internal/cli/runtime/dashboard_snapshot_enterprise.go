//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard/runtimesnapshot"
	"github.com/luckyPipewrench/pipelock/internal/edition"
)

func init() {
	startDashboardRuntimeSnapshotHook = startDashboardRuntimeSnapshotEnterprise
}

func startDashboardRuntimeSnapshotEnterprise(opts dashboardRuntimeSnapshotOptions) {
	if opts.Context == nil || opts.WaitGroup == nil || opts.StartupConfig == nil {
		return
	}
	cfg := opts.StartupConfig
	if !cfg.DashboardSnapshot.EnabledWithRecorderDir(cfg.FlightRecorder.Dir) {
		return
	}
	path := cfg.DashboardSnapshot.PathWithRecorderDir(cfg.FlightRecorder.Dir)
	if path == "" {
		return
	}
	interval := cfg.DashboardSnapshot.IntervalDuration()
	if dashboardRuntimeSnapshotProvider(opts) == nil {
		return
	}

	producerID := dashboardRuntimeSnapshotProducerID()
	opts.WaitGroup.Add(1)
	go func() {
		defer opts.WaitGroup.Done()
		writeDashboardRuntimeSnapshotTick(opts, path, producerID)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-opts.Context.Done():
				return
			case <-ticker.C:
				writeDashboardRuntimeSnapshotTick(opts, path, producerID)
			}
		}
	}()
}

func writeDashboardRuntimeSnapshotTick(opts dashboardRuntimeSnapshotOptions, path, producerID string) {
	provider := dashboardRuntimeSnapshotProvider(opts)
	if provider == nil {
		return
	}
	policyHash := ""
	if opts.CurrentConfig != nil {
		cfg := opts.CurrentConfig()
		if cfg != nil {
			policyHash = cfg.CanonicalPolicyHash()
		}
	}
	snap, err := buildDashboardRuntimeSnapshot(opts.Context, provider, time.Now().UTC(), producerID, policyHash)
	if err != nil {
		_, _ = fmt.Fprintf(opts.Stderr, "pipelock: dashboard runtime snapshot unavailable: %v\n", err)
		return
	}
	if err := runtimesnapshot.Write(path, snap); err != nil {
		_, _ = fmt.Fprintf(opts.Stderr, "pipelock: dashboard runtime snapshot write failed: %v\n", err)
	}
}

func dashboardRuntimeSnapshotProvider(opts dashboardRuntimeSnapshotOptions) edition.AgentBudgetSnapshotProvider {
	if opts.BudgetProvider != nil {
		return opts.BudgetProvider
	}
	if opts.Proxy == nil {
		return nil
	}
	provider, _ := opts.Proxy.Edition().(edition.AgentBudgetSnapshotProvider)
	return provider
}

func buildDashboardRuntimeSnapshot(
	ctx context.Context,
	provider edition.AgentBudgetSnapshotProvider,
	now time.Time,
	producerID string,
	policyHash string,
) (runtimesnapshot.Envelope, error) {
	budgets, err := provider.AgentBudgetSnapshots(ctx, runtimesnapshot.MaxBudgetRows+1)
	if err != nil {
		return runtimesnapshot.Envelope{}, fmt.Errorf("read agent budget snapshots: %w", err)
	}
	return runtimesnapshot.NewEnvelope(now, producerID, policyHash, budgets), nil
}

func dashboardRuntimeSnapshotProducerID() string {
	return "pipelock-run"
}
