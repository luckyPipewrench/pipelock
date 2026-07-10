// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"io"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

type dashboardRuntimeSnapshotOptions struct {
	Context        context.Context
	WaitGroup      *sync.WaitGroup
	Proxy          *proxy.Proxy
	BudgetProvider edition.AgentBudgetSnapshotProvider
	StartupConfig  *config.Config
	CurrentConfig  func() *config.Config
	Stderr         io.Writer
}

var startDashboardRuntimeSnapshotHook func(dashboardRuntimeSnapshotOptions)

func (s *Server) startDashboardRuntimeSnapshot(ctx context.Context, wg *sync.WaitGroup, cfg *config.Config) {
	if startDashboardRuntimeSnapshotHook == nil {
		return
	}
	startDashboardRuntimeSnapshotHook(dashboardRuntimeSnapshotOptions{
		Context:       ctx,
		WaitGroup:     wg,
		Proxy:         s.proxy,
		StartupConfig: cfg,
		CurrentConfig: s.currentConfig,
		Stderr:        s.opts.Stderr,
	})
}
