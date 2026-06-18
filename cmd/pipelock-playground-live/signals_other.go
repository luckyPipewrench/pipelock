// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package main

import (
	"context"

	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

// watchKillSwitch is a no-op on platforms without SIGUSR1/SIGUSR2 (the live
// playground server deploys on Linux). The Kill/Resume API stays available
// programmatically and via server shutdown.
func watchKillSwitch(_ context.Context, _ *livechat.Server) {}
