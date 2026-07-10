// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
)

func needsHITLApprover(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	if cfg.ResponseScanning.Action == config.ActionAsk {
		return true
	}
	return cfg.Taint.Enabled && cfg.Taint.Policy != config.ModePermissive
}

func newRuntimeApprover(cfg *config.Config) *hitl.Approver {
	if !needsHITLApprover(cfg) {
		return nil
	}
	return hitl.New(cfg.ResponseScanning.AskTimeoutSeconds)
}
