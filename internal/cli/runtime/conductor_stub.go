//go:build !enterprise

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/ed25519"
	"errors"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

var errConductorEnterpriseBuildRequired = errors.New("conductor.enabled requires an enterprise build")

func (s *Server) touchConductorCoreFields() {
	if s == nil {
		return
	}
	_ = s.conductorAuditQueue
	_ = &s.conductorApplyMu
}

// initConductorApplyAndAudit is a no-op in the Apache-only build. The
// follower-side Conductor runtime (apply cache, audit queue/transport,
// remote kill poller) ships only in the enterprise build. If a valid fleet
// license is supplied to an Apache-only binary, still fail closed rather
// than silently starting a follower with no Conductor wiring.
func (s *Server) initConductorApplyAndAudit(cfg *config.Config, _ *metrics.Metrics) error {
	s.touchConductorCoreFields()
	if cfg != nil && cfg.Conductor.Enabled {
		return errConductorEnterpriseBuildRequired
	}
	return nil
}

// initConductorRemoteKill is a no-op in the Apache-only build. See
// initConductorApplyAndAudit for the rationale.
func (s *Server) initConductorRemoteKill(cfg *config.Config, _ *killswitch.Controller, _ io.Writer) error {
	s.touchConductorCoreFields()
	if cfg != nil && cfg.Conductor.Enabled {
		return errConductorEnterpriseBuildRequired
	}
	return nil
}

// initConductorProducer is a no-op in the Apache-only build. See
// initConductorApplyAndAudit for the rationale.
func (s *Server) initConductorProducer(cfg *config.Config, _ *metrics.Metrics, _ ed25519.PrivateKey, _ io.Writer) error {
	s.touchConductorCoreFields()
	if cfg != nil && cfg.Conductor.Enabled {
		return errConductorEnterpriseBuildRequired
	}
	return nil
}
