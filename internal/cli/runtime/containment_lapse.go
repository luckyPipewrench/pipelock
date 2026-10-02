// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
)

// containmentGrantLapsedEvent is the emitted event for a declared containment
// grant whose expires_at passed. Expiry ends the grant; it is not a reason to
// refuse to start or reload, so the entry is dropped from the effective set
// and this event is how an operator learns it happened.
const containmentGrantLapsedEvent = "containment_grant_lapsed"

// reportLapsedContainmentGrants makes every lapsed loopback_services or
// published_services entry visible on the audit log and the emit sinks, the
// same two surfaces containment metrics drift uses. The stderr warning is
// already printed by config validation, which names each entry. Nothing is
// reported when no grant lapsed.
func (s *Server) reportLapsedContainmentGrants(cfg *config.Config, phase string) {
	if cfg == nil {
		return
	}
	for _, grant := range cfg.LapsedContainmentGrants() {
		detail := fmt.Sprintf("containment grant lapsed (%s): %s: %s; the entry is not exposed or rendered; renew or remove it from %s",
			phase, config.ContainmentGrantField(grant.Kind), grant.Message, strings.TrimSpace(s.opts.ConfigFile))
		if s.logger != nil {
			s.logger.LogError(audit.NewResourceLogContext("CONTAINMENT_GRANT_LAPSED", s.opts.ConfigFile), errors.New(detail))
		}
		if s.emitter != nil {
			s.emitter.EmitWithSeverity(context.Background(), emit.SeverityWarn, containmentGrantLapsedEvent, map[string]any{
				"field":      config.ContainmentGrantField(grant.Kind),
				"entry":      grant.Name,
				"owner":      grant.Owner,
				"expired_at": grant.ExpiresAt,
				"phase":      phase,
				"outcome":    "grant_dropped",
			})
		}
	}
}
