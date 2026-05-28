// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"reflect"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// conductorRuntimeChanged reports whether two configs disagree on any
// Conductor field. Used by the reload path to enforce "Conductor settings
// are restart-only" — a hot reload that flips conductor.enabled or
// re-points the control plane is ignored and the previous Conductor
// block is preserved on newCfg. Lives in the untagged file because the
// comparison is pure config-struct DeepEqual, no enterprise types needed,
// and the reload-protects-conductor invariant must hold on both the
// Apache-only core and the enterprise build.
func conductorRuntimeChanged(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}
	return !reflect.DeepEqual(oldCfg.Conductor, newCfg.Conductor)
}

// conductorRunner is the minimal interface the runtime needs from the Conductor
// audit transport and remote kill poller. Both are concrete *types in the
// enterprise build (auditbatcher.Transport, emergency.RemoteKillPoller); the
// Apache-only core only ever observes the Run(ctx) entry point.
type conductorRunner interface {
	Run(ctx context.Context) error
}

// conductorCloser is the minimal interface the runtime needs from the Conductor
// audit producer. The concrete *auditbatcher.Producer lives in the enterprise
// build; reload-side teardown only needs Close().
type conductorCloser interface {
	Close() error
}
