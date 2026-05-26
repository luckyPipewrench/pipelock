// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"syscall"
)

// wrapBindError annotates a bind/listen failure with a hint pointing at the
// pipelock doctor port-check flag, but only when the underlying cause is
// EADDRINUSE. Other listen errors (permission denied, address unavailable,
// fd exhaustion) get the original wrap unchanged because the doctor port
// check would not help diagnose them.
//
// Use this only for listeners that are reachable from *config.Config (and
// therefore from diag's collectConfiguredListeners). Listeners constructed
// purely from runtime/CLI state (mcp_listen, agents[*].listen) should call
// wrapBindErrorNoDoctorHint instead, because doctor --check-ports cannot
// inspect them; pointing operators at it would be a dead-end hint.
//
// label is the config knob name the operator wrote ("fetch_proxy.listen",
// "kill_switch.api_listen", ...) so they can see which knob to retune.
// addr is the literal listen address that failed.
func wrapBindError(label, addr string, cause error) error {
	if cause == nil {
		return nil
	}
	if errors.Is(cause, syscall.EADDRINUSE) {
		return fmt.Errorf("%s bind %s: %w\nhint: run `pipelock doctor --check-ports --config <path>` to identify which process holds %s", label, addr, cause, addr)
	}
	return fmt.Errorf("%s bind %s: %w", label, addr, cause)
}

// wrapBindErrorNoDoctorHint mirrors wrapBindError without the doctor
// port-check hint. Use this for runtime-only listeners (mcp_listen,
// agents[*].listen) that diag.collectConfiguredListeners does not look at,
// so the doctor cannot actually identify the conflicting process there.
// Hinting operators at a tool that will report no info is dead-end UX.
func wrapBindErrorNoDoctorHint(label, addr string, cause error) error {
	if cause == nil {
		return nil
	}
	return fmt.Errorf("%s bind %s: %w", label, addr, cause)
}
