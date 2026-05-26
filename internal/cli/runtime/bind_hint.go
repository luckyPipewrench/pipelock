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
