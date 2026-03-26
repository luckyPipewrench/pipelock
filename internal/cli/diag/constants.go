// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

// Test result status constants.
const (
	statusPass = "pass"
	statusFail = "fail"
	statusSkip = "skip"
)

// stateUnavailable is the display string for unavailable sandbox capabilities.
const stateUnavailable = "unavailable"

// configLabelDefaults is the sentinel config label used when no config file
// is specified (uses built-in defaults).
const configLabelDefaults = "defaults"

// ANSI escape codes for terminal color output.
const (
	ansiReset      = "\033[0m"
	ansiBold       = "\033[1m"
	ansiDim        = "\033[2m"
	ansiBoldGreen  = "\033[1;32m"
	ansiBoldYellow = "\033[1;33m"
	ansiBoldRed    = "\033[1;31m"
	ansiBoldCyan   = "\033[1;36m"
)

// demoScanAllowed is the detail string for demo scenarios that were not blocked.
const demoScanAllowed = "scan allowed"
