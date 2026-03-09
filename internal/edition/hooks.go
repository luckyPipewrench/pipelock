// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package edition

import "github.com/luckyPipewrench/pipelock/internal/config"

// NewEditionFunc creates an Edition from config. Set by enterprise builds.
// Default (OSS) creates a noopEdition.
var NewEditionFunc = newNoopEdition

// ResetHooks restores all hook variables to their default (OSS) values.
// Used by tests that need to undo enterprise hook activation.
func ResetHooks() {
	NewEditionFunc = newNoopEdition
	config.ValidateAgentsFunc = nil
	config.EnforceLicenseGateFunc = nil
	config.MergeAgentProfileFunc = nil
}
