// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import "github.com/luckyPipewrench/pipelock/internal/edition"

// agentAnonymous is the fallback agent name when no header/query/context
// override identifies the caller. Used by proxy handlers for display.
// Agent resolution logic lives in internal/edition/.
const agentAnonymous = "anonymous"

// AgentHeader re-exports the canonical agent header from edition.
// Used by proxy tests and any proxy-internal code that needs it.
const AgentHeader = edition.AgentHeader
