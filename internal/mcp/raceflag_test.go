// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build race

package mcp

// raceEnabled thins the large-payload media sweeps under the race detector,
// which slows each multi-megabyte scan to about a minute and adds nothing to
// what the boundary case already proves.
const raceEnabled = true
