// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package capabilitymanifest validates the public capability manifest and
// renders the generated contributor-guide section from it.
//
//go:generate go run ./cmd/generate -manifest ../../docs/security/capability-manifest.json -agents ../../AGENTS.md
package capabilitymanifest
