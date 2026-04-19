// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package redact implements class-preserving, irreversible secret redaction
// for pipelock request bodies bound for upstream LLM providers.
//
// The package holds no mapping from placeholder back to original; redaction
// is one-way by design. See the redaction-v1 design spec for the full
// semantic model and threat analysis.
//
// Invariants enforced by this package:
//
//   - No vault, no reversibility: the placeholder is terminal.
//   - Whole-body scan: every string scalar in a parsed request body is
//     scanned, regardless of field position. No cache-safe exemption.
//   - Fail-closed: if redaction is configured and cannot be applied safely
//     (unparseable body, overflow, unsupported transport), the request is
//     blocked rather than forwarded.
//   - Class-preserving placeholders: `<pl:CLASS:N>` retains semantic class
//     so the upstream model can reason about type without seeing the value.
package redact
