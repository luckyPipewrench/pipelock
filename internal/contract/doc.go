// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package contract defines the typed schemas, canonicalization rules, and
// verification primitives for v2.4 learn-and-lock policy contracts.
//
// All signed artifacts (Contract, ActiveManifest, CompileManifest, Tombstone,
// KeyRoster, VerificationMetadata) parse from their transport format (YAML or
// JSON) into typed Go structs and sign JCS-canonicalized projections of those
// structs. YAML is transport/display only; signatures never cover YAML bytes.
//
// Signing uses Ed25519 PureEdDSA per RFC 8032 section 5.1.6. Implementations
// MUST NOT use Ed25519ph, Ed25519ctx, or any randomized variant.
package contract
