// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package auditpacket holds the canonical Go binding for the Pipelock Audit
// Packet v0 schema published at sdk/audit-packet/v0.json.
//
// The Audit Packet is the procurement-ready evidence bundle Pipelock writes
// after a Pipelock-mediated agent run. It pairs a verifier verdict from the
// signed receipt chain with the enforcement posture that produced it.
//
// The locked contract is v0.json. Go consumers SHOULD use the structs in this
// package; producers in other languages MUST validate against v0.json with a
// JSON Schema 2020-12 validator. example.json is the golden minimal packet
// and round-trips through this package without loss.
//
// See README.md in this directory for design rationale, intended consumers,
// and what is deliberately out of scope for v0.
package auditpacket
