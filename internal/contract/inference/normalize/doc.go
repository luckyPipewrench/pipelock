// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package normalize implements the path-normalization layer of the
// contract-compile inference engine: frequency-weighted entropy
// bucketing, the 5-gate collapse decision, the reserved-segment
// blocklist, and per-host cardinality capping with tail-coverage. Pure
// functions, no I/O. Consumed by the future compile pipeline at
// compile-time only; the runtime proxy never invokes this package.
package normalize
