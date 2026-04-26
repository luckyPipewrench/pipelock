// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package privacy enforces the learn-and-lock data-class taxonomy on
// observation events before they reach the recorder. The resolver layer
// loads the deployment's redaction salt from the configured source; the
// enforcer layer rewrites field values according to their declared data
// class (public clear, internal salt-hashed, sensitive opt-in-only,
// regulated counter-only and never emitted). The salt is held inside the
// Enforcer and never logged, emitted, or re-exported.
package privacy
