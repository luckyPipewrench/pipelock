// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package audit

// Windows does not expose directory-handle fsync through os.File. The audit
// file itself is synced before this point, which is the strongest durability
// boundary available through the portable file API on this target.
func syncDurableAuditParent(string) error { return nil }
