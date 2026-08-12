// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package audit

// Unsupported targets cannot provide the Unix directory-sync durability
// checkpoint. File sync still runs before a lifecycle command proceeds.
func syncDurableAuditParent(string) error { return nil }
